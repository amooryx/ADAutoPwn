#!/bin/bash
# ADAutoPwn  - Comprehensive Setup Script
# Run with: sudo ./setup.sh

echo "[!] Installing system dependencies..."
sudo apt update
sudo apt install -y \
    nmap \
    smbclient \
    enum4linux \
    ldap-utils \
    seclists \
    libsasl2-dev \
    libldap2-dev \
    libssl-dev \
    git \
    wget \
    unzip \
    python3-pip \
    bloodhound \
    powershell \
    crackmapexec

echo "[+] Installing Python tools..."
sudo pip3 install \
    impacket \
    bloodhound \
    certipy-ad \
    ldap3 \
    requests \
    pycryptodome \
    crackmapexec

echo "[+] Installing Kerbrute..."
wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64
chmod +x kerbrute_linux_amd64
sudo mv kerbrute_linux_amd64 /usr/local/bin/kerbrute

echo "[+] Installing Mimikatz (Linux port)..."
git clone https://github.com/gentilkiwi/mimikatz
sudo cp -r mimikatz /opt/
sudo ln -s /opt/mimikatz/x64/mimikatz /usr/local/bin/mimikatz

echo "[+] Configuring wordlists..."
sudo gunzip /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true
if [ ! -f /usr/share/wordlists/rockyou.txt ]; then
    sudo wget -O /usr/share/wordlists/rockyou.txt https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt
fi

echo "[+] Setting up PowerShell for Mimikatz..."
pwsh -Command "Install-Module -Name Mimikatz -Force"

echo "[+] Creating pentest directory..."
mkdir -p ~/ad_pentest
cp /usr/share/wordlists/rockyou.txt ~/ad_pentest/

echo "[!] Setup completed successfully!"
echo "  - Installed: Impacket, BloodHound, Certipy, Kerbrute, Mimikatz"
echo "  - Wordlists: rockyou.txt in ~/ad_pentest"
echo "  - Run: python3 ad_autopwn_pro.py to start"
