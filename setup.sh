#!/bin/bash
# AD AutoPwn Professional - Setup Script
# Run with: sudo ./setup.sh

# System Dependencies
sudo apt update
sudo apt install -y \
    nmap \
    smbclient \
    enum4linux \
    ldap-utils \
    seclists \
    libsasl2-dev \
    libldap2-dev \
    libssl-dev

# Install Kerbrute
if ! command -v kerbrute &> /dev/null; then
    echo "[+] Installing Kerbrute..."
    wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64
    chmod +x kerbrute_linux_amd64
    sudo mv kerbrute_linux_amd64 /usr/local/bin/kerbrute
fi

# Create sample wordlists
mkdir -p wordlists
if [ ! -f wordlists/users.txt ]; then
    echo "administrator" > wordlists/users.txt
    echo "admin" >> wordlists/users.txt
    echo "svc_account" >> wordlists/users.txt
fi

if [ ! -f wordlists/targets.txt ]; then
    echo "10.0.0.1" > wordlists/targets.txt
    echo "10.0.0.5" >> wordlists/targets.txt
    echo "10.0.0.10" >> wordlists/targets.txt
fi

# Install Python dependencies
pip install -r requirements.txt

echo "[+] Setup completed successfully!"
echo "[!] Remember to add your target IPs to wordlists/targets.txt"
echo "[!] Add domain users to wordlists/users.txt"
