#!/bin/bash

# RedHawk Installation Script
# Automated setup for the RedHawk framework

echo "========================================="
echo "   🦅 RedHawk Framework Installer      "
echo "========================================="
echo ""

# Check Python version
echo "[*] Checking Python version..."
python_version=$(python3 --version 2>&1 | awk '{print $2}')
echo "[+] Python version: $python_version"

# Check pip
echo "[*] Checking pip..."
if ! command -v pip3 &> /dev/null; then
    echo "[-] pip3 not found. Please install pip3 first."
    exit 1
fi
echo "[+] pip3 found"

# Install dependencies
echo ""
echo "[*] Installing dependencies..."
pip3 install -r requirements.txt --break-system-packages

if [ $? -eq 0 ]; then
    echo "[+] Dependencies installed successfully"
else
    echo "[-] Error installing dependencies"
    exit 1
fi

# Create necessary directories
echo ""
echo "[*] Creating directories..."
mkdir -p data reports logs

# Create default wordlist if not exists
if [ ! -f "data/subdomains.txt" ]; then
    echo "[*] Creating default subdomain wordlist..."
    cat > data/subdomains.txt << 'EOF'
www
mail
ftp
smtp
pop
imap
webmail
admin
portal
api
dev
test
staging
demo
beta
blog
shop
store
vpn
secure
login
mobile
app
cdn
static
assets
img
images
upload
download
docs
support
help
forum
status
monitor
ns1
ns2
dns
mx
autodiscover
EOF
    echo "[+] Default wordlist created"
fi

# Make main script executable
chmod +x redhawk.py

echo ""
echo "========================================="
echo "   ✅ Installation Complete!            "
echo "========================================="
echo ""
echo "Usage:"
echo "  GUI Mode:  python3 redhawk.py --gui"
echo "  CLI Mode:  python3 redhawk.py --cli --target example.com --all"
echo ""
echo "For more information, see README.md"
echo ""