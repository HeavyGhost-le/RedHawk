#!/bin/bash
# Quick Fix and Verification Script for RedHawk

echo "========================================"
echo "  RedHawk - Quick Fix & Verification"
echo "========================================"
echo ""

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

echo "[*] Current directory: $(pwd)"
echo ""

# Check Python version
echo "[1/7] Checking Python version..."
python3 --version
if [ $? -ne 0 ]; then
    echo "[!] Python 3 not found!"
    exit 1
fi
echo "[✓] Python OK"
echo ""

# Check directory structure
echo "[2/7] Checking directory structure..."
errors=0

for dir in core modules gui utils config; do
    if [ ! -d "$dir" ]; then
        echo "[!] Missing directory: $dir"
        errors=$((errors + 1))
    else
        echo "[✓] Found: $dir/"
    fi
done

if [ $errors -gt 0 ]; then
    echo "[!] Directory structure incomplete!"
    exit 1
fi
echo ""

# Check __init__.py files
echo "[3/7] Checking/creating __init__.py files..."
for dir in core modules gui utils config; do
    if [ ! -f "$dir/__init__.py" ]; then
        echo "[*] Creating $dir/__init__.py"
        touch "$dir/__init__.py"
    fi
    echo "[✓] $dir/__init__.py exists"
done
echo ""

# Check key files exist
echo "[4/7] Checking key files..."
key_files=(
    "redhawk.py"
    "run.py"
    "core/engine.py"
    "gui/main_window.py"
    "modules/dns.py"
    "config/config.yaml"
)

for file in "${key_files[@]}"; do
    if [ ! -f "$file" ]; then
        echo "[!] Missing file: $file"
        errors=$((errors + 1))
    else
        echo "[✓] Found: $file"
    fi
done

if [ $errors -gt 0 ]; then
    echo "[!] Some files are missing!"
    exit 1
fi
echo ""

# Make scripts executable
echo "[5/7] Making scripts executable..."
chmod +x redhawk.py run.py demo.py install.sh 2>/dev/null
echo "[✓] Scripts are executable"
echo ""

# Check dependencies
echo "[6/7] Checking Python dependencies..."
python3 -c "
import sys
missing = []
try:
    import dns
    print('[✓] dnspython installed')
except:
    missing.append('dnspython')
    print('[!] dnspython missing')

try:
    import requests
    print('[✓] requests installed')
except:
    missing.append('requests')
    print('[!] requests missing')

try:
    import yaml
    print('[✓] PyYAML installed')
except:
    missing.append('PyYAML')
    print('[!] PyYAML missing')

if missing:
    print('\n[!] Missing dependencies:', ', '.join(missing))
    print('[*] Install with: pip3 install -r requirements.txt --break-system-packages')
    sys.exit(1)
"

if [ $? -ne 0 ]; then
    echo ""
    echo "[!] Dependencies missing. Installing..."
    pip3 install -r requirements.txt --break-system-packages
fi
echo ""

# Test imports
echo "[7/7] Testing imports..."
python3 -c "
import sys
sys.path.insert(0, '.')

try:
    from core.engine import RedHawkEngine
    print('[✓] Core engine import OK')
    
    engine = RedHawkEngine()
    print('[✓] Engine initialization OK')
    print('[✓] Loaded', len(engine.get_available_modules()), 'modules')
    
    print('\n[SUCCESS] All checks passed!')
    print('\nYou can now run:')
    print('  python3 run.py --gui')
    print('  python3 run.py --cli --target example.com --module dns')
    
except Exception as e:
    print('[!] Import test failed:', str(e))
    print('\n[*] Try running from the RedHawk directory:')
    print('    cd', '$(pwd)')
    print('    python3 run.py --gui')
    sys.exit(1)
"

echo ""
echo "========================================"
echo "  ✓ RedHawk is ready to use!"
echo "========================================"
echo ""
echo "Quick Start:"
echo "  python3 run.py --gui"
echo "  python3 run.py --cli --target example.com --all"
echo ""