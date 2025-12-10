# 🦅 RedHawk - Advanced Security Assessment Framework

![Version](https://img.shields.io/badge/version-1.0-blue)
![Python](https://img.shields.io/badge/python-3.8+-green)
![License](https://img.shields.io/badge/license-MIT-orange)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey)

**RedHawk** is a powerful, modular security reconnaissance and vulnerability assessment framework designed for professional penetration testers and security researchers. Built with Python, it provides comprehensive scanning capabilities with an intuitive GUI and advanced automation features.

---

## 📋 Table of Contents

- [Features](#-features)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Usage](#-usage)
- [Modules](#-modules)
- [GUI Features](#-gui-features)
- [Advanced Features](#-advanced-features)
- [Examples](#-examples)
- [Configuration](#%EF%B8%8F-configuration)
- [Troubleshooting](#-troubleshooting)
- [Legal Disclaimer](#%EF%B8%8F-legal-disclaimer)

---

## ✨ Features

### Core Capabilities
- 🔍 **Comprehensive Scanning**: DNS, SSL/TLS, Headers, Ports, Email, WAF Detection
- 🌐 **Wildcard Subdomain Discovery**: Discover hundreds of subdomains using 5 methods
- 🎯 **Smart Prioritization**: Intelligent ranking of targets by criticality
- 📊 **Batch Scanning**: Scan multiple targets efficiently
- 🎨 **Modern GUI**: User-friendly interface with real-time updates
- 📧 **Email Intelligence**: Hunter.io integration for advanced email discovery
- 📝 **Professional Reports**: Export to HTML and JSON formats
- ⚡ **High Performance**: Multi-threaded scanning

### Subdomain Discovery (5 Methods)
1. Certificate Transparency logs
2. DNS enumeration
3. Common name patterns
4. Wordlist-based discovery
5. Search engine queries

---

## 🚀 Installation

### Prerequisites

```bash
# Python 3.8 or higher
python3 --version

# Git
git --version
```

### Quick Install

```bash
# Clone repository
git clone https://github.com/yourusername/RedHawk.git
cd RedHawk

# Install dependencies
pip3 install -r requirements.txt --break-system-packages

# Set up alias (optional)
echo "alias redhawk='python3 $(pwd)/scan.py'" >> ~/.bashrc
source ~/.bashrc
```

### Required Packages

```bash
pip3 install dnspython requests pyyaml beautifulsoup4 --break-system-packages
pip3 install pyOpenSSL --break-system-packages
```

---

## 🎯 Quick Start

### Basic Usage

```bash
# Scan single domain
python3 scan.py example.com

# Or with alias
redhawk example.com
```

### Launch GUI

```bash
python3 scan.py --gui

# Or
redhawk --gui
```

### Wildcard Discovery

```bash
# Discover all subdomains
python3 scan.py --wildcard gov.gh

# Result: Hundreds of subdomains in minutes
```

---

## 📖 Usage

### Command Line

```bash
# Basic scan
python3 scan.py target.com

# Wildcard scan  
python3 scan.py --wildcard example.com

# Batch scan
python3 scan_list.py targets.txt

# Specify modules
python3 scan.py target.com --modules dns,ssl,headers

# Verbose mode
python3 scan.py target.com --verbose
```

### GUI Workflow

1. **Launch**: `redhawk --gui`
2. **Enter target**: `gov.gh`
3. **Select**: ☑ Wildcard Scan (*)
4. **Click**: Scan All
5. **Wait**: Discovery completes (~5 min)
6. **Review**: 606 subdomains found
7. **Prioritize**: Automatic smart ranking
8. **Scan**: Top 10 critical targets
9. **Export**: Professional HTML report

---

## 🔧 Modules

### Available Modules

| Module | Description |
|--------|-------------|
| **DNS** | A/AAAA/MX/NS/TXT records, DNSSEC |
| **Subdomain** | Subdomain discovery |
| **Subdomain Wildcard** | Advanced 5-method discovery |
| **SSL/TLS** | Certificate and protocol analysis |
| **Headers** | HTTP security headers |
| **Email** | SPF/DMARC/DKIM + Hunter.io |
| **Port Scan** | Service discovery |
| **WHOIS** | Domain registration info |
| **WAF** | WAF detection |

---

## 🎨 GUI Features

### Main Interface

**Target Input:**
- Quick entry with history
- Wildcard scan option
- Module selection

**Scan Controls:**
- Scan All
- Stop
- Prioritize Results
- Scan from List
- Export Report

**Results Display:**
- Console (real-time)
- Results (organized tree)
- Vulnerabilities (severity-based)

### Smart Scanning

**Example: Government Domain**

```
Step 1: Discover
Target: gov.gh
☑ Wildcard Scan
→ Result: 606 subdomains (5 min)

Step 2: Prioritize (Automatic)
Critical: 18 (parliament, mfa, defense)
High: 57 (finance, police, immigration)
Medium: 150 (ministries)
Other: 381 (test, dev, staging)

Step 3: Smart Scan Options
○ Top 10 Critical (30-60 min) ⭐
○ Top 25 Priority (2-3 hours)
○ Top 50 Extended (5-8 hours)
● Skip scanning

Step 4: Export
Professional HTML report ready!
```

---

## 🚀 Advanced Features

### 1. Wildcard Subdomain Discovery

```bash
redhawk --wildcard example.com
```

**Output:**
```
[+] Certificate Transparency: 342 subdomains
[+] DNS Enumeration: 156 subdomains
[+] Common Patterns: 89 subdomains
[+] Total: 606 unique subdomains

Files created:
✅ subdomains_example_com_20251210.txt
✅ discovery_example_com_20251210.json
✅ top10_example_com_20251210.txt
✅ top25_example_com_20251210.txt
✅ top50_example_com_20251210.txt
```

### 2. Smart Prioritization

**Automatic Ranking:**

```
CRITICAL (18):
- parliament.gov.gh
- mfa.gov.gh
- defense.gov.gh
- presidency.gov.gh

HIGH (57):
- finance.gov.gh
- police.gov.gh
- immigration.gov.gh
- gra.gov.gh

MEDIUM (150):
- ministries
- departments
- services

LOW (381):
- test/dev/staging
```

### 3. Time-Saving Strategy

```
Traditional: Scan all 606 = 20+ hours
Smart: Discovery + Top 10 = 35-65 minutes
Savings: ~19 hours! ⚡
```

### 4. Hunter.io Email Intelligence

**Setup:**

Edit `config/config.yaml`:
```yaml
modules:
  email:
    enabled: true
    use_hunter_api: true
    hunter_api_key: 'your-api-key-here'
```

**Results:**
- Traditional: 5-10 emails
- With Hunter.io: 40-50+ emails
- **Total: 50+ with full metadata**

**Metadata includes:**
- Full names
- Job positions  
- Departments
- Seniority levels
- LinkedIn profiles
- Twitter handles
- Confidence scores (0-100%)

---

## 💡 Examples

### Example 1: Government Assessment

```bash
# Discover all subdomains
redhawk --wildcard gov.gh

# Result: 606 subdomains in 5 minutes

# Prioritize automatically
# Critical: 18, High: 57

# Scan top 10 (GUI or CLI)
redhawk --list top10_gov_gh_20251210.txt

# Export report
# 30-60 minutes for comprehensive assessment
```

### Example 2: Batch Scanning

```bash
# Create target list
cat > targets.txt << EOF
parliament.gov.gh
mofep.gov.gh
police.gov.gh
gra.gov.gh
mfa.gov.gh
EOF

# Scan all
python3 scan_list.py targets.txt

# Result: Aggregated report
```

### Example 3: Email Discovery

```bash
# Scan with Hunter.io
redhawk example.com

# Traditional: 5 emails
# Hunter.io: 42 emails
# Total: 47 with metadata
```

### Example 4: Targeted Scanning

```bash
# Only specific modules
redhawk example.com --modules dns,ssl,email

# Quick security check
redhawk example.com --modules headers,ssl
```

---

## ⚙️ Configuration

### Main Config File

`config/config.yaml`:

```yaml
engine:
  max_threads: 10
  timeout: 30

modules:
  dns:
    enabled: true
    check_dnssec: true
  
  subdomain_wildcard:
    enabled: true
    max_subdomains: 1000
  
  email:
    enabled: true
    use_hunter_api: true
    hunter_api_key: 'your-key'

output:
  directory: 'reports'
  timestamp: true
```

---

## 📊 Output

### File Structure

```
RedHawk/
├── reports/
│   ├── example_com_20251210.json
│   └── example_com_20251210.html
├── subdomains_example_com_*.txt
├── discovery_example_com_*.json
├── top10_example_com_*.txt
├── top25_example_com_*.txt
└── top50_example_com_*.txt
```

### HTML Report

- Executive Summary
- Severity Breakdown
- Critical Vulnerabilities
- Module Details
- Recommendations

---

## 🔧 Troubleshooting

### Common Issues

**1. Module Import Errors**
```bash
pip3 install dnspython pyyaml --break-system-packages
```

**2. Permission Errors**
```bash
pip3 install --break-system-packages
```

**3. GUI Not Launching**
```bash
sudo apt-get install python3-tk
```

**4. SSL Warnings**
```bash
# Normal for security scanning
# Can be safely ignored
```

### Debug Mode

```bash
redhawk target.com --verbose
```

---

## ⚖️ Legal Disclaimer

**⚠️ IMPORTANT: Authorized Use Only**

### Legal Requirements

✅ **DO**:
- Use on systems you own
- Obtain written authorization
- Follow responsible disclosure
- Comply with local laws

❌ **DON'T**:
- Scan without permission
- Use for illegal activities  
- Cause damage or disruption
- Violate privacy laws

### User Responsibility

You are responsible for:
- Obtaining proper authorization
- Legal compliance
- Ethical use
- Any consequences

**The developers are not responsible for misuse.**

### By Using RedHawk

You agree to:
- Use it legally and ethically
- Have proper authorization
- Accept full responsibility
- Follow all applicable laws

**Security testing laws vary by jurisdiction. Know your local laws.**

---

## 📄 License

MIT License - See LICENSE file

---

## 🎯 Quick Reference

### Essential Commands

```bash
# Basic
redhawk example.com

# Wildcard
redhawk --wildcard example.com

# GUI
redhawk --gui

# Batch
python3 scan_list.py targets.txt
```

### Files

```
Config: config/config.yaml
Reports: reports/
Modules: modules/
```

### Workflow

```
1. Discover → redhawk --wildcard target.com
2. Prioritize → Automatic
3. Scan → Top 10/25/50
4. Export → HTML report
```

---

## 📞 Support

- **Issues**: GitHub Issues
- **Docs**: [Full Documentation](docs/)
- **Community**: GitHub Discussions

---

**🦅 RedHawk - Hunt Smarter, Not Harder**

*Professional Security Assessment Made Easy*

---

*Version 1.0 | Last Updated: December 10, 2025*
