#!/usr/bin/env python3
"""
RedHawk Wildcard Scanner
Specialized scanner for wildcard domains like *.gov.gh
"""

import sys
import os
from pathlib import Path
import warnings
import argparse

# Suppress SSL warnings
warnings.filterwarnings('ignore', message='Unverified HTTPS request')
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Setup paths
SCRIPT_DIR = Path(__file__).parent.resolve()
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
os.chdir(SCRIPT_DIR)

from core.engine import RedHawkEngine
import json

def scan_wildcard_domain(target, modules=None, config_path='config/config.yaml'):
    """
    Scan a wildcard domain pattern
    
    Args:
        target: Domain (e.g., 'gov.gh' or '*.gov.gh')
        modules: List of modules to run, None for all
        config_path: Path to config file
    """
    # Normalize target
    if not target.startswith('*.'):
        base_domain = target
        wildcard_target = f"*.{target}"
    else:
        wildcard_target = target
        base_domain = target[2:]
    
    print("=" * 60)
    print("  🦅 RedHawk Wildcard Domain Scanner")
    print("=" * 60)
    print(f"\n[*] Target: {wildcard_target}")
    print(f"[*] Base Domain: {base_domain}")
    print()
    
    # Initialize engine
    engine = RedHawkEngine(config_path=config_path)
    
    # Phase 1: Discover subdomains
    print("\n" + "=" * 60)
    print("  PHASE 1: Subdomain Discovery")
    print("=" * 60)
    
    # Use enhanced subdomain module
    subdomain_results = engine.run_module('subdomain', wildcard_target)
    
    if subdomain_results.get('status') != 'success':
        print(f"[-] Subdomain discovery failed: {subdomain_results.get('error', 'Unknown')}")
        return
    
    discovered = subdomain_results.get('subdomains', [])
    print(f"\n[+] Discovered {len(discovered)} subdomains")
    
    if not discovered:
        print("[-] No subdomains found. Exiting.")
        return
    
    # Show top 10 discovered
    print("\n[*] Sample of discovered subdomains:")
    for sub in discovered[:10]:
        print(f"    • {sub}")
    if len(discovered) > 10:
        print(f"    ... and {len(discovered) - 10} more")
    
    # Phase 2: Scan each subdomain (optional)
    if modules:
        print("\n" + "=" * 60)
        print("  PHASE 2: Detailed Scanning")
        print("=" * 60)
        
        # Ask user if they want to scan all
        if len(discovered) > 10:
            response = input(f"\n[?] Scan all {len(discovered)} subdomains? (y/N): ")
            if response.lower() != 'y':
                # Let user pick how many
                try:
                    count = int(input(f"[?] How many to scan? (1-{len(discovered)}): "))
                    discovered = discovered[:count]
                except:
                    discovered = discovered[:10]
                    print(f"[*] Scanning top 10 subdomains")
        
        print(f"\n[*] Scanning {len(discovered)} subdomains with {len(modules)} modules")
        
        all_results = {
            'wildcard_scan': True,
            'base_domain': base_domain,
            'total_subdomains': len(subdomain_results.get('subdomains', [])),
            'scanned_subdomains': len(discovered),
            'subdomain_details': subdomain_results,
            'individual_scans': {}
        }
        
        for i, subdomain in enumerate(discovered, 1):
            print(f"\n[{i}/{len(discovered)}] Scanning {subdomain}...")
            
            # Enable only specified modules
            for mod in engine.config.get('modules', {}):
                engine.config['modules'][mod]['enabled'] = mod in modules
            
            result = engine.run_all_modules(subdomain)
            all_results['individual_scans'][subdomain] = result
            
            print(f"    [+] {subdomain} scan complete")
        
        # Save combined results
        output_path = Path('reports') / f'wildcard_{base_domain.replace(".", "_")}_{engine.get_timestamp()}.json'
        with open(output_path, 'w') as f:
            json.dump(all_results, f, indent=2)
        
        print(f"\n[+] Wildcard scan complete!")
        print(f"[+] Results saved to: {output_path}")
        
        # Generate summary
        generate_wildcard_summary(all_results, base_domain)
    
    else:
        # Just subdomain discovery
        print(f"\n[+] Subdomain discovery complete!")
        print(f"[+] Found {len(discovered)} subdomains for {base_domain}")
        print(f"\n[*] To scan these subdomains individually:")
        print(f"    python3 wildcard_scan.py {base_domain} --modules dns email ssl")

def generate_wildcard_summary(results, base_domain):
    """Generate a summary report"""
    print("\n" + "=" * 60)
    print("  WILDCARD SCAN SUMMARY")
    print("=" * 60)
    
    print(f"\nBase Domain: {base_domain}")
    print(f"Total Subdomains Found: {results['total_subdomains']}")
    print(f"Subdomains Scanned: {results['scanned_subdomains']}")
    
    # Aggregate vulnerabilities
    all_vulns = []
    critical_count = 0
    high_count = 0
    medium_count = 0
    low_count = 0
    
    for subdomain, scan_result in results['individual_scans'].items():
        for module, module_data in scan_result.get('modules', {}).items():
            for vuln in module_data.get('vulnerabilities', []):
                vuln['subdomain'] = subdomain
                vuln['module'] = module
                all_vulns.append(vuln)
                
                severity = vuln.get('severity', '').lower()
                if severity == 'critical':
                    critical_count += 1
                elif severity == 'high':
                    high_count += 1
                elif severity == 'medium':
                    medium_count += 1
                elif severity == 'low':
                    low_count += 1
    
    print(f"\nTotal Vulnerabilities Found: {len(all_vulns)}")
    print(f"  • Critical: {critical_count}")
    print(f"  • High: {high_count}")
    print(f"  • Medium: {medium_count}")
    print(f"  • Low: {low_count}")
    
    # Show top critical/high issues
    if critical_count > 0 or high_count > 0:
        print(f"\n🚨 Critical/High Issues:")
        for vuln in all_vulns:
            if vuln.get('severity', '').lower() in ['critical', 'high']:
                print(f"  [{vuln['severity'].upper()}] {vuln['subdomain']}")
                print(f"    Type: {vuln.get('type', 'Unknown')}")
                print(f"    Module: {vuln.get('module', 'Unknown')}")

def main():
    parser = argparse.ArgumentParser(
        description='RedHawk Wildcard Domain Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Discover all *.gov.gh subdomains
  python3 wildcard_scan.py gov.gh
  
  # Discover and scan with specific modules
  python3 wildcard_scan.py gov.gh --modules dns email ssl
  
  # Full scan of all subdomains (can take a while!)
  python3 wildcard_scan.py gov.gh --modules dns email ssl port_scan headers
  
  # Alternative notation
  python3 wildcard_scan.py "*.gov.gh" --modules dns
        """
    )
    
    parser.add_argument('domain', help='Base domain (e.g., gov.gh or *.gov.gh)')
    parser.add_argument('--modules', nargs='+', 
                       help='Modules to run on each subdomain (dns, email, ssl, etc.)')
    parser.add_argument('--config', default='config/config.yaml',
                       help='Config file path')
    
    args = parser.parse_args()
    
    try:
        scan_wildcard_domain(args.domain, args.modules, args.config)
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()