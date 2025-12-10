#!/usr/bin/env python3
"""
Scan subdomains from a target list file
"""

import sys
import argparse
from pathlib import Path

# Add project to path
sys.path.insert(0, str(Path(__file__).parent))

from core.engine import RedHawkEngine

def load_target_list(filename):
    """Load targets from file"""
    targets = []
    with open(filename) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                targets.append(line)
    return targets

def main():
    parser = argparse.ArgumentParser(
        description='Scan subdomains from a target list',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 scan_list.py top10_critical.txt --modules dns email ssl
  python3 scan_list.py targets.txt --all
  python3 scan_list.py top25_priority.txt --modules dns ssl headers port_scan
        """
    )
    
    parser.add_argument('target_file', help='File containing list of targets (one per line)')
    parser.add_argument('--modules', nargs='+', help='Specific modules to run')
    parser.add_argument('--all', action='store_true', help='Run all modules')
    parser.add_argument('--config', default='config/config.yaml', help='Config file path')
    
    args = parser.parse_args()
    
    # Load targets
    if not Path(args.target_file).exists():
        print(f"[-] Error: File not found: {args.target_file}")
        sys.exit(1)
    
    targets = load_target_list(args.target_file)
    print(f"[*] Loaded {len(targets)} targets from {args.target_file}")
    
    if not targets:
        print("[-] No targets found in file")
        sys.exit(1)
    
    # Initialize engine
    print(f"[*] Initializing RedHawk Engine...")
    engine = RedHawkEngine(config_path=args.config)
    
    # Disable all modules first
    for module in engine.config['modules']:
        engine.config['modules'][module]['enabled'] = False
    
    # Enable selected modules
    if args.all:
        for module in engine.config['modules']:
            engine.config['modules'][module]['enabled'] = True
        print(f"[*] Enabled all modules")
    elif args.modules:
        for module in args.modules:
            if module in engine.config['modules']:
                engine.config['modules'][module]['enabled'] = True
            else:
                print(f"[!] Warning: Unknown module '{module}'")
        print(f"[*] Enabled modules: {', '.join(args.modules)}")
    else:
        print("[-] Error: Specify --modules or --all")
        sys.exit(1)
    
    # Scan each target
    print(f"\n{'='*70}")
    print(f"  Starting scan of {len(targets)} targets")
    print(f"{'='*70}\n")
    
    results = []
    for i, target in enumerate(targets, 1):
        print(f"\n[{i}/{len(targets)}] Scanning {target}...")
        print("-" * 60)
        
        try:
            result = engine.run_all_modules(target)
            results.append(result)
            
            # Show summary
            if result.get('modules'):
                vuln_count = 0
                for module_name, module_result in result['modules'].items():
                    if module_result.get('status') == 'success':
                        vulns = len(module_result.get('vulnerabilities', []))
                        vuln_count += vulns
                        if vulns > 0:
                            print(f"  [!] {module_name}: {vulns} issues found")
                
                if vuln_count == 0:
                    print(f"  [+] No issues found")
                else:
                    print(f"  [!] Total: {vuln_count} issues")
            
            print(f"  [+] Results saved: {result.get('output_path', 'N/A')}")
            
        except KeyboardInterrupt:
            print(f"\n[!] Scan interrupted by user")
            break
        except Exception as e:
            print(f"  [-] Error scanning {target}: {e}")
            continue
    
    # Final summary
    print(f"\n{'='*70}")
    print(f"  SCAN COMPLETE")
    print(f"{'='*70}")
    print(f"  Scanned: {len(results)}/{len(targets)} targets")
    print(f"  Reports: reports/ directory")
    print(f"{'='*70}\n")

if __name__ == "__main__":
    main()