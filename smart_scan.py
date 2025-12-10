#!/usr/bin/env python3
"""
RedHawk Smart Scanner - Python-based tool for intelligent wildcard scanning
Handles discovery, prioritization, and focused scanning
"""

import json
import sys
import argparse
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Set

# Add project to path
sys.path.insert(0, str(Path(__file__).parent))

try:
    from core.engine import RedHawkEngine
except ImportError:
    print("[!] Error: Could not import RedHawkEngine")
    print("[*] Make sure you're running from RedHawk directory")
    sys.exit(1)


class SmartScanner:
    """Smart wildcard scanner with prioritization"""
    
    def __init__(self):
        self.engine = RedHawkEngine()
        self.subdomains = []
        self.priorities = {}
        
    def discover_subdomains(self, domain: str, save_raw: bool = True) -> List[str]:
        """Discover subdomains using wildcard module"""
        print(f"\n{'='*70}")
        print(f"  PHASE 1: SUBDOMAIN DISCOVERY")
        print(f"{'='*70}\n")
        
        # Ensure wildcard format
        if not domain.startswith('*.'):
            domain = f"*.{domain}"
        
        print(f"[*] Target: {domain}")
        print(f"[*] Running subdomain_wildcard module...")
        
        # Run discovery
        results = self.engine.run_module('subdomain_wildcard', domain)
        
        if results.get('status') != 'success':
            print(f"[-] Discovery failed: {results.get('error', 'Unknown error')}")
            return []
        
        # Extract subdomains
        self.subdomains = results.get('subdomains', [])
        
        print(f"\n[+] Discovered {len(self.subdomains)} subdomains!")
        
        # Save raw subdomain list
        if save_raw and self.subdomains:
            base_domain = domain.replace('*.', '')
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            
            # Save full list
            all_file = f"subdomains_{base_domain.replace('.', '_')}_{timestamp}.txt"
            with open(all_file, 'w') as f:
                for sub in sorted(self.subdomains):
                    f.write(f"{sub}\n")
            print(f"[+] Saved all subdomains to: {all_file}")
            
            # Save JSON with metadata
            json_file = f"discovery_{base_domain.replace('.', '_')}_{timestamp}.json"
            discovery_data = {
                'timestamp': timestamp,
                'base_domain': base_domain,
                'target': domain,
                'total_discovered': len(self.subdomains),
                'subdomains': self.subdomains,
                'discovery_methods': results.get('methods', {}),
                'statistics': results.get('statistics', {})
            }
            with open(json_file, 'w') as f:
                json.dump(discovery_data, f, indent=2)
            print(f"[+] Saved discovery data to: {json_file}")
        
        # Show sample
        if self.subdomains:
            print(f"\n[*] Sample subdomains (first 10):")
            for i, sub in enumerate(self.subdomains[:10], 1):
                print(f"  {i:2d}. {sub}")
            if len(self.subdomains) > 10:
                print(f"  ... and {len(self.subdomains) - 10} more")
        
        return self.subdomains
    
    def prioritize(self) -> Dict:
        """Prioritize discovered subdomains"""
        print(f"\n{'='*70}")
        print(f"  PHASE 2: SUBDOMAIN PRIORITIZATION")
        print(f"{'='*70}\n")
        
        if not self.subdomains:
            print("[-] No subdomains to prioritize")
            return {}
        
        print(f"[*] Analyzing {len(self.subdomains)} subdomains...")
        
        self.priorities = {
            'critical': {'keywords': [
                'parliament', 'presidency', 'cabinet', 'pm', 'president',
                'mfa', 'foreign', 'defense', 'military', 'army', 'navy', 'airforce',
                'nsa', 'nis', 'security', 'intelligence', 'cybersecurity'
            ], 'subdomains': []},
            'high': {'keywords': [
                'finance', 'treasury', 'mofep', 'revenue', 'tax', 'gra', 'cagd',
                'police', 'immigration', 'customs', 'fire', 'emergency', 'ges',
                'health', 'education', 'justice', 'interior', 'ghs',
                'portal', 'admin', 'api', 'webmail', 'mail', 'smtp', 'vpn'
            ], 'subdomains': []},
            'medium': {'keywords': [
                'energy', 'water', 'transport', 'roads', 'housing', 'works',
                'agriculture', 'trade', 'tourism', 'culture', 'sports', 'youth',
                'labor', 'employment', 'social', 'welfare', 'gender',
                'www', 'web', 'site', 'online', 'info', 'my'
            ], 'subdomains': []},
            'low': {'keywords': [
                'test', 'dev', 'staging', 'demo', 'sandbox', 'qa',
                'old', 'backup', 'archive', 'legacy', 'deprecated',
                'cdn', 'static', 'assets', 'img', 'images', 'media'
            ], 'subdomains': []}
        }
        
        # Categorize
        categorized = set()
        for subdomain in self.subdomains:
            lower_sub = subdomain.lower()
            
            for priority, data in self.priorities.items():
                if subdomain in categorized:
                    break
                for keyword in data['keywords']:
                    if keyword in lower_sub:
                        data['subdomains'].append(subdomain)
                        categorized.add(subdomain)
                        break
        
        # Remaining subdomains
        self.priorities['other'] = {
            'subdomains': [s for s in self.subdomains if s not in categorized]
        }
        
        # Display results
        self._display_priorities()
        
        return self.priorities
    
    def _display_priorities(self):
        """Display prioritization results"""
        print(f"\n{'='*70}")
        print(f"  PRIORITIZATION RESULTS")
        print(f"{'='*70}")
        
        priority_order = ['critical', 'high', 'medium', 'low', 'other']
        
        for level in priority_order:
            if level not in self.priorities:
                continue
            
            subs = self.priorities[level]['subdomains']
            if not subs:
                continue
            
            print(f"\n{level.upper()} PRIORITY: {len(subs)} targets")
            print("-" * 70)
            
            # Show first 15
            for i, sub in enumerate(subs[:15], 1):
                print(f"  {i:2d}. {sub}")
            
            if len(subs) > 15:
                print(f"  ... and {len(subs) - 15} more")
    
    def save_priority_lists(self, counts: List[int] = [10, 25, 50]) -> List[str]:
        """Save prioritized target lists"""
        print(f"\n{'='*70}")
        print(f"  SAVING TARGET LISTS")
        print(f"{'='*70}\n")
        
        if not self.priorities:
            print("[-] Run prioritize() first")
            return []
        
        # Collect all subdomains in priority order
        all_prioritized = []
        for level in ['critical', 'high', 'medium', 'low', 'other']:
            if level in self.priorities:
                all_prioritized.extend(self.priorities[level]['subdomains'])
        
        saved_files = []
        
        for count in counts:
            targets = all_prioritized[:count]
            if not targets:
                continue
            
            filename = f"top{count}_targets.txt"
            with open(filename, 'w') as f:
                f.write(f"# Top {count} Priority Targets\n")
                f.write(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"# Total discovered: {len(self.subdomains)}\n\n")
                for target in targets:
                    f.write(f"{target}\n")
            
            print(f"[+] Saved {len(targets)} targets to: {filename}")
            saved_files.append(filename)
        
        return saved_files
    
    def scan_targets(self, target_file: str, modules: List[str] = None):
        """Scan targets from a file"""
        print(f"\n{'='*70}")
        print(f"  PHASE 3: SCANNING TARGETS")
        print(f"{'='*70}\n")
        
        # Load targets
        if not Path(target_file).exists():
            print(f"[-] File not found: {target_file}")
            return
        
        with open(target_file) as f:
            targets = [line.strip() for line in f 
                      if line.strip() and not line.startswith('#')]
        
        if not targets:
            print(f"[-] No targets found in {target_file}")
            return
        
        print(f"[*] Loaded {len(targets)} targets from {target_file}")
        
        # Configure modules
        if modules:
            for module in self.engine.config['modules']:
                self.engine.config['modules'][module]['enabled'] = module in modules
            print(f"[*] Enabled modules: {', '.join(modules)}")
        else:
            print(f"[*] Using all enabled modules")
        
        # Estimate time
        est_time_min = len(targets) * 2
        est_time_max = len(targets) * 3
        print(f"[*] Estimated time: {est_time_min}-{est_time_max} minutes\n")
        
        # Confirm
        try:
            response = input(f"[?] Proceed with scan? (y/n): ").lower().strip()
            if response not in ['y', 'yes']:
                print("[!] Scan cancelled")
                return
        except KeyboardInterrupt:
            print("\n[!] Scan cancelled")
            return
        
        # Scan each target
        results = []
        for i, target in enumerate(targets, 1):
            print(f"\n{'='*70}")
            print(f"[{i}/{len(targets)}] Scanning: {target}")
            print(f"{'='*70}")
            
            try:
                result = self.engine.run_all_modules(target)
                results.append(result)
                
                # Show summary
                vuln_count = 0
                for module_name, module_result in result.get('modules', {}).items():
                    if module_result.get('status') == 'success':
                        vulns = len(module_result.get('vulnerabilities', []))
                        vuln_count += vulns
                        if vulns > 0:
                            print(f"  [!] {module_name}: {vulns} issues")
                
                if vuln_count == 0:
                    print(f"  [+] No critical issues found")
                else:
                    print(f"  [!] Total: {vuln_count} issues found")
                
                print(f"  [+] Report: {result.get('output_path', 'N/A')}")
                
            except KeyboardInterrupt:
                print(f"\n[!] Scan interrupted by user")
                break
            except Exception as e:
                print(f"  [-] Error: {e}")
                continue
        
        print(f"\n{'='*70}")
        print(f"  SCAN COMPLETE")
        print(f"{'='*70}")
        print(f"[+] Scanned: {len(results)}/{len(targets)} targets")
        print(f"[+] Reports saved to: reports/ directory")
    
    def interactive_mode(self, domain: str):
        """Interactive mode with menu"""
        print(f"\n{'='*70}")
        print(f"  RedHawk Smart Scanner - Interactive Mode")
        print(f"{'='*70}\n")
        
        while True:
            print(f"\nCurrent status:")
            print(f"  - Discovered: {len(self.subdomains)} subdomains")
            print(f"  - Prioritized: {'Yes' if self.priorities else 'No'}")
            
            print(f"\nOptions:")
            print(f"  1. Discover subdomains (Phase 1)")
            print(f"  2. Prioritize subdomains (Phase 2)")
            print(f"  3. Save priority lists")
            print(f"  4. Scan top 10 critical")
            print(f"  5. Scan top 25 priority")
            print(f"  6. Scan from custom file")
            print(f"  7. Show priorities")
            print(f"  8. Export subdomain list")
            print(f"  0. Exit")
            
            try:
                choice = input(f"\n[?] Select option: ").strip()
                
                if choice == '0':
                    print("[*] Exiting...")
                    break
                
                elif choice == '1':
                    self.discover_subdomains(domain)
                
                elif choice == '2':
                    if not self.subdomains:
                        print("[!] Run discovery first (option 1)")
                    else:
                        self.prioritize()
                
                elif choice == '3':
                    if not self.priorities:
                        print("[!] Run prioritization first (option 2)")
                    else:
                        self.save_priority_lists()
                
                elif choice == '4':
                    if not Path('top10_targets.txt').exists():
                        print("[!] Run options 1, 2, 3 first")
                    else:
                        modules = input("[?] Modules (comma-separated, or 'all'): ").strip()
                        if modules.lower() == 'all':
                            modules = None
                        else:
                            modules = [m.strip() for m in modules.split(',')]
                        self.scan_targets('top10_targets.txt', modules)
                
                elif choice == '5':
                    if not Path('top25_targets.txt').exists():
                        print("[!] Run options 1, 2, 3 first")
                    else:
                        modules = input("[?] Modules (comma-separated, or 'all'): ").strip()
                        if modules.lower() == 'all':
                            modules = None
                        else:
                            modules = [m.strip() for m in modules.split(',')]
                        self.scan_targets('top25_targets.txt', modules)
                
                elif choice == '6':
                    filename = input("[?] Target file path: ").strip()
                    modules = input("[?] Modules (comma-separated, or 'all'): ").strip()
                    if modules.lower() == 'all':
                        modules = None
                    else:
                        modules = [m.strip() for m in modules.split(',')]
                    self.scan_targets(filename, modules)
                
                elif choice == '7':
                    if not self.priorities:
                        print("[!] Run prioritization first (option 2)")
                    else:
                        self._display_priorities()
                
                elif choice == '8':
                    if not self.subdomains:
                        print("[!] Run discovery first (option 1)")
                    else:
                        filename = input("[?] Output filename [subdomains.txt]: ").strip()
                        if not filename:
                            filename = 'subdomains.txt'
                        with open(filename, 'w') as f:
                            for sub in sorted(self.subdomains):
                                f.write(f"{sub}\n")
                        print(f"[+] Saved {len(self.subdomains)} subdomains to: {filename}")
                
                else:
                    print("[!] Invalid option")
                
            except KeyboardInterrupt:
                print("\n[!] Interrupted")
                break
            except Exception as e:
                print(f"[!] Error: {e}")


def main():
    parser = argparse.ArgumentParser(
        description='RedHawk Smart Scanner - Intelligent wildcard scanning',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive mode
  python3 smart_scan.py gov.gh --interactive
  
  # Automatic workflow
  python3 smart_scan.py gov.gh --discover --prioritize --save-lists
  
  # Full workflow with scanning
  python3 smart_scan.py gov.gh --discover --prioritize --save-lists --scan-top10
  
  # Scan from existing list
  python3 smart_scan.py gov.gh --scan top10_targets.txt --modules dns email ssl
        """
    )
    
    parser.add_argument('domain', help='Target domain (e.g., gov.gh)')
    parser.add_argument('-i', '--interactive', action='store_true', 
                       help='Interactive mode with menu')
    parser.add_argument('-d', '--discover', action='store_true', 
                       help='Run subdomain discovery')
    parser.add_argument('-p', '--prioritize', action='store_true', 
                       help='Prioritize discovered subdomains')
    parser.add_argument('-s', '--save-lists', action='store_true', 
                       help='Save priority lists (top10, top25, top50)')
    parser.add_argument('--scan-top10', action='store_true', 
                       help='Scan top 10 critical targets')
    parser.add_argument('--scan-top25', action='store_true', 
                       help='Scan top 25 priority targets')
    parser.add_argument('--scan', type=str, metavar='FILE', 
                       help='Scan targets from file')
    parser.add_argument('--modules', nargs='+', 
                       help='Specific modules to use for scanning')
    
    args = parser.parse_args()
    
    scanner = SmartScanner()
    
    # Interactive mode
    if args.interactive:
        scanner.interactive_mode(args.domain)
        return
    
    # Automatic workflow
    if args.discover:
        scanner.discover_subdomains(args.domain)
    
    if args.prioritize:
        if not scanner.subdomains:
            print("[!] No subdomains to prioritize. Run --discover first.")
        else:
            scanner.prioritize()
    
    if args.save_lists:
        if not scanner.priorities:
            print("[!] No priorities to save. Run --prioritize first.")
        else:
            scanner.save_priority_lists()
    
    if args.scan_top10:
        scanner.scan_targets('top10_targets.txt', args.modules)
    
    if args.scan_top25:
        scanner.scan_targets('top25_targets.txt', args.modules)
    
    if args.scan:
        scanner.scan_targets(args.scan, args.modules)
    
    # If no action specified, show help
    if not any([args.interactive, args.discover, args.prioritize, 
                args.save_lists, args.scan_top10, args.scan_top25, args.scan]):
        parser.print_help()


if __name__ == "__main__":
    main()