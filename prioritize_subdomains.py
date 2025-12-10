#!/usr/bin/env python3
"""
Smart Subdomain Prioritization
Extracts and prioritizes high-value targets from wildcard discovery
"""

import json
import sys
from pathlib import Path

def load_latest_wildcard_results():
    """Load the most recent wildcard scan results"""
    reports_dir = Path('reports')
    if not reports_dir.exists():
        print("[-] No reports directory found")
        return None
    
    # Find latest wildcard report
    wildcard_reports = list(reports_dir.glob('wildcard_*.json'))
    if not wildcard_reports:
        print("[-] No wildcard reports found")
        return None
    
    latest = max(wildcard_reports, key=lambda p: p.stat().st_mtime)
    print(f"[*] Loading: {latest.name}")
    
    with open(latest) as f:
        return json.load(f)

def prioritize_subdomains(subdomains):
    """Prioritize subdomains by importance"""
    
    # Define priority categories
    priorities = {
        'critical': {
            'keywords': [
                'parliament', 'presidency', 'cabinet', 'pm', 'president',
                'mfa', 'foreign', 'defense', 'military', 'army', 'navy', 'airforce',
                'nsa', 'nis', 'security', 'intelligence'
            ],
            'subdomains': []
        },
        'high': {
            'keywords': [
                'finance', 'treasury', 'mofep', 'revenue', 'tax', 'gra',
                'police', 'immigration', 'customs', 'fire', 'emergency',
                'health', 'education', 'justice', 'interior',
                'portal', 'admin', 'api', 'webmail', 'mail', 'smtp'
            ],
            'subdomains': []
        },
        'medium': {
            'keywords': [
                'energy', 'water', 'transport', 'roads', 'housing',
                'agriculture', 'trade', 'tourism', 'culture', 'sports',
                'labor', 'employment', 'social', 'welfare',
                'www', 'web', 'site', 'online'
            ],
            'subdomains': []
        },
        'low': {
            'keywords': [
                'test', 'dev', 'staging', 'demo', 'old', 'backup',
                'archive', 'static', 'cdn', 'assets', 'img', 'images'
            ],
            'subdomains': []
        }
    }
    
    # Categorize subdomains
    categorized = set()
    for subdomain in subdomains:
        lower_sub = subdomain.lower()
        
        for priority, data in priorities.items():
            if subdomain in categorized:
                break
            for keyword in data['keywords']:
                if keyword in lower_sub:
                    data['subdomains'].append(subdomain)
                    categorized.add(subdomain)
                    break
    
    # Remaining subdomains
    priorities['other'] = {
        'subdomains': [s for s in subdomains if s not in categorized]
    }
    
    return priorities

def print_priorities(priorities):
    """Print prioritized subdomains"""
    
    print("\n" + "="*70)
    print("  PRIORITIZED SUBDOMAIN TARGETS")
    print("="*70)
    
    priority_order = ['critical', 'high', 'medium', 'low', 'other']
    
    for level in priority_order:
        if level not in priorities:
            continue
        
        subs = priorities[level]['subdomains']
        if not subs:
            continue
        
        print(f"\n{'='*70}")
        print(f"  {level.upper()} PRIORITY ({len(subs)} targets)")
        print(f"{'='*70}")
        
        # Show first 20
        for i, sub in enumerate(subs[:20], 1):
            print(f"  {i:2d}. {sub}")
        
        if len(subs) > 20:
            print(f"  ... and {len(subs) - 20} more")
    
    print("\n" + "="*70)

def generate_scan_lists(priorities):
    """Generate scan list files"""
    
    # Top 10 critical targets
    top10 = []
    for level in ['critical', 'high']:
        if level in priorities:
            top10.extend(priorities[level]['subdomains'])
    top10 = top10[:10]
    
    # Top 25 priority targets
    top25 = []
    for level in ['critical', 'high', 'medium']:
        if level in priorities:
            top25.extend(priorities[level]['subdomains'])
    top25 = top25[:25]
    
    # Top 50 targets
    top50 = []
    for level in ['critical', 'high', 'medium']:
        if level in priorities:
            top50.extend(priorities[level]['subdomains'])
    top50 = top50[:50]
    
    # Save lists
    lists = {
        'top10_critical.txt': top10,
        'top25_priority.txt': top25,
        'top50_targets.txt': top50
    }
    
    for filename, subdomains in lists.items():
        if not subdomains:
            continue
        with open(filename, 'w') as f:
            for sub in subdomains:
                f.write(f"{sub}\n")
        print(f"[+] Saved: {filename} ({len(subdomains)} targets)")

def main():
    print("\n" + "="*70)
    print("  RedHawk Subdomain Prioritization Tool")
    print("="*70 + "\n")
    
    # Load results
    results = load_latest_wildcard_results()
    if not results:
        return
    
    # Extract subdomains
    subdomains = []
    if 'subdomain_discovery' in results:
        subdomains = results['subdomain_discovery'].get('subdomains', [])
    elif 'subdomains' in results:
        subdomains = results['subdomains']
    
    if not subdomains:
        print("[-] No subdomains found in results")
        return
    
    print(f"[*] Total subdomains discovered: {len(subdomains)}")
    
    # Prioritize
    print("[*] Analyzing and prioritizing targets...")
    priorities = prioritize_subdomains(subdomains)
    
    # Display
    print_priorities(priorities)
    
    # Generate scan lists
    print("\n" + "="*70)
    print("  GENERATING SCAN LISTS")
    print("="*70 + "\n")
    generate_scan_lists(priorities)
    
    # Recommendations
    print("\n" + "="*70)
    print("  SCANNING RECOMMENDATIONS")
    print("="*70)
    print("""
Phase 1 - Quick Assessment (30-60 minutes):
  python3 scan_list.py top10_critical.txt --modules dns email ssl

Phase 2 - Priority Targets (2-3 hours):
  python3 scan_list.py top25_priority.txt --modules dns email ssl headers

Phase 3 - Extended Analysis (5-8 hours):
  python3 scan_list.py top50_targets.txt --all

GUI Approach:
  1. Click Stop on current scan
  2. Copy targets from top10_critical.txt
  3. Scan them individually with GUI
  4. Assess results before expanding
    """)
    print("="*70 + "\n")

if __name__ == "__main__":
    main()