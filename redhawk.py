#!/usr/bin/env python3
"""
RedHawk - Offensive Security & OSINT Framework
A modular, lightweight framework for security assessments
"""

import sys
import os
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.resolve()
sys.path.insert(0, str(project_root))

# Now import with error handling
try:
    from core.engine import RedHawkEngine
    from gui.main_window import RedHawkGUI
except ImportError as e:
    print(f"[!] Import Error: {e}")
    print(f"[*] Current directory: {os.getcwd()}")
    print(f"[*] Script location: {project_root}")
    print(f"[*] Python path: {sys.path[:3]}")
    print("\n[!] Please ensure you're running from the RedHawk directory")
    print("    cd /path/to/RedHawk")
    print("    python3 redhawk.py --gui")
    sys.exit(1)

import argparse

def main():
    parser = argparse.ArgumentParser(
        description='RedHawk - Offensive Security Framework',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python redhawk.py --gui                    # Launch GUI interface
  python redhawk.py --cli --target example.com --module dns
  python redhawk.py --cli --target example.com --all
  python redhawk.py --report /path/to/scan
        """
    )
    
    parser.add_argument('--gui', action='store_true', help='Launch GUI interface')
    parser.add_argument('--cli', action='store_true', help='Run in CLI mode')
    parser.add_argument('--target', type=str, help='Target domain/IP')
    parser.add_argument('--module', type=str, help='Specific module to run')
    parser.add_argument('--all', action='store_true', help='Run all modules')
    parser.add_argument('--report', type=str, help='Generate report from scan data')
    parser.add_argument('--config', type=str, default='config/config.yaml', help='Config file path')
    
    args = parser.parse_args()
    
    # If no arguments, launch GUI by default
    if len(sys.argv) == 1:
        args.gui = True
    
    if args.gui:
        print("[*] Launching RedHawk GUI...")
        app = RedHawkGUI()
        app.run()
    elif args.cli:
        if not args.target:
            print("[-] Error: --target required for CLI mode")
            sys.exit(1)
        
        print(f"[*] Initializing RedHawk Engine...")
        engine = RedHawkEngine(config_path=args.config)
        
        if args.all:
            print(f"[*] Running all modules against {args.target}")
            results = engine.run_all_modules(args.target)
        elif args.module:
            print(f"[*] Running module '{args.module}' against {args.target}")
            results = engine.run_module(args.module, args.target)
        else:
            print("[-] Error: Specify --module or --all")
            sys.exit(1)
        
        print(f"[+] Scan complete. Results saved to: {results['output_path']}")
    
    elif args.report:
        print(f"[*] Generating report from: {args.report}")
        engine = RedHawkEngine(config_path=args.config)
        engine.generate_report(args.report)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()