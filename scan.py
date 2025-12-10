#!/usr/bin/env python3
"""
RedHawk Launcher - Clean version without SSL warnings
"""

import sys
import os
from pathlib import Path
import warnings

# Suppress SSL warnings (expected for security scanning)
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

# Also suppress at urllib3 level
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Get the directory where this script is located
SCRIPT_DIR = Path(__file__).parent.resolve()

# Add to Python path
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

# Change to script directory
os.chdir(SCRIPT_DIR)

# Now run the main application
if __name__ == "__main__":
    try:
        from core.engine import RedHawkEngine
        from gui.main_window import RedHawkGUI
        import argparse
        
        parser = argparse.ArgumentParser(
            description='RedHawk - Offensive Security Framework',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  python3 scan.py --gui                    # Launch GUI interface
  python3 scan.py --cli --target example.com --module dns
  python3 scan.py --cli --target example.com --all
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
            
            print(f"[+] Scan complete. Results saved to: {results.get('output_path', 'N/A')}")
        
        elif args.report:
            print(f"[*] Generating report from: {args.report}")
            engine = RedHawkEngine(config_path=args.config)
            engine.generate_report(args.report)
        else:
            parser.print_help()
            
    except ImportError as e:
        print(f"\n[!] Import Error: {e}")
        print(f"\n[*] Troubleshooting:")
        print(f"    1. Ensure you're in the RedHawk directory")
        print(f"    2. Run: pip3 install -r requirements.txt --break-system-packages")
        print(f"    3. Run: ./verify.sh")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)