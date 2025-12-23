#!/usr/bin/env python3
"""
RedHawk Launcher - improved CLI/GUI entrypoint

Improvements applied:
- Lazy imports (GUI not required for CLI)
- Support positional target as well as --target
- Support --modules (comma-separated) and --module (single)
- Safer engine invocation with error handling
- Clearer import error handling and non-zero exit
"""

import sys
import os
from pathlib import Path
import warnings
import argparse
import logging

# Suppress SSL warnings (expected for security scanning)
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

# Also suppress at urllib3 level
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure basic logging
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
log = logging.getLogger("RedHawk")

# Get the directory where this script is located
SCRIPT_DIR = Path(__file__).parent.resolve()

# Add to Python path
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

# Change to script directory
os.chdir(SCRIPT_DIR)


def parse_args():
    parser = argparse.ArgumentParser(
        description='RedHawk - Offensive Security Framework',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Launch GUI
  python3 scan.py --gui

  # CLI: single target (positional)
  python3 scan.py example.com

  # CLI: positional with modules
  python3 scan.py example.com --modules dns,ssl

  # CLI: explicit flags
  python3 scan.py --cli --target example.com --module dns
"""
    )

    parser.add_argument('--gui', action='store_true', help='Launch GUI interface')
    parser.add_argument('--cli', action='store_true', help='Run in CLI mode')
    parser.add_argument('--target', type=str, help='Target domain/IP')
    parser.add_argument('positional_target', nargs='?', help='Positional target (legacy/simple)')
    parser.add_argument('--module', type=str, help='Specific module to run (single)')
    parser.add_argument('--modules', type=str, help='Comma-separated list of modules to run')
    parser.add_argument('--all', action='store_true', help='Run all modules')
    parser.add_argument('--report', type=str, help='Generate report from scan data')
    parser.add_argument('--config', type=str, default='config/config.yaml', help='Config file path')
    parser.add_argument('--version', action='store_true', help='Show version and exit')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')

    return parser.parse_args()


def main():
    args = parse_args()

    if args.version:
        print("RedHawk: version information not set in this script.")
        sys.exit(0)

    # Set logging level
    if args.verbose:
        log.setLevel(logging.DEBUG)

    # If no args and no positional target, default to GUI
    if len(sys.argv) == 1 or args.gui:
        # Lazy import GUI so CLI usage doesn't require GUI deps
        try:
            from gui.main_window import RedHawkGUI
        except ImportError as e:
            log.error("GUI dependencies are missing: %s", e)
            log.info("If you intended to run the CLI, use: python3 scan.py <target> or --cli --target <target>")
            sys.exit(1)

        log.info("Launching RedHawk GUI...")
        app = RedHawkGUI()
        app.run()
        return

    # Resolve target (positional or --target)
    target = args.target or args.positional_target

    # If report requested (separate flow)
    if args.report:
        try:
            from core.engine import RedHawkEngine
        except ImportError as e:
            log.error("Import Error: %s", e)
            log.error("Ensure requirements are installed: python3 -m pip install -r requirements.txt --user")
            sys.exit(1)

        engine = RedHawkEngine(config_path=args.config)
        try:
            engine.generate_report(args.report)
            log.info("Report generation complete: %s", args.report)
        except Exception as e:
            log.error("Report generation failed: %s", e)
            sys.exit(1)
        return

    # CLI flow
    if args.cli or target:
        if not target:
            log.error("--target required for CLI mode (or provide positional target)")
            sys.exit(1)

        # Prepare modules list
        modules = None
        if args.modules:
            modules = [m.strip() for m in args.modules.split(',') if m.strip()]
        elif args.module:
            modules = [args.module.strip()]

        # Lazy import engine
        try:
            from core.engine import RedHawkEngine
        except ImportError as e:
            log.error("Import Error: %s", e)
            log.error("Ensure requirements are installed: python3 -m pip install -r requirements.txt --user")
            sys.exit(1)

        log.info("Initializing RedHawk Engine...")
        engine = RedHawkEngine(config_path=args.config)

        try:
            if args.all:
                log.info("Running all modules against %s", target)
                results = engine.run_all_modules(target)
            elif modules:
                # If modules list provided, run them one by one or via engine.run_modules if exists
                if hasattr(engine, 'run_modules'):
                    log.info("Running modules %s against %s", modules, target)
                    results = engine.run_modules(modules, target)
                else:
                    all_results = {}
                    for mod in modules:
                        log.info("Running module '%s' against %s", mod, target)
                        mod_res = engine.run_module(mod, target)
                        all_results[mod] = mod_res
                    results = {'modules': all_results}
            elif args.module:
                log.info("Running module '%s' against %s", args.module, target)
                results = engine.run_module(args.module, target)
            else:
                log.error("Specify --module/--modules or --all")
                sys.exit(1)
        except Exception as e:
            log.error("Scan failed: %s", e)
            sys.exit(1)

        # Print a short summary
        if isinstance(results, dict):
            outpath = results.get('output_path', 'N/A')
            log.info("Scan complete. Results saved to: %s", outpath)
        else:
            log.info("Scan complete.")
        return

    # If we reach here, print help
    print("No action taken. Use --help for usage.")
    sys.exit(0)


if __name__ == '__main__':
    main()
