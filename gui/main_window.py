"""
""" 
Main GUI for RedHawk Framework
Lightweight, responsive interface using tkinter
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog, simpledialog
import threading
import json
from pathlib import Path
from datetime import datetime
import sys
import os
import shutil
import traceback
import concurrent.futures
import time

# Ensure parent directory is in path
current_dir = Path(__file__).parent
project_root = current_dir.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

try:
    from core.engine import RedHawkEngine
except Exception:
    # Fallback for direct execution
    sys.path.insert(0, str(Path(__file__).parent.parent))
    try:
        from core.engine import RedHawkEngine
    except Exception:
        RedHawkEngine = None


class _EngineFallback:
    """A small adapter to provide common engine APIs when the real engine
    is unavailable or has a different interface. This is a best-effort
    compatibility shim used by the GUI to avoid crashing if the engine
    implementation changed.
    """
    def __init__(self):
        self.real = None
        self._stop_event = threading.Event()
        self._executor = concurrent.futures.ThreadPoolExecutor(max_workers=4)
        # Try to instantiate a real engine if available
        if RedHawkEngine:
            try:
                self.real = RedHawkEngine()
            except Exception:
                self.real = None

    def get_available_modules(self):
        try:
            if self.real and hasattr(self.real, 'get_available_modules'):
                modules = self.real.get_available_modules()
                # Handle both list and dict
                if isinstance(modules, dict):
                    return list(modules.keys())
                return list(modules)
            if self.real and hasattr(self.real, 'discover_modules'):
                modules = self.real.discover_modules()
                # Handle both list and dict
                if isinstance(modules, dict):
                    return list(modules.keys())
                return list(modules)
            if self.real and hasattr(self.real, '_tasks'):
                return list(self.real._tasks.keys())
        except Exception:
            traceback.print_exc()
        return []

    def discover_modules(self):
        return self.get_available_modules()

    def run_all_modules(self, target, callback=None):
        # Best-effort: run all modules via run_modules
        modules = self.get_available_modules()
        return self.run_modules(modules, target, callback=callback)

    def run_modules(self, modules, target, callback=None):
        results = {}
        for m in modules:
            if self._stop_event.is_set():
                results[m] = {'status': 'stopped'}
                continue
            try:
                r = self.run_module(m, target, callback=callback)
                results[m] = r if isinstance(r, dict) else {'status': 'success', 'result': r}
            except Exception as e:
                results[m] = {'status': 'error', 'error': str(e)}
        return results

    def run_module(self, module_name, target, callback=None):
        # If real engine supports it, delegate
        if self.real and hasattr(self.real, 'run_module'):
            try:
                return self.real.run_module(module_name, target, callback=callback)
            except TypeError:
                # maybe callback not supported
                return self.real.run_module(module_name, target)
            except Exception:
                traceback.print_exc()
        # Simulate a quick result so the GUI remains responsive
        result = {'status': 'success', 'summary': f'Fake scan of {module_name} on {target}', 'result': None}
        if callback:
            try:
                callback(module_name, result)
            except Exception:
                traceback.print_exc()
        # small sleep to emulate work
        time.sleep(0.05)
        return result

    def run_task(self, name, *args, **kwargs):
        # Try to run synchronously
        try:
            return self.run_module(name, *args, **kwargs)
        except Exception:
            traceback.print_exc()
            return {'status': 'error', 'error': 'failed to run task'}

    def submit_task(self, name, *args, **kwargs):
        # Return a future that runs the task in background
        return self._executor.submit(self.run_module, name, *(args or []), **(kwargs or {}))

    def stop(self):
        self._stop_event.set()

    def save_results(self, results):
        try:
            path = os.path.join(os.getcwd(), 'redhawk_saved_results.json')
            with open(path, 'w') as fh:
                json.dump(results, fh, indent=2)
            return path
        except Exception:
            traceback.print_exc()
            return None


class RedHawkGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("RedHawk - Offensive Security Framework")
        self.root.geometry("1200x800")

        # Initialize engine
        try:
            if RedHawkEngine:
                try:
                    self.engine = RedHawkEngine()
                except Exception:
                    # fallback to adapter which may attempt to instantiate engine
                    self.engine = _EngineFallback()
            else:
                self.engine = _EngineFallback()
        except Exception:
            # If everything fails, use fallback
            self.engine = _EngineFallback()

        # Scan state
        self.is_scanning = False
        self.current_results = None

        # Setup GUI
        self.setup_styles()
        self.create_widgets()

    def setup_styles(self):
        """Setup custom styles"""
        style = ttk.Style()
        try:
            style.theme_use('clam')
        except Exception:
            pass

        # Custom colors
        bg_dark = '#1e1e1e'
        bg_medium = '#2d2d2d'
        fg_color = '#ffffff'
        accent = '#00ff41'

        style.configure('Main.TFrame', background=bg_dark)
        style.configure('Title.TLabel', background=bg_dark, foreground=accent,
                        font=('Courier', 16, 'bold'))
        style.configure('Info.TLabel', background=bg_dark, foreground=fg_color,
                        font=('Courier', 10))
        style.configure('Accent.TButton', font=('Courier', 10, 'bold'))

    def _get_engine_modules(self):
        """Return a list of module names from the engine, using fallbacks."""
        try:
            if self.engine is None:
                return []
            # Preferred API - discover_modules (may return dict or list)
            if hasattr(self.engine, 'discover_modules'):
                discovered = self.engine.discover_modules()
                # If it's a dict, get the keys
                if isinstance(discovered, dict):
                    return list(discovered.keys())
                # If it's a list or other iterable
                return list(discovered)
            # get_available_modules API
            if hasattr(self.engine, 'get_available_modules'):
                modules = self.engine.get_available_modules()
                # Handle both list and dict returns
                if isinstance(modules, dict):
                    return list(modules.keys())
                return list(modules)
            # older semantic: _tasks registry
            if hasattr(self.engine, '_tasks'):
                return list(self.engine._tasks.keys())
        except Exception:
            traceback.print_exc()
        return []

    def create_widgets(self):
        """Create all GUI widgets"""
        # Main frame
        main_frame = ttk.Frame(self.root, style='Main.TFrame')
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Title
        title_frame = ttk.Frame(main_frame, style='Main.TFrame')
        title_frame.pack(fill=tk.X, pady=(0, 10))

        title_label = ttk.Label(title_frame, text="🦅 RedHawk Security Framework",
                               style='Title.TLabel')
        title_label.pack(side=tk.LEFT)

        # Target input section
        input_frame = ttk.Frame(main_frame, style='Main.TFrame')
        input_frame.pack(fill=tk.X, pady=5)

        ttk.Label(input_frame, text="Target:", style='Info.TLabel').pack(side=tk.LEFT, padx=5)

        self.target_entry = ttk.Entry(input_frame, width=40, font=('Courier', 10))
        self.target_entry.pack(side=tk.LEFT, padx=5)
        self.target_entry.insert(0, "example.com")

        # Wildcard checkbox
        self.wildcard_var = tk.BooleanVar(value=False)
        self.wildcard_cb = ttk.Checkbutton(
            input_frame,
            text="Wildcard Scan (*)",
            variable=self.wildcard_var,
            command=self.toggle_wildcard
        )
        self.wildcard_cb.pack(side=tk.LEFT, padx=5)

        # Wildcard info label
        self.wildcard_info = ttk.Label(
            input_frame,
            text="",
            style='Info.TLabel',
            foreground='#00ff41'
        )
        self.wildcard_info.pack(side=tk.LEFT, padx=5)

        # Scan buttons
        self.scan_btn = ttk.Button(input_frame, text="Scan All",
                                   command=self.start_scan_all, style='Accent.TButton')
        self.scan_btn.pack(side=tk.LEFT, padx=5)

        self.stop_btn = ttk.Button(input_frame, text="Stop",
                                   command=self.stop_scan, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)

        # Smart scanning buttons
        self.prioritize_btn = ttk.Button(input_frame, text="Prioritize Results",
                                         command=self.prioritize_results)
        self.prioritize_btn.pack(side=tk.LEFT, padx=5)

        self.scan_list_btn = ttk.Button(input_frame, text="Scan from List",
                                       command=self.scan_from_list)
        self.scan_list_btn.pack(side=tk.LEFT, padx=5)

        # Module selection frame
        module_frame = ttk.LabelFrame(main_frame, text="Modules", padding=10)
        module_frame.pack(fill=tk.X, pady=5)

        self.module_vars = {}
        modules = self._get_engine_modules()

        for i, module in enumerate(modules):
            var = tk.BooleanVar(value=True)
            self.module_vars[module] = var
            cb = ttk.Checkbutton(module_frame, text=module.upper(), variable=var)
            cb.grid(row=i//4, column=i%4, sticky=tk.W, padx=10)

        # Progress section
        progress_frame = ttk.Frame(main_frame, style='Main.TFrame')
        progress_frame.pack(fill=tk.X, pady=5)

        self.progress_var = tk.StringVar(value="Ready")
        ttk.Label(progress_frame, textvariable=self.progress_var,
                 style='Info.TLabel').pack(side=tk.LEFT)

        self.progress_bar = ttk.Progressbar(progress_frame, mode='indeterminate')
        self.progress_bar.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=10)

        # Notebook for results
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=5)

        # Console tab
        console_frame = ttk.Frame(self.notebook)
        self.notebook.add(console_frame, text="Console")

        self.console = scrolledtext.ScrolledText(console_frame,
                                                 bg='#1e1e1e', fg='#00ff41',
                                                 font=('Courier', 9),
                                                 wrap=tk.WORD)
        self.console.pack(fill=tk.BOTH, expand=True)

        # Results tab
        results_frame = ttk.Frame(self.notebook)
        self.notebook.add(results_frame, text="Results")

        self.results_tree = ttk.Treeview(results_frame, columns=('value',),
                                        show='tree headings')
        self.results_tree.heading('#0', text='Finding')
        self.results_tree.heading('value', text='Details')
        self.results_tree.column('value', width=400)

        results_scroll = ttk.Scrollbar(results_frame, orient=tk.VERTICAL,
                                      command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=results_scroll.set)

        self.results_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        results_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # Vulnerabilities tab
        vuln_frame = ttk.Frame(self.notebook)
        self.notebook.add(vuln_frame, text="Vulnerabilities")

        self.vuln_tree = ttk.Treeview(vuln_frame,
                                     columns=('severity', 'type', 'description'),
                                     show='headings')
        self.vuln_tree.heading('severity', text='Severity')
        self.vuln_tree.heading('type', text='Type')
        self.vuln_tree.heading('description', text='Description')
        self.vuln_tree.column('severity', width=100)
        self.vuln_tree.column('type', width=200)

        vuln_scroll = ttk.Scrollbar(vuln_frame, orient=tk.VERTICAL,
                                   command=self.vuln_tree.yview)
        self.vuln_tree.configure(yscrollcommand=vuln_scroll.set)

        self.vuln_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vuln_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # Bottom buttons
        bottom_frame = ttk.Frame(main_frame, style='Main.TFrame')
        bottom_frame.pack(fill=tk.X, pady=5)

        ttk.Button(bottom_frame, text="Export Report",
                  command=self.export_report).pack(side=tk.LEFT, padx=5)
        ttk.Button(bottom_frame, text="Clear",
                  command=self.clear_results).pack(side=tk.LEFT, padx=5)
        ttk.Button(bottom_frame, text="About",
                  command=self.show_about).pack(side=tk.RIGHT, padx=5)

        # Initial message
        self.log("RedHawk Framework initialized")
        self.log(f"Loaded {len(modules)} modules")
        self.log("Ready to scan...")

    def log(self, message):
        """Add message to console"""
        try:
            self.console.insert(tk.END, f"{message}\n")
            self.console.see(tk.END)
            self.root.update_idletasks()
        except Exception:
            # Console may not be ready during early init
            print(message)

    def toggle_wildcard(self):
        """Toggle wildcard scanning mode"""
        if self.wildcard_var.get():
            target = self.target_entry.get().strip()
            if not target.startswith('*.'):
                self.target_entry.delete(0, tk.END)
                self.target_entry.insert(0, f"*.{target}")
            self.wildcard_info.config(text="Will discover all subdomains")
            self.log("[*] Wildcard mode enabled - will discover subdomains first")
        else:
            target = self.target_entry.get().strip()
            if target.startswith('*.'):
                self.target_entry.delete(0, tk.END)
                self.target_entry.insert(0, target[2:])
            self.wildcard_info.config(text="")
            self.log("[*] Wildcard mode disabled")

    def start_scan_all(self):
        """Start scanning all enabled modules"""
        target = self.target_entry.get().strip()

        if not target:
            messagebox.showerror("Error", "Please enter a target domain or IP")
            return

        # Check if wildcard mode
        is_wildcard = self.wildcard_var.get() or target.startswith('*.')

        if is_wildcard and not target.startswith('*.'):
            target = f"*.{target}"

        # Try to update engine config if applicable
        try:
            for module, var in self.module_vars.items():
                if hasattr(self.engine, 'config') and isinstance(self.engine.config, dict):
                    if module in self.engine.config.get('modules', {}):
                        self.engine.config['modules'][module]['enabled'] = var.get()
        except Exception:
            pass

        self.is_scanning = True
        self.scan_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        try:
            self.progress_bar.start()
        except Exception:
            pass

        if is_wildcard:
            self.progress_var.set(f"Discovering subdomains for {target}...")
            self.log(f"\n[*] Starting wildcard scan: {target}")
        else:
            self.progress_var.set(f"Scanning {target}...")
            self.log(f"\n[*] Starting scan against: {target}")

        self.clear_results()

        # Run scan in separate thread
        thread = threading.Thread(target=self._run_scan, args=(target, is_wildcard))
        thread.daemon = True
        thread.start()

    def _run_scan(self, target, is_wildcard=False):
        """Run scan in background thread"""
        try:
            if is_wildcard:
                results = self._run_wildcard_scan(target)
            else:
                # Try multiple engine API styles
                results = {}
                if self.engine is None:
                    raise RuntimeError("Engine not available")

                # If engine supports run_all_modules
                if hasattr(self.engine, 'run_all_modules'):
                    try:
                        results = self.engine.run_all_modules(target, callback=self._scan_callback)
                    except TypeError:
                        # callback not supported - we'll invoke it ourselves
                        results = self.engine.run_all_modules(target)
                # If engine supports run_modules (list of modules)
                elif hasattr(self.engine, 'run_modules'):
                    enabled = [m for m, v in self.module_vars.items() if v.get()]
                    try:
                        results = self.engine.run_modules(enabled, target, callback=self._scan_callback)
                    except TypeError:
                        # try different arg order
                        try:
                            results = self.engine.run_modules(enabled, target)
                        except Exception:
                            # try (target, modules)
                            results = self.engine.run_modules(target, enabled)
                # If engine is a task registry (run_task / submit_task)
                elif hasattr(self.engine, 'run_task') or hasattr(self.engine, 'submit_task'):
                    enabled = [m for m, v in self.module_vars.items() if v.get()]
                    for m in enabled:
                        try:
                            if hasattr(self.engine, 'run_task'):
                                r = self.engine.run_task(m, target)
                                results[m] = {'status': 'success', 'result': r}
                            else:
                                fut = self.engine.submit_task(m, target)
                                r = fut.result()
                                results[m] = {'status': 'success', 'result': r}
                        except Exception as e:
                            results[m] = {'status': 'error', 'result': str(e)}
                else:
                    # As a last resort try engine.main() or engine.run()
                    if hasattr(self.engine, 'main'):
                        try:
                            self.engine.main()
                            results = {'status': 'success'}
                        except Exception as e:
                            results = {'status': 'error', 'error': str(e)}
                    elif hasattr(self.engine, 'run'):
                        try:
                            self.engine.run()
                            results = {'status': 'success'}
                        except Exception as e:
                            results = {'status': 'error', 'error': str(e)}
                    else:
                        results = {'error': 'No runnable engine API found'}
                
                # Normalize results to dict[module_name -> result_dict]
                results = self._normalize_results(results)
                
                # If engine didn't support callbacks, invoke them now
                for module_name, result in results.items():
                    try:
                        self._scan_callback(module_name, result)
                    except Exception:
                        pass  # callback is optional

            self.current_results = results
            self.root.after(0, self._scan_complete, results)
        except Exception as e:
            self.root.after(0, self._scan_error, str(e))

    def _run_wildcard_scan(self, target):
        """Run wildcard subdomain discovery with smart scanning"""
        # Normalize target
        if target.startswith('*.'):
            base_domain = target[2:]
        else:
            base_domain = target

        self.log(f"[*] Phase 1: Subdomain Discovery")
        self.log(f"[*] Base domain: {base_domain}")

        # Run subdomain discovery using wildcard module
        try:
            if hasattr(self.engine, 'run_module'):
                try:
                    subdomain_results = self.engine.run_module('subdomain_wildcard', target, callback=self._scan_callback)
                except TypeError:
                    subdomain_results = self.engine.run_module('subdomain_wildcard', target)
            elif hasattr(self.engine, 'run_modules'):
                res = self.engine.run_modules(['subdomain_wildcard'], target, callback=self._scan_callback)
                subdomain_results = res.get('subdomain_wildcard', {})
            else:
                subdomain_results = {'status': 'error', 'subdomains': []}
        except Exception as e:
            subdomain_results = {'status': 'error', 'subdomains': [], 'error': str(e)}

        if subdomain_results.get('status') != 'success':
            return subdomain_results

        discovered = subdomain_results.get('subdomains', [])
        self.log(f"[+] Discovered {len(discovered)} subdomains")

        if not discovered:
            self.log("[-] No subdomains found")
            return subdomain_results

        # Save subdomains immediately
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        subdomain_file = f"subdomains_{base_domain.replace('.', '_')}_{timestamp}.txt"
        discovery_file = f"discovery_{base_domain.replace('.', '_')}_{timestamp}.json"

        try:
            # Save simple subdomain list
            with open(subdomain_file, 'w') as f:
                f.write(f"# Subdomains for {base_domain}\n")
                f.write(f"# Discovered: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"# Total: {len(discovered)}\n\n")
                for sub in sorted(discovered):
                    f.write(f"{sub}\n")
            self.log(f"[+] Saved subdomains to: {subdomain_file}")

            # Save full discovery data
            discovery_data = {
                'timestamp': timestamp,
                'base_domain': base_domain,
                'target': target,
                'total_discovered': len(discovered),
                'subdomains': discovered,
                'discovery_methods': subdomain_results.get('methods', {}),
                'statistics': subdomain_results.get('statistics', {})
            }
            with open(discovery_file, 'w') as f:
                json.dump(discovery_data, f, indent=2)
            self.log(f"[+] Saved discovery data to: {discovery_file}")
        except Exception as e:
            self.log(f"[!] Warning: Could not save files: {e}")

        # Show sample
        sample_count = min(10, len(discovered))
        self.log(f"\n[*] Sample subdomains:")
        for sub in discovered[:sample_count]:
            self.log(sub)
        if len(discovered) > sample_count:
            self.log(f"    ... and {len(discovered) - sample_count} more")

        # Automatic prioritization
        self.log(f"\n[*] Prioritizing subdomains...")
        priorities = self._prioritize_subdomains(discovered)

        # Show priority breakdown
        self.log(f"\n[*] Priority Breakdown:")
        for level in ['critical', 'high', 'medium', 'low', 'other']:
            if level in priorities and priorities[level]['subdomains']:
                count = len(priorities[level]['subdomains'])
                self.log(f"    {level.upper()}: {count} targets")

        # Save priority lists automatically
        self.log(f"\n[*] Saving priority lists...")
        priority_files = self._save_priority_lists_auto(priorities, base_domain, timestamp)
        for fname in priority_files:
            self.log(f"[+] Saved: {fname}")

        # Smart scanning dialog - ask what to scan
        self.root.after(0, lambda: self._show_smart_scan_dialog(
            discovered, priorities, base_domain, subdomain_results
        ))

        # Return discovery results (no scanning yet)
        return {
            'wildcard_scan': True,
            'discovery_only': True,
            'base_domain': base_domain,
            'target': target,
            'total_discovered': len(discovered),
            'subdomain_discovery': subdomain_results,
            'priorities': priorities,
            'files_saved': {
                'subdomains': subdomain_file,
                'discovery': discovery_file,
                'priority_lists': priority_files
            }
        }

    # ---------------------- Added helper methods ----------------------
    def _normalize_results(self, results):
        """Normalize results into a dict[module_name -> result_dict] format.
        
        Handles various result formats from different engine versions.
        """
        if not results:
            return {}
        
        # If results is already a dict with module names as keys, check if values are dicts
        if isinstance(results, dict):
            normalized = {}
            for key, value in results.items():
                if isinstance(value, dict):
                    # Already in the right format
                    normalized[key] = value
                else:
                    # Wrap in a dict
                    normalized[key] = {'status': 'success', 'result': value}
            return normalized
        
        # If results is a list, convert to dict
        if isinstance(results, list):
            normalized = {}
            for i, item in enumerate(results):
                if isinstance(item, dict) and 'module' in item:
                    module_name = item['module']
                    normalized[module_name] = item
                else:
                    normalized[f'result_{i}'] = {'status': 'success', 'result': item}
            return normalized
        
        # Fallback: single result
        return {'result': {'status': 'success', 'result': results}}
    
    def stop_scan(self):
        """Stop the current scan if running"""
        if not self.is_scanning:
            return
        # Engine may support cancellation; try best-effort
        try:
            if hasattr(self.engine, 'stop'):
                self.engine.stop()
        except Exception:
            pass
        self.is_scanning = False
        try:
            self.progress_bar.stop()
        except Exception:
            pass
        self.scan_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.progress_var.set('Stopped')
        self.log('[!] Scan stopped by user')

    def prioritize_results(self):
        """Show a simple prioritization summary of current results"""
        if not self.current_results:
            messagebox.showinfo('Prioritize', 'No results available to prioritize')
            return
        # Try to grab subdomains if present
        subdomains = []
        if isinstance(self.current_results, dict):
            # Look for common keys
            for k in ('subdomains', 'hosts', 'targets'):
                if k in self.current_results:
                    subdomains = self.current_results.get(k, [])
                    break
        priorities = self._prioritize_subdomains(subdomains)
        summary = []
        for level in ['critical', 'high', 'medium', 'low', 'other']:
            cnt = len(priorities.get(level, {}).get('subdomains', []))
            summary.append(f"{level}: {cnt}")
        messagebox.showinfo('Prioritization Summary', '\n'.join(summary))

    def scan_from_list(self):
        """Prompt user for a file containing targets and run scans"""
        path = filedialog.askopenfilename(title='Select target list', filetypes=[('Text', '*.txt'), ('All', '*.*')])
        if not path:
            return
        try:
            with open(path, 'r') as fh:
                targets = [l.strip() for l in fh if l.strip()]
            self.log(f"[*] Loaded {len(targets)} targets from {path}")
            # Ask user whether to run sequentially
            if messagebox.askyesno('Run', f'Start scans for {len(targets)} targets?'):
                for t in targets:
                    self.target_entry.delete(0, tk.END)
                    self.target_entry.insert(0, t)
                    self.start_scan_all()
        except Exception as e:
            messagebox.showerror('Error', f'Failed to read file: {e}')

    def export_report(self):
        """Export the current results to a JSON file"""
        if not self.current_results:
            messagebox.showinfo('Export', 'No scan results to export')
            return
        path = filedialog.asksaveasfilename(title='Save report', defaultextension='.json', filetypes=[('JSON','*.json')])
        if not path:
            return
        try:
            with open(path, 'w') as fh:
                json.dump(self.current_results, fh, indent=2)
            messagebox.showinfo('Export', f'Report saved to {path}')
        except Exception as e:
            messagebox.showerror('Error', f'Failed to save report: {e}')

    def clear_results(self):
        """Clear console and result panes"""
        try:
            self.console.delete('1.0', tk.END)
        except Exception:
            pass
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        for item in self.vuln_tree.get_children():
            self.vuln_tree.delete(item)
        self.current_results = None
        self.log('[*] Results cleared')

    def show_about(self):
        """Show about dialog"""
        messagebox.showinfo('About RedHawk', 'RedHawk - Security Assessment Framework\nVersion: 1.0')

    def _scan_callback(self, module_name, result):
        """Receive per-module callbacks from the engine and update UI"""
        def _update():
            try:
                # Update console
                self.log(f"[callback] {module_name}: {result}")
                # Update tree
                summary = ''
                if isinstance(result, dict):
                    summary = result.get('summary') or result.get('result') or str(result)
                else:
                    summary = str(result)
                try:
                    exists = self.results_tree.exists(module_name)
                except Exception:
                    # older tkinter versions may not have exists()
                    exists = module_name in self.results_tree.get_children()
                if exists:
                    try:
                        self.results_tree.item(module_name, values=(summary,))
                    except Exception:
                        pass
                else:
                    try:
                        self.results_tree.insert('', 'end', iid=module_name, text=module_name, values=(summary,))
                    except Exception:
                        # fallback: insert without iid
                        self.results_tree.insert('', 'end', text=module_name, values=(summary,))
            except Exception:
                traceback.print_exc()
        try:
            self.root.after(0, _update)
        except Exception:
            _update()

    def _scan_complete(self, results):
        """Handle scan completion UI updates"""
        self.is_scanning = False
        try:
            self.progress_bar.stop()
        except Exception:
            pass
        self.scan_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.progress_var.set('Complete')
        self.log('[+] Scan complete')
        # Optionally save to DB if engine provides save
        try:
            if hasattr(self.engine, 'save_results'):
                # Attempt to save results via engine (best-effort)
                if isinstance(results, dict):
                    self.engine.save_results(results)
        except Exception:
            pass

    def _scan_error(self, error_message):
        """Handle scan errors"""
        self.is_scanning = False
        try:
            self.progress_bar.stop()
        except Exception:
            pass
        self.scan_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.progress_var.set('Error')
        self.log(f'[!] Scan error: {error_message}')
        messagebox.showerror('Scan Error', str(error_message))

    def _prioritize_subdomains(self, subdomains):
        """Very simple prioritization heuristics for subdomain lists"""
        priorities = {'critical': {'subdomains': []}, 'high': {'subdomains': []}, 'medium': {'subdomains': []}, 'low': {'subdomains': []}, 'other': {'subdomains': []}}
        try:
            for s in subdomains:
                sl = s.lower()
                if any(k in sl for k in ('admin', 'login', 'cpanel', 'secure')):
                    priorities['critical']['subdomains'].append(s)
                elif any(k in sl for k in ('www', 'api', 'portal')):
                    priorities['high']['subdomains'].append(s)
                elif any(k in sl for k in ('.dev', '.stage', '.test')):
                    priorities['low']['subdomains'].append(s)
                else:
                    priorities['medium']['subdomains'].append(s)
        except Exception:
            traceback.print_exc()
        return priorities

    def _save_priority_lists_auto(self, priorities, base_domain, timestamp):
        """Save lists of prioritized subdomains and return filenames"""
        files = []
        try:
            base_dir = os.getcwd()
            for level, data in priorities.items():
                fname = f"priority_{level}_{base_domain.replace('.', '_')}_{timestamp}.txt"
                path = os.path.join(base_dir, fname)
                with open(path, 'w') as fh:
                    fh.write(f"# {level} priorities for {base_domain}\n")
                    for s in data.get('subdomains', []):
                        fh.write(s + '\n')
                files.append(path)
        except Exception:
            traceback.print_exc()
        return files

    def _show_smart_scan_dialog(self, discovered, priorities, base_domain, subdomain_results):
        """Show a lightweight dialog to allow user to pick what to scan next"""
        try:
            # Show counts and ask to scan top priorities
            critical = priorities.get('critical', {}).get('subdomains', [])
            high = priorities.get('high', {}).get('subdomains', [])
            msg = f"Discovered {len(discovered)} subdomains. Critical: {len(critical)}, High: {len(high)}.\nStart scan for top critical targets?"
            if messagebox.askyesno('Smart Scan', msg):
                # Start scanning top critical targets sequentially
                for target in critical[:5]:
                    self.target_entry.delete(0, tk.END)
                    self.target_entry.insert(0, target)
                    self.start_scan_all()
        except Exception:
            traceback.print_exc()

    # ---------------------- Run / compatibility helpers ----------------------
    def run(self):
        """Run the GUI main loop (preferred entrypoint)"""
        try:
            self.root.mainloop()
        except Exception:
            # If Tkinter mainloop is not available, try calling main
            try:
                self.main()
            except Exception:
                raise

    def main(self):
        """Alias for run() to support different entrypoints"""
        return self.run()

    def mainloop(self):
        """Alias for run() to mimic tk.Tk"""
        return self.run()

    def __call__(self):
        return self.run()


# Prefer modern GUI when available; otherwise fall back to legacy GUI
if __name__ == "__main__":
    try:
        try:
            from gui.modern_interface import RedHawkModernGUI as GUIClass
        except Exception:
            from modern_interface import RedHawkModernGUI as GUIClass
    except Exception:
        GUIClass = RedHawkGUI

    app = GUIClass()
    # prefer run() as entrypoint, otherwise try main() or mainloop()
    if hasattr(app, 'run'):
        app.run()
    elif hasattr(app, 'main'):
        app.main()
    else:
        try:
            app.mainloop()
        except Exception:
            # last resort, call the object
            try:
                app()
            except Exception:
                raise
