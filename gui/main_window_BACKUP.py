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

# Ensure parent directory is in path
current_dir = Path(__file__).parent
project_root = current_dir.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

try:
    from core.engine import RedHawkEngine
except ImportError:
    # Fallback for direct execution
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from core.engine import RedHawkEngine

class RedHawkGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("RedHawk - Offensive Security Framework")
        self.root.geometry("1200x800")
        
        # Initialize engine
        self.engine = RedHawkEngine()
        
        # Scan state
        self.is_scanning = False
        self.current_results = None
        
        # Setup GUI
        self.setup_styles()
        self.create_widgets()
        
    def setup_styles(self):
        """Setup custom styles"""
        style = ttk.Style()
        style.theme_use('clam')
        
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
        modules = self.engine.get_available_modules()
        
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
        self.console.insert(tk.END, f"{message}\n")
        self.console.see(tk.END)
        self.root.update_idletasks()
    
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
        
        # Disable enabled modules in engine based on checkboxes
        for module, var in self.module_vars.items():
            if module in self.engine.config['modules']:
                self.engine.config['modules'][module]['enabled'] = var.get()
            # Skip modules not in config (like subdomain_wildcard)
        
        self.is_scanning = True
        self.scan_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.progress_bar.start()
        
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
                # Wildcard scan - discover subdomains first
                results = self._run_wildcard_scan(target)
            else:
                # Normal scan
                results = self.engine.run_all_modules(target, callback=self._scan_callback)
            
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
        subdomain_results = self.engine.run_module('subdomain_wildcard', target, callback=self._scan_callback)
        
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
            self.log(f"    • {sub}")
        if len(discovered) > sample_count:
            self.log(f"    ... and {len(discovered) - 10} more")
        
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
        for f in priority_files:
            self.log(f"[+] Saved: {f}")
        
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
    
    def _save_priority_lists_auto(self, priorities, base_domain, timestamp):
        """Automatically save priority lists"""
        # Collect all subdomains in priority order
        all_prioritized = []
        for level in ['critical', 'high', 'medium', 'low', 'other']:
            if level in priorities:
                all_prioritized.extend(priorities[level]['subdomains'])
        
        saved_files = []
        counts = [10, 25, 50]
        
        for count in counts:
            targets = all_prioritized[:count]
            if not targets:
                continue
            
            filename = f"top{count}_{base_domain.replace('.', '_')}_{timestamp}.txt"
            with open(filename, 'w') as f:
                f.write(f"# Top {count} Priority Targets for {base_domain}\n")
                f.write(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"# Total discovered: {len(all_prioritized)}\n\n")
                for target in targets:
                    f.write(f"{target}\n")
            saved_files.append(filename)
        
        return saved_files
    
    def _show_smart_scan_dialog(self, discovered, priorities, base_domain, subdomain_results):
        """Show smart scanning options dialog"""
        try:
            dialog = tk.Toplevel(self.root)
            dialog.title("Smart Scanning Options")
            dialog.geometry("750x650")
            
            # Make it modal
            dialog.transient(self.root)
            dialog.grab_set()
            
            main = ttk.Frame(dialog, padding=20)
            main.pack(fill=tk.BOTH, expand=True)
            
            # Title
            title = ttk.Label(main, text=f"Discovered {len(discovered)} subdomains for {base_domain}", 
                             font=('Arial', 14, 'bold'))
            title.pack(pady=(0, 10))
            
            # Info
            info_text = (
                f"✅ Subdomains saved to files\n"
                f"✅ Priority lists generated\n"
                f"✅ Ready for smart scanning\n\n"
                f"Scanning all {len(discovered)} would take {len(discovered) * 2}-{len(discovered) * 3} minutes.\n"
                f"Choose a smart scanning option below:"
            )
            info = ttk.Label(main, text=info_text, justify=tk.LEFT)
            info.pack(pady=(0, 20))
            
            # Priority summary
            summary_frame = ttk.LabelFrame(main, text="Priority Breakdown", padding=10)
            summary_frame.pack(fill=tk.X, pady=(0, 20))
            
            for level in ['critical', 'high', 'medium']:
                if level in priorities and priorities[level]['subdomains']:
                    count = len(priorities[level]['subdomains'])
                    sample = ', '.join(priorities[level]['subdomains'][:3])
                    if count > 3:
                        sample += f"... (+{count-3} more)"
                    
                    level_frame = ttk.Frame(summary_frame)
                    level_frame.pack(fill=tk.X, pady=2)
                    
                    ttk.Label(level_frame, text=f"{level.upper()}: {count}", 
                             font=('Arial', 10, 'bold')).pack(side=tk.LEFT)
                    ttk.Label(level_frame, text=f"  ({sample})", 
                             foreground='gray').pack(side=tk.LEFT)
            
            # Scanning options
            options_frame = ttk.LabelFrame(main, text="Scanning Options", padding=10)
            options_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
            
            scan_var = tk.StringVar(value="top10")
            
            options = [
                ("top10", f"Scan Top 10 Critical (30-60 min) ⭐⭐⭐⭐⭐ RECOMMENDED"),
                ("top25", f"Scan Top 25 Priority (2-3 hours)"),
                ("top50", f"Scan Top 50 Extended (5-8 hours)"),
                ("custom", f"Custom count (you choose)"),
                ("none", f"Skip scanning (just save discoveries)")
            ]
            
            for value, text in options:
                ttk.Radiobutton(options_frame, text=text, variable=scan_var, 
                               value=value).pack(anchor=tk.W, pady=5)
            
            # Buttons
            btn_frame = ttk.Frame(main)
            btn_frame.pack(pady=10)
            
            def proceed_scan():
                option = scan_var.get()
                dialog.destroy()
                
                if option == "none":
                    self.log("\n[*] Discovery complete. Files saved.")
                    self.log("[*] Use 'Scan from List' button to scan later.")
                    self._finish_discovery_only(subdomain_results, base_domain)
                elif option == "custom":
                    count_str = tk.simpledialog.askstring(
                        "Custom Count",
                        f"How many subdomains to scan? (1-{len(discovered)})",
                        parent=self.root
                    )
                    try:
                        count = int(count_str) if count_str else 10
                        count = min(max(1, count), len(discovered))
                        self._start_priority_scan(discovered[:count], base_domain, subdomain_results)
                    except:
                        self.log("[!] Invalid count, using top 10")
                        self._start_priority_scan(discovered[:10], base_domain, subdomain_results)
                else:
                    # Load from priority list file
                    count_map = {'top10': 10, 'top25': 25, 'top50': 50}
                    count = count_map.get(option, 10)
                    
                    # Get prioritized subdomains
                    all_prioritized = []
                    for level in ['critical', 'high', 'medium', 'low', 'other']:
                        if level in priorities:
                            all_prioritized.extend(priorities[level]['subdomains'])
                    
                    targets = all_prioritized[:count]
                    self._start_priority_scan(targets, base_domain, subdomain_results)
            
            # Buttons frame with better styling
            btn_frame = ttk.Frame(main)
            btn_frame.pack(pady=10, fill=tk.X)
            
            # Create buttons with consistent styling
            proceed_btn = ttk.Button(btn_frame, text="Proceed", command=proceed_scan, width=15)
            proceed_btn.pack(side=tk.LEFT, padx=5)
            
            cancel_btn = ttk.Button(btn_frame, text="Cancel", command=dialog.destroy, width=15)
            cancel_btn.pack(side=tk.LEFT, padx=5)
            
            # Make dialog modal and center it
            dialog.transient(self.root)
            dialog.grab_set()
            
            # Center dialog
            dialog.update_idletasks()
            x = (dialog.winfo_screenwidth() // 2) - (dialog.winfo_width() // 2)
            y = (dialog.winfo_screenheight() // 2) - (dialog.winfo_height() // 2)
            dialog.geometry(f"+{x}+{y}")
            
            # Focus on proceed button
            proceed_btn.focus_set()
            
            self.log("[*] Smart scan dialog displayed - choose your option")
            
        except Exception as e:
            self.log(f"[!] Error showing dialog: {e}")
            # Fallback - just scan top 10
            messagebox.showwarning(
                "Dialog Error",
                f"Could not show dialog.\n\nDefaulting to top 10 critical targets.\n\nError: {e}"
            )
            # Get top 10 from priorities
            all_prioritized = []
            for level in ['critical', 'high', 'medium', 'low', 'other']:
                if level in priorities:
                    all_prioritized.extend(priorities[level]['subdomains'])
            targets = all_prioritized[:10]
            self._start_priority_scan(targets, base_domain, subdomain_results)
    
    def _start_priority_scan(self, targets, base_domain, subdomain_results):
        """Start scanning prioritized targets"""
        self.log(f"\n[*] Phase 2: Scanning {len(targets)} priority targets")
        self.log(f"[*] Estimated time: {len(targets) * 2}-{len(targets) * 3} minutes")
        
        # Continue with scanning
        self.is_scanning = True
        self.scan_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        
        # Run scans in thread
        thread = threading.Thread(target=self._run_priority_scan, 
                                 args=(targets, base_domain, subdomain_results))
        thread.daemon = True
        thread.start()
    
    def _run_priority_scan(self, targets, base_domain, subdomain_results):
        """Run priority scan in background"""
        all_results = {
            'wildcard_scan': True,
            'base_domain': base_domain,
            'total_discovered': len(subdomain_results.get('subdomains', [])),
            'scanned_count': len(targets),
            'subdomain_discovery': subdomain_results,
            'individual_scans': {}
        }
        
        for i, subdomain in enumerate(targets, 1):
            if not self.is_scanning:
                break
            
            self.root.after(0, lambda s=subdomain, idx=i, total=len(targets): 
                          self.progress_var.set(f"Scanning {s} ({idx}/{total})"))
            self.log(f"\n[{i}/{len(targets)}] Scanning {subdomain}...")
            
            try:
                result = self.engine.run_all_modules(subdomain, callback=self._scan_callback)
                all_results['individual_scans'][subdomain] = result
                
                # Show summary
                vuln_count = 0
                for module_result in result.get('modules', {}).values():
                    if module_result.get('status') == 'success':
                        vuln_count += len(module_result.get('vulnerabilities', []))
                
                if vuln_count > 0:
                    self.log(f"[!] Found {vuln_count} issues")
                else:
                    self.log(f"[+] No critical issues")
            except Exception as e:
                self.log(f"[-] Error: {e}")
        
        # Save results
        try:
            output_path = self.engine.save_results(all_results)
            all_results['output_path'] = output_path
        except:
            pass
        
        self.root.after(0, self._scan_complete, all_results)
    
    def _finish_discovery_only(self, subdomain_results, base_domain):
        """Finish when user chooses not to scan"""
        results = {
            'wildcard_scan': True,
            'discovery_only': True,
            'base_domain': base_domain,
            'total_discovered': len(subdomain_results.get('subdomains', [])),
            'subdomain_discovery': subdomain_results
        }
        
        self.is_scanning = False
        self.scan_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.progress_bar.stop()
        self.progress_var.set("Discovery complete")
        
        self.current_results = results
        self.display_results(results)
    
    def _scan_callback(self, module_name, result):
        """Callback for each module completion"""
        self.log(f"[+] {module_name} scan completed")
    
    def _scan_complete(self, results):
        """Handle scan completion"""
        self.is_scanning = False
        self.scan_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.progress_bar.stop()
        self.progress_var.set("Scan complete")
        
        self.log(f"\n[+] Scan completed successfully")
        
        # Safely get output path if it exists
        if 'output_path' in results:
            self.log(f"[+] Results saved to: {results['output_path']}")
        elif 'results' in results and isinstance(results['results'], dict):
            # Check if any module has output_path
            for module_name, module_data in results['results'].items():
                if isinstance(module_data, dict) and 'output_path' in module_data:
                    self.log(f"[+] Results saved to: {module_data['output_path']}")
                    break
        
        # Store current results before displaying
        self.current_results = results
        self.display_results(results)
    
    def _scan_error(self, error):
        """Handle scan error"""
        self.is_scanning = False
        self.scan_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.progress_bar.stop()
        self.progress_var.set("Scan failed")
        
        self.log(f"\n[-] Error: {error}")
        messagebox.showerror("Scan Error", f"An error occurred:\n{error}")
    
    def stop_scan(self):
        """Stop current scan"""
        self.is_scanning = False
        self.log("\n[!] Scan stopped by user")
    
    def display_results(self, results):
        """Display scan results in tree view"""
        # Clear existing items
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        
        for item in self.vuln_tree.get_children():
            self.vuln_tree.delete(item)
        
        # Check scan type and display accordingly
        if results.get('wildcard_scan'):
            self._display_wildcard_results(results)
        elif results.get('batch_scan'):
            self._display_batch_results(results)
        else:
            self._display_normal_results(results)
        
        self.notebook.select(1)  # Switch to results tab
    
    def _display_batch_results(self, results):
        """Display batch scan results"""
        # Summary node
        summary_node = self.results_tree.insert('', tk.END, 
                                                text=f"BATCH SCAN: {results.get('total_targets', 0)} targets", 
                                                values=('',))
        
        # Process each target
        total_vulns = 0
        for target, target_results in results.get('results', {}).items():
            target_node = self.results_tree.insert('', tk.END, 
                                                   text=target, 
                                                   values=('',))
            
            # Count vulnerabilities for this target
            target_vuln_count = 0
            
            # Add module results
            for module_name, module_results in target_results.get('modules', {}).items():
                if module_results.get('status') != 'success':
                    continue
                
                vulns = module_results.get('vulnerabilities', [])
                target_vuln_count += len(vulns)
                
                if vulns:
                    module_node = self.results_tree.insert(target_node, tk.END,
                                                          text=module_name.upper(),
                                                          values=(f'{len(vulns)} issues',))
                    
                    # Add vulnerabilities to tree
                    for vuln in vulns:
                        # Add to results tree under module
                        self.results_tree.insert(module_node, tk.END,
                                               text=vuln.get('type', 'Issue'),
                                               values=(vuln.get('description', ''),))
                        
                        # Add to vulnerability summary
                        self.vuln_tree.insert('', tk.END, values=(
                            vuln.get('severity', 'unknown').upper(),
                            vuln.get('type', ''),
                            f"[{target}] {vuln.get('description', '')}"
                        ))
            
            total_vulns += target_vuln_count
            
            # Update target node with count
            self.results_tree.item(target_node, values=(f'{target_vuln_count} issues',))
        
        # Update summary
        self.results_tree.item(summary_node, values=(f'{total_vulns} total issues',))
        
        self.log(f"\n[*] Display complete: {len(results.get('results', {}))} targets, {total_vulns} total issues")
    
    def _display_wildcard_results(self, results):
        """Display wildcard scan results"""
        # Summary node
        summary_node = self.results_tree.insert('', tk.END, 
                                                text=f"WILDCARD SCAN: {results.get('base_domain', 'Unknown')}", 
                                                values=('',))
        
        self.results_tree.insert(summary_node, tk.END, 
                                text='Total Discovered', 
                                values=(results.get('total_discovered', 0),))
        self.results_tree.insert(summary_node, tk.END, 
                                text='Scanned', 
                                values=(results.get('scanned_count', 0),))
        
        # Subdomain discovery results
        discovery = results.get('subdomain_discovery', {})
        if discovery:
            disc_node = self.results_tree.insert('', tk.END, 
                                                 text='Subdomain Discovery', 
                                                 values=('',))
            self._add_module_results(disc_node, discovery)
        
        # Individual scan results
        individual = results.get('individual_scans', {})
        if individual:
            scans_node = self.results_tree.insert('', tk.END, 
                                                  text=f'Individual Scans ({len(individual)})', 
                                                  values=('',))
            
            for subdomain, scan_result in individual.items():
                sub_node = self.results_tree.insert(scans_node, tk.END, 
                                                    text=subdomain, 
                                                    values=('',))
                
                # Add vulnerabilities
                for module_name, module_results in scan_result.get('modules', {}).items():
                    if module_results.get('status') != 'success':
                        continue
                    
                    for vuln in module_results.get('vulnerabilities', []):
                        vuln['subdomain'] = subdomain
                        self.vuln_tree.insert('', tk.END, values=(
                            vuln.get('severity', 'unknown').upper(),
                            vuln.get('type', ''),
                            f"[{subdomain}] {vuln.get('description', '')}"
                        ))
                    
                    # Add module summary
                    vuln_count = len(module_results.get('vulnerabilities', []))
                    if vuln_count > 0:
                        self.results_tree.insert(sub_node, tk.END, 
                                                text=module_name.upper(), 
                                                values=(f'{vuln_count} issues',))
    
    def _display_normal_results(self, results):
        """Display normal scan results"""
        # Add results
        for module_name, module_results in results.get('modules', {}).items():
            if module_results.get('status') != 'success':
                continue
            
            module_node = self.results_tree.insert('', tk.END, text=module_name.upper(),
                                                   values=('',))
            
            # Add module-specific results
            self._add_module_results(module_node, module_results)
            
            # Add vulnerabilities
            for vuln in module_results.get('vulnerabilities', []):
                self.vuln_tree.insert('', tk.END, values=(
                    vuln.get('severity', 'unknown').upper(),
                    vuln.get('type', ''),
                    vuln.get('description', '')
                ))
    
    def _add_module_results(self, parent, results):
        """Add module-specific results to tree"""
        for key, value in results.items():
            if key in ['status', 'error', 'vulnerabilities', 'target']:
                continue
            
            if isinstance(value, dict):
                node = self.results_tree.insert(parent, tk.END, text=key, values=('',))
                self._add_module_results(node, value)
            elif isinstance(value, list) and value:
                node = self.results_tree.insert(parent, tk.END, text=key, 
                                               values=(f'{len(value)} items',))
                for item in value:
                    if isinstance(item, dict):
                        item_str = ', '.join(f"{k}: {v}" for k, v in item.items())
                        self.results_tree.insert(node, tk.END, text='•', values=(item_str,))
                    else:
                        self.results_tree.insert(node, tk.END, text='•', values=(str(item),))
            else:
                self.results_tree.insert(parent, tk.END, text=key, values=(str(value),))
    
    def export_report(self):
        """Export results to HTML report"""
        if not self.current_results:
            messagebox.showwarning("Warning", "No results to export")
            return
        
        # Check if this is a discovery-only scan
        if self.current_results.get('discovery_only'):
            messagebox.showinfo(
                "Discovery Only",
                "This was a discovery-only scan (no vulnerabilities scanned).\n\n"
                "To export a full report:\n"
                "1. Use 'Scan from List' to scan some targets\n"
                "2. Then export the report\n\n"
                "Your discovery files are already saved:\n"
                "- subdomains_*.txt\n"
                "- discovery_*.json\n"
                "- top10/25/50_*.txt"
            )
            return
        
        # Check if output_path exists
        if 'output_path' not in self.current_results:
            # Try to find discovery files as alternative
            discovery_files = list(Path('.').glob('discovery_*.json'))
            if discovery_files:
                latest = max(discovery_files, key=lambda p: p.stat().st_mtime)
                messagebox.showinfo(
                    "No Report Data",
                    f"No report data available for export.\n\n"
                    f"Discovery file available: {latest.name}\n\n"
                    f"To get a report:\n"
                    f"1. Click 'Scan from List'\n"
                    f"2. Select a target list (e.g., top10_*.txt)\n"
                    f"3. Complete the scan\n"
                    f"4. Then export the report"
                )
            else:
                messagebox.showwarning(
                    "No Results",
                    "No scan results available for export.\n\n"
                    "Please run a scan first."
                )
            return
        
        filepath = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML files", "*.html"), ("All files", "*.*")]
        )
        
        if filepath:
            try:
                self.engine.generate_report(self.current_results['output_path'], 'html')
                messagebox.showinfo("Success", f"Report exported to:\n{filepath}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export report:\n{e}")
    
    def clear_results(self):
        """Clear all results"""
        self.console.delete(1.0, tk.END)
        
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        
        for item in self.vuln_tree.get_children():
            self.vuln_tree.delete(item)
        
        self.current_results = None
    
    def show_about(self):
        """Show about dialog"""
        about_text = """
RedHawk - Offensive Security Framework v1.0

A lightweight, modular framework for security assessments
and OSINT reconnaissance.

Features:
• DNS Enumeration & Analysis
• Subdomain Discovery
• Port Scanning
• Email Security Assessment
• SSL/TLS Analysis
• And more...

Developed for ethical security testing only.
        """
        messagebox.showinfo("About RedHawk", about_text)
    
    def prioritize_results(self):
        """Prioritize wildcard scan results"""
        subdomains = []
        source = None
        
        # Method 1: Check if we just did a discovery (current_results)
        if hasattr(self, 'current_results') and self.current_results:
            if self.current_results.get('wildcard_scan'):
                if 'subdomain_discovery' in self.current_results:
                    subdomains = self.current_results['subdomain_discovery'].get('subdomains', [])
                    source = "current scan"
                elif 'subdomains' in self.current_results:
                    subdomains = self.current_results.get('subdomains', [])
                    source = "current scan"
        
        # Method 2: Look for discovery JSON files in current directory
        if not subdomains:
            discovery_files = list(Path('.').glob('discovery_*.json'))
            if discovery_files:
                latest_discovery = max(discovery_files, key=lambda p: p.stat().st_mtime)
                try:
                    with open(latest_discovery) as f:
                        data = json.load(f)
                    subdomains = data.get('subdomains', [])
                    source = f"discovery file: {latest_discovery.name}"
                except:
                    pass
        
        # Method 3: Look for subdomain TXT files in current directory
        if not subdomains:
            subdomain_files = list(Path('.').glob('subdomains_*.txt'))
            if subdomain_files:
                latest_subdomain_file = max(subdomain_files, key=lambda p: p.stat().st_mtime)
                try:
                    with open(latest_subdomain_file) as f:
                        subdomains = [line.strip() for line in f 
                                    if line.strip() and not line.startswith('#')]
                    source = f"subdomain file: {latest_subdomain_file.name}"
                except:
                    pass
        
        # Method 4: Look for wildcard reports in reports directory (old method)
        if not subdomains:
            reports_dir = Path('reports')
            if reports_dir.exists():
                wildcard_reports = list(reports_dir.glob('wildcard_*.json'))
                if wildcard_reports:
                    latest = max(wildcard_reports, key=lambda p: p.stat().st_mtime)
                    try:
                        with open(latest) as f:
                            results = json.load(f)
                        
                        if 'subdomain_discovery' in results:
                            subdomains = results['subdomain_discovery'].get('subdomains', [])
                        elif 'subdomains' in results:
                            subdomains = results['subdomains']
                        source = f"report: {latest.name}"
                    except:
                        pass
        
        # If still no subdomains found
        if not subdomains:
            messagebox.showinfo(
                "No Subdomains Found", 
                "No subdomain data found.\n\n"
                "Please:\n"
                "1. Run a wildcard scan first, OR\n"
                "2. Place a discovery_*.json or subdomains_*.txt file in this directory"
            )
            return
        
        self.log(f"[*] Prioritizing {len(subdomains)} subdomains from {source}")
        
        # Prioritize
        priorities = self._prioritize_subdomains(subdomains)
        
        # Show dialog with options
        self._show_priority_dialog(priorities)
    
    def _prioritize_subdomains(self, subdomains):
        """Categorize subdomains by priority"""
        priorities = {
            'critical': {'keywords': [
                'parliament', 'presidency', 'cabinet', 'pm', 'president',
                'mfa', 'foreign', 'defense', 'military', 'army', 'navy', 'airforce',
                'nsa', 'nis', 'security', 'intelligence'
            ], 'subdomains': []},
            'high': {'keywords': [
                'finance', 'treasury', 'mofep', 'revenue', 'tax', 'gra',
                'police', 'immigration', 'customs', 'fire', 'emergency',
                'health', 'education', 'justice', 'interior',
                'portal', 'admin', 'api', 'webmail', 'mail', 'smtp'
            ], 'subdomains': []},
            'medium': {'keywords': [
                'energy', 'water', 'transport', 'roads', 'housing',
                'agriculture', 'trade', 'tourism', 'culture', 'sports',
                'labor', 'employment', 'social', 'welfare',
                'www', 'web', 'site', 'online'
            ], 'subdomains': []},
        }
        
        # Categorize
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
        
        priorities['other'] = {'subdomains': [s for s in subdomains if s not in categorized]}
        
        return priorities
    
    def _show_priority_dialog(self, priorities):
        """Show dialog with prioritized results"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Prioritized Targets")
        dialog.geometry("800x600")
        
        # Main frame
        main = ttk.Frame(dialog, padding=10)
        main.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(main, text="Prioritized Subdomain Targets", 
                 font=('Arial', 14, 'bold')).pack(pady=10)
        
        # Notebook for categories
        notebook = ttk.Notebook(main)
        notebook.pack(fill=tk.BOTH, expand=True, pady=10)
        
        priority_order = ['critical', 'high', 'medium', 'other']
        for level in priority_order:
            if level not in priorities or not priorities[level]['subdomains']:
                continue
            
            frame = ttk.Frame(notebook)
            notebook.add(frame, text=f"{level.upper()} ({len(priorities[level]['subdomains'])})")
            
            # Scrolled text
            text = scrolledtext.ScrolledText(frame, wrap=tk.WORD, height=20)
            text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            
            for i, sub in enumerate(priorities[level]['subdomains'], 1):
                text.insert(tk.END, f"{i:3d}. {sub}\n")
            
            text.config(state=tk.DISABLED)
        
        # Buttons
        btn_frame = ttk.Frame(main)
        btn_frame.pack(pady=10)
        
        def save_top10():
            self._save_target_list(priorities, 10, 'top10_critical.txt')
        
        def save_top25():
            self._save_target_list(priorities, 25, 'top25_priority.txt')
        
        def save_top50():
            self._save_target_list(priorities, 50, 'top50_targets.txt')
        
        ttk.Button(btn_frame, text="Save Top 10 Critical", 
                  command=save_top10).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Save Top 25 Priority", 
                  command=save_top25).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Save Top 50 Targets", 
                  command=save_top50).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Close", 
                  command=dialog.destroy).pack(side=tk.LEFT, padx=5)
    
    def _save_target_list(self, priorities, count, filename):
        """Save prioritized target list to file"""
        targets = []
        for level in ['critical', 'high', 'medium', 'other']:
            if level in priorities:
                targets.extend(priorities[level]['subdomains'])
            if len(targets) >= count:
                break
        
        targets = targets[:count]
        
        if not targets:
            messagebox.showinfo("Info", "No targets to save")
            return
        
        try:
            with open(filename, 'w') as f:
                for target in targets:
                    f.write(f"{target}\n")
            
            messagebox.showinfo("Success", 
                              f"Saved {len(targets)} targets to:\n{filename}\n\n"
                              f"Use 'Scan from List' button to scan them.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save list:\n{e}")
    
    def scan_from_list(self):
        """Scan targets from a file list"""
        # Check if there are target list files in current directory
        current_dir = Path('.')
        target_files = list(current_dir.glob('top*_*.txt'))
        
        if target_files:
            self.log(f"[*] Found {len(target_files)} target list files in current directory")
        
        # File dialog (starts in current directory)
        filename = filedialog.askopenfilename(
            title="Select Target List",
            initialdir=str(current_dir.resolve()),
            filetypes=[
                ("Target lists", "top*.txt"),
                ("Text files", "*.txt"), 
                ("All files", "*.*")
            ]
        )
        
        if not filename:
            return
        
        try:
            # Load targets
            with open(filename) as f:
                targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            
            if not targets:
                messagebox.showinfo("Info", "No targets found in file")
                return
            
            self.log(f"[*] Loaded {len(targets)} targets from: {Path(filename).name}")
            
            # Confirm
            response = messagebox.askyesno(
                "Confirm Scan",
                f"Found {len(targets)} targets in file.\n\n"
                f"Scan all with selected modules?\n"
                f"Estimated time: {len(targets) * 2}-{len(targets) * 3} minutes",
                parent=self.root
            )
            
            if not response:
                return
            
            # Start batch scan
            self._start_batch_scan(targets)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load target list:\n{e}")
    
    def _start_batch_scan(self, targets):
        """Start batch scanning of multiple targets"""
        self.is_scanning = True
        self.scan_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.progress_bar.start()
        
        self.log(f"\n[*] Starting batch scan of {len(targets)} targets")
        
        # Run in thread
        thread = threading.Thread(target=self._run_batch_scan, args=(targets,))
        thread.daemon = True
        thread.start()
    
    def _run_batch_scan(self, targets):
        """Run batch scan in background"""
        all_results = {
            'batch_scan': True,
            'total_targets': len(targets),
            'results': {}
        }
        
        for i, target in enumerate(targets, 1):
            if not self.is_scanning:
                break
            
            self.root.after(0, lambda t=target, idx=i, total=len(targets): 
                          self.progress_var.set(f"Scanning {t} ({idx}/{total})"))
            self.log(f"\n[{i}/{len(targets)}] Scanning {target}...")
            
            try:
                result = self.engine.run_all_modules(target, callback=self._scan_callback)
                all_results['results'][target] = result
                
                # Show summary
                vuln_count = 0
                for module_result in result.get('modules', {}).values():
                    if module_result.get('status') == 'success':
                        vuln_count += len(module_result.get('vulnerabilities', []))
                
                self.log(f"[+] {target}: {vuln_count} issues found")
                
            except Exception as e:
                self.log(f"[-] {target}: Error - {e}")
        
        # Save batch results
        try:
            output_path = self.engine.save_results(all_results)
            all_results['output_path'] = output_path
        except:
            pass
        
        self.root.after(0, self._scan_complete, all_results)
    
    def run(self):
        """Start the GUI"""
        self.root.mainloop()


if __name__ == "__main__":
    app = RedHawkGUI()
    app.run()