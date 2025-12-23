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
            f.write(f"{sub}\n")
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
