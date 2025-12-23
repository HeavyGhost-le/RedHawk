"""
RedHawk Modern GUI
Material Design with Dark/Light theme support
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import json
from typing import Dict, List, Optional
from datetime import datetime
import threading


class ModernTheme:
    """Material Design color schemes"""
    
    DARK = {
        'bg': '#1e1e1e',
        'fg': '#e0e0e0',
        'bg_secondary': '#2d2d2d',
        'bg_tertiary': '#383838',
        'accent': '#007acc',
        'accent_hover': '#005a9e',
        'success': '#4caf50',
        'warning': '#ff9800',
        'error': '#f44336',
        'info': '#2196f3',
        'border': '#404040',
        'selected': '#094771',
        'text_primary': '#ffffff',
        'text_secondary': '#b0b0b0',
        'critical': '#e74c3c',
        'high': '#e67e22',
        'medium': '#f39c12',
        'low': '#3498db'
    }
    
    LIGHT = {
        'bg': '#ffffff',
        'fg': '#212121',
        'bg_secondary': '#f5f5f5',
        'bg_tertiary': '#eeeeee',
        'accent': '#2196f3',
        'accent_hover': '#1976d2',
        'success': '#4caf50',
        'warning': '#ff9800',
        'error': '#f44336',
        'info': '#2196f3',
        'border': '#e0e0e0',
        'selected': '#bbdefb',
        'text_primary': '#212121',
        'text_secondary': '#757575',
        'critical': '#d32f2f',
        'high': '#f57c00',
        'medium': '#fbc02d',
        'low': '#1976d2'
    }


class ModernButton(tk.Canvas):
    """Custom modern button with hover effects"""
    
    def __init__(self, parent, text: str, command=None, 
                 width: int = 120, height: int = 36, theme: Dict = None):
        super().__init__(parent, width=width, height=height, 
                        highlightthickness=0, cursor='hand2')
        
        self.theme = theme or ModernTheme.DARK
        self.text = text
        self.command = command
        self.width = width
        self.height = height
        
        self.configure(bg=self.theme['bg'])
        self._draw_button()
        self._bind_events()
    
    def _draw_button(self, hover: bool = False):
        """Draw button with rounded corners"""
        self.delete('all')
        
        color = self.theme['accent_hover'] if hover else self.theme['accent']
        
        # Rounded rectangle
        radius = 4
        self.create_rectangle(0, 0, self.width, self.height, 
                            fill=color, outline='', tags='button')
        
        # Text
        self.create_text(self.width/2, self.height/2, 
                        text=self.text, fill=self.theme['text_primary'],
                        font=('Segoe UI', 10, 'bold'), tags='text')
    
    def _bind_events(self):
        """Bind hover and click events"""
        self.bind('<Enter>', lambda e: self._draw_button(hover=True))
        self.bind('<Leave>', lambda e: self._draw_button(hover=False))
        self.bind('<Button-1>', lambda e: self.command() if self.command else None)


class ModernCard(tk.Frame):
    """Material Design card widget"""
    
    def __init__(self, parent, title: str = '', theme: Dict = None):
        self.theme = theme or ModernTheme.DARK
        super().__init__(parent, bg=self.theme['bg_secondary'], 
                        relief=tk.FLAT, bd=1)
        
        if title:
            title_label = tk.Label(self, text=title, 
                                  bg=self.theme['bg_secondary'],
                                  fg=self.theme['text_primary'],
                                  font=('Segoe UI', 11, 'bold'))
            title_label.pack(anchor='w', padx=15, pady=(15, 10))
        
        # Content frame
        self.content = tk.Frame(self, bg=self.theme['bg_secondary'])
        self.content.pack(fill=tk.BOTH, expand=True, padx=15, pady=(0, 15))


class ModernProgressBar(tk.Canvas):
    """Animated progress bar"""
    
    def __init__(self, parent, width: int = 300, height: int = 4, theme: Dict = None):
        self.theme = theme or ModernTheme.DARK
        super().__init__(parent, width=width, height=height, 
                        bg=self.theme['bg_tertiary'], highlightthickness=0)
        
        self.width = width
        self.height = height
        self.progress = 0
        self._animation_id = None
    
    def set_progress(self, value: float):
        """Set progress (0-100)"""
        self.progress = max(0, min(100, value))
        self._draw()
    
    def _draw(self):
        """Draw progress bar"""
        self.delete('all')
        
        # Background
        self.create_rectangle(0, 0, self.width, self.height, 
                            fill=self.theme['bg_tertiary'], outline='')
        
        # Progress
        progress_width = (self.progress / 100) * self.width
        self.create_rectangle(0, 0, progress_width, self.height,
                            fill=self.theme['accent'], outline='')
    
    def animate_indeterminate(self):
        """Animate indeterminate progress"""
        if self._animation_id:
            self.after_cancel(self._animation_id)
        
        def animate(position=0):
            self.delete('all')
            
            # Background
            self.create_rectangle(0, 0, self.width, self.height,
                                fill=self.theme['bg_tertiary'], outline='')
            
            # Moving bar
            bar_width = self.width // 3
            x = (position % (self.width + bar_width)) - bar_width
            self.create_rectangle(x, 0, x + bar_width, self.height,
                                fill=self.theme['accent'], outline='')
            
            self._animation_id = self.after(20, lambda: animate(position + 5))
        
        animate()
    
    def stop_animation(self):
        """Stop animation"""
        if self._animation_id:
            self.after_cancel(self._animation_id)
            self._animation_id = None
        self._draw()


class ModernTreeView(ttk.Treeview):
    """Enhanced treeview with modern styling"""
    
    def __init__(self, parent, theme: Dict = None, **kwargs):
        self.theme = theme or ModernTheme.DARK
        super().__init__(parent, **kwargs)
        
        # Configure style
        style = ttk.Style()
        style.theme_use('clam')
        
        # Treeview styling
        style.configure('Modern.Treeview',
                       background=self.theme['bg_secondary'],
                       foreground=self.theme['text_primary'],
                       fieldbackground=self.theme['bg_secondary'],
                       borderwidth=0)
        
        style.configure('Modern.Treeview.Heading',
                       background=self.theme['bg_tertiary'],
                       foreground=self.theme['text_primary'],
                       borderwidth=1,
                       relief='flat')
        
        style.map('Modern.Treeview',
                 background=[('selected', self.theme['selected'])])
        
        self.configure(style='Modern.Treeview')


class RedHawkModernGUI:
    """
    Modern RedHawk GUI with Material Design
    """
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("RedHawk - Security Assessment Framework")
        self.root.geometry("1400x900")
        
        # Theme
        self.current_theme = ModernTheme.DARK
        self.is_dark_mode = True
        
        # Variables
        self.target_var = tk.StringVar()
        self.wildcard_var = tk.BooleanVar()
        self.scanning = False
        
        self._setup_ui()
        self._apply_theme()
    
    def _setup_ui(self):
        """Setup main UI"""
        # Configure root
        self.root.configure(bg=self.current_theme['bg'])
        
        # Main container
        main_container = tk.Frame(self.root, bg=self.current_theme['bg'])
        main_container.pack(fill=tk.BOTH, expand=True)
        
        # Header
        self._create_header(main_container)
        
        # Content area
        content = tk.Frame(main_container, bg=self.current_theme['bg'])
        content.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # Left panel (Controls)
        left_panel = tk.Frame(content, bg=self.current_theme['bg'], width=400)
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, padx=(0, 10))
        left_panel.pack_propagate(False)
        
        self._create_controls(left_panel)
        self._create_module_selector(left_panel)
        
        # Right panel (Results)
        right_panel = tk.Frame(content, bg=self.current_theme['bg'])
        right_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        self._create_results_area(right_panel)
        
        # Status bar
        self._create_status_bar(main_container)
    
    def _create_header(self, parent):
        """Create header with title and theme toggle"""
        header = tk.Frame(parent, bg=self.current_theme['bg_secondary'], height=70)
        header.pack(fill=tk.X, pady=(0, 10))
        header.pack_propagate(False)
        
        # Logo/Title
        title_frame = tk.Frame(header, bg=self.current_theme['bg_secondary'])
        title_frame.pack(side=tk.LEFT, padx=20)
        
        title = tk.Label(title_frame, text="🦅 RedHawk", 
                        bg=self.current_theme['bg_secondary'],
                        fg=self.current_theme['accent'],
                        font=('Segoe UI', 24, 'bold'))
        title.pack(anchor='w')
        
        subtitle = tk.Label(title_frame, text="Security Assessment Framework",
                           bg=self.current_theme['bg_secondary'],
                           fg=self.current_theme['text_secondary'],
                           font=('Segoe UI', 10))
        subtitle.pack(anchor='w')
        
        # Right controls
        controls_frame = tk.Frame(header, bg=self.current_theme['bg_secondary'])
        controls_frame.pack(side=tk.RIGHT, padx=20)
        
        # Theme toggle
        theme_btn = tk.Button(controls_frame, text="🌙" if self.is_dark_mode else "☀️",
                             command=self.toggle_theme,
                             bg=self.current_theme['bg_tertiary'],
                             fg=self.current_theme['text_primary'],
                             font=('Segoe UI', 16),
                             relief=tk.FLAT, cursor='hand2',
                             width=3)
        theme_btn.pack(side=tk.RIGHT, padx=5)
    
    def _create_controls(self, parent):
        """Create control panel"""
        card = ModernCard(parent, title="Target Configuration", theme=self.current_theme)
        card.pack(fill=tk.X, pady=(0, 10))
        
        # Target input
        tk.Label(card.content, text="Target Domain/IP:",
                bg=self.current_theme['bg_secondary'],
                fg=self.current_theme['text_primary'],
                font=('Segoe UI', 10)).pack(anchor='w', pady=(5, 2))
        
        target_entry = tk.Entry(card.content, textvariable=self.target_var,
                               bg=self.current_theme['bg_tertiary'],
                               fg=self.current_theme['text_primary'],
                               font=('Segoe UI', 10),
                               relief=tk.FLAT,
                               insertbackground=self.current_theme['text_primary'])
        target_entry.pack(fill=tk.X, pady=(0, 10), ipady=8)
        
        # Wildcard option
        wildcard_check = tk.Checkbutton(card.content, text="Enable Wildcard Subdomain Discovery",
                                       variable=self.wildcard_var,
                                       bg=self.current_theme['bg_secondary'],
                                       fg=self.current_theme['text_primary'],
                                       selectcolor=self.current_theme['bg_tertiary'],
                                       activebackground=self.current_theme['bg_secondary'],
                                       activeforeground=self.current_theme['text_primary'],
                                       font=('Segoe UI', 9))
        wildcard_check.pack(anchor='w', pady=(0, 15))
        
        # Action buttons
        btn_frame = tk.Frame(card.content, bg=self.current_theme['bg_secondary'])
        btn_frame.pack(fill=tk.X)
        
        scan_btn = ModernButton(btn_frame, "Start Scan", 
                               command=self.start_scan,
                               width=180, height=40,
                               theme=self.current_theme)
        scan_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        stop_btn = ModernButton(btn_frame, "Stop",
                               command=self.stop_scan,
                               width=90, height=40,
                               theme=self.current_theme)
        stop_btn.pack(side=tk.LEFT)
    
    def _create_module_selector(self, parent):
        """Create module selection panel"""
        card = ModernCard(parent, title="Scan Modules", theme=self.current_theme)
        card.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        modules = [
            ("DNS Records", True),
            ("Subdomain Discovery", True),
            ("SSL/TLS Analysis", True),
            ("Security Headers", True),
            ("Email Intelligence", False),
            ("Port Scanning", False),
            ("WAF Detection", True),
            ("API Scanner", False),
            ("Cloud Security", False),
        ]
        
        for module, default in modules:
            var = tk.BooleanVar(value=default)
            cb = tk.Checkbutton(card.content, text=module,
                               variable=var,
                               bg=self.current_theme['bg_secondary'],
                               fg=self.current_theme['text_primary'],
                               selectcolor=self.current_theme['bg_tertiary'],
                               activebackground=self.current_theme['bg_secondary'],
                               font=('Segoe UI', 9))
            cb.pack(anchor='w', pady=2)
    
    def _create_results_area(self, parent):
        """Create results display area"""
        # Notebook for tabs
        style = ttk.Style()
        style.configure('Modern.TNotebook',
                       background=self.current_theme['bg'],
                       borderwidth=0)
        style.configure('Modern.TNotebook.Tab',
                       background=self.current_theme['bg_secondary'],
                       foreground=self.current_theme['text_primary'],
                       padding=[20, 10])
        style.map('Modern.TNotebook.Tab',
                 background=[('selected', self.current_theme['bg_tertiary'])])
        
        notebook = ttk.Notebook(parent, style='Modern.TNotebook')
        notebook.pack(fill=tk.BOTH, expand=True)
        
        # Console tab
        console_frame = tk.Frame(notebook, bg=self.current_theme['bg_secondary'])
        self.console_text = scrolledtext.ScrolledText(console_frame,
                                                      bg=self.current_theme['bg_tertiary'],
                                                      fg=self.current_theme['text_primary'],
                                                      font=('Consolas', 9),
                                                      relief=tk.FLAT)
        self.console_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        notebook.add(console_frame, text='Console')
        
        # Results tab
        results_frame = tk.Frame(notebook, bg=self.current_theme['bg_secondary'])
        self.results_tree = ModernTreeView(results_frame, 
                                          columns=('Value', 'Status'),
                                          theme=self.current_theme)
        self.results_tree.heading('#0', text='Finding')
        self.results_tree.heading('Value', text='Value')
        self.results_tree.heading('Status', text='Status')
        self.results_tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        notebook.add(results_frame, text='Results')
        
        # Vulnerabilities tab
        vuln_frame = tk.Frame(notebook, bg=self.current_theme['bg_secondary'])
        self.vuln_tree = ModernTreeView(vuln_frame,
                                       columns=('Severity', 'Description'),
                                       theme=self.current_theme)
        self.vuln_tree.heading('#0', text='Type')
        self.vuln_tree.heading('Severity', text='Severity')
        self.vuln_tree.heading('Description', text='Description')
        self.vuln_tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        notebook.add(vuln_frame, text='Vulnerabilities')
    
    def _create_status_bar(self, parent):
        """Create status bar"""
        status_frame = tk.Frame(parent, bg=self.current_theme['bg_tertiary'], height=30)
        status_frame.pack(fill=tk.X)
        status_frame.pack_propagate(False)
        
        self.status_label = tk.Label(status_frame, text="Ready",
                                     bg=self.current_theme['bg_tertiary'],
                                     fg=self.current_theme['text_secondary'],
                                     font=('Segoe UI', 9))
        self.status_label.pack(side=tk.LEFT, padx=10)
        
        # Progress bar
        self.progress_bar = ModernProgressBar(status_frame, width=200, 
                                             theme=self.current_theme)
        self.progress_bar.pack(side=tk.RIGHT, padx=10, pady=10)
    
    def _apply_theme(self):
        """Apply current theme to all widgets"""
        # This would recursively update all widgets
        pass
    
    def toggle_theme(self):
        """Toggle between dark and light themes"""
        self.is_dark_mode = not self.is_dark_mode
        self.current_theme = ModernTheme.DARK if self.is_dark_mode else ModernTheme.LIGHT
        
        # Rebuild UI with new theme
        for widget in self.root.winfo_children():
            widget.destroy()
        self._setup_ui()
    
    def start_scan(self):
        """Start scanning process"""
        target = self.target_var.get()
        if not target:
            messagebox.showwarning("Input Required", "Please enter a target domain or IP")
            return
        
        self.scanning = True
        self.log_console(f"[*] Starting scan for {target}")
        self.status_label.config(text=f"Scanning {target}...")
        self.progress_bar.animate_indeterminate()
        
        # Run scan in thread
        thread = threading.Thread(target=self._run_scan, args=(target,))
        thread.daemon = True
        thread.start()
    
    def stop_scan(self):
        """Stop scanning process"""
        self.scanning = False
        self.log_console("[!] Scan stopped by user")
        self.status_label.config(text="Stopped")
        self.progress_bar.stop_animation()
    
    def _run_scan(self, target: str):
        """Run scan (placeholder)"""
        import time
        
        # Simulate scanning
        for i in range(100):
            if not self.scanning:
                break
            
            time.sleep(0.05)
            progress = (i + 1)
            
            self.root.after(0, lambda p=progress: self.progress_bar.set_progress(p))
            
            if i % 10 == 0:
                self.root.after(0, lambda: self.log_console(f"[+] Progress: {progress}%"))
        
        self.root.after(0, lambda: self.log_console("[✓] Scan complete!"))
        self.root.after(0, lambda: self.status_label.config(text="Complete"))
    
    def log_console(self, message: str):
        """Log message to console"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.console_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.console_text.see(tk.END)
    
    def run(self):
        """Start GUI main loop"""
        self.root.mainloop()


if __name__ == '__main__':
    app = RedHawkModernGUI()
    app.run()
