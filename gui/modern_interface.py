"""
RedHawk Modern GUI
Material Design with Dark/Light theme support

This modern_interface implementation integrates with core.engine.RedHawkEngine
(with a safe lazy import/fallback) and uses it to run scans. Module callbacks
from the engine are printed to the console and also summarized briefly in the
results tree.
"""

import sys
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import json
from typing import Dict, List, Optional, Any
from datetime import datetime
import threading
from pathlib import Path
import traceback

# Lazy import of engine; try package import first
try:
    from core.engine import RedHawkEngine
except Exception:
    # Fallback for direct execution
    sys.path.insert(0, str(Path(__file__).parent.parent))
    try:
        from core.engine import RedHawkEngine
    except Exception:
        RedHawkEngine = None


# Simple theme container
class ModernTheme:
    DARK = {
        'bg': '#1e1e1e', 'fg': '#e0e0e0', 'accent': '#007acc', 'border': '#404040'
    }
    LIGHT = {
        'bg': '#ffffff', 'fg': '#212121', 'accent': '#2196f3', 'border': '#e0e0e0'
    }


class ModernInterface(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title('RedHawk - Modern GUI')
        self.geometry('900x650')
        self.protocol('WM_DELETE_WINDOW', self._on_close)

        # theme
        self.theme = ModernTheme.DARK
        self.configure(bg=self.theme['bg'])

        self._create_widgets()
        self.engine = None
        self._scan_thread: Optional[threading.Thread] = None

    def _create_widgets(self):
        # Top frame for controls
        top = tk.Frame(self, bg=self.theme['bg'])
        top.pack(side=tk.TOP, fill=tk.X, padx=10, pady=(10, 5))

        lbl = tk.Label(top, text='Modules (select one or more):', bg=self.theme['bg'], fg=self.theme['fg'])
        lbl.pack(side=tk.LEFT)

        self.module_list = tk.Listbox(top, selectmode=tk.EXTENDED, height=4)
        self.module_list.pack(side=tk.LEFT, padx=(8, 12))

        # Fill with placeholder modules; in a real install you might enumerate available modules
        for m in ['whois', 'subdomains', 'http', 'dns', 'vulnscan']:
            self.module_list.insert(tk.END, m)

        ttk.Button(top, text='Load Modules From File', command=self._load_modules_from_file).pack(side=tk.LEFT)

        self.run_btn = ttk.Button(top, text='Run Scan', command=self._on_run_click)
        self.run_btn.pack(side=tk.RIGHT)

        # Split main area
        main = tk.PanedWindow(self, orient=tk.HORIZONTAL)
        main.pack(fill=tk.BOTH, expand=True, padx=10, pady=8)

        left_frame = tk.Frame(main, bg=self.theme['bg'])
        right_frame = tk.Frame(main, bg=self.theme['bg'])
        main.add(left_frame, minsize=300)
        main.add(right_frame, minsize=300)

        # Results tree
        res_lbl = tk.Label(left_frame, text='Results', bg=self.theme['bg'], fg=self.theme['fg'])
        res_lbl.pack(anchor='w')

        cols = ('status', 'summary', 'time')
        self.results_tree = ttk.Treeview(left_frame, columns=cols, show='tree headings')
        self.results_tree.heading('#0', text='Module')
        self.results_tree.heading('status', text='Status')
        self.results_tree.heading('summary', text='Summary')
        self.results_tree.heading('time', text='Time')
        self.results_tree.column('status', width=80, anchor='center')
        self.results_tree.column('summary', width=220)
        self.results_tree.column('time', width=120, anchor='center')
        self.results_tree.pack(fill=tk.BOTH, expand=True, pady=(4, 0))

        # Console / Log
        console_lbl = tk.Label(right_frame, text='Console / Log', bg=self.theme['bg'], fg=self.theme['fg'])
        console_lbl.pack(anchor='w')

        self.console = scrolledtext.ScrolledText(right_frame, height=20, bg=self.theme['bg_secondary'] if 'bg_secondary' in self.theme else '#2d2d2d', fg=self.theme['fg'])
        # Make console read-only
        self.console.configure(state='disabled')
        self.console.pack(fill=tk.BOTH, expand=True)

        # Bottom status
        self.status_var = tk.StringVar(value='Ready')
        status = tk.Label(self, textvariable=self.status_var, bg=self.theme['bg'], fg=self.theme['fg'])
        status.pack(side=tk.BOTTOM, fill=tk.X)

    def _load_modules_from_file(self):
        path = filedialog.askopenfilename(title='Select modules JSON', filetypes=[('JSON', '*.json'), ('All', '*.*')])
        if not path:
            return
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            self.module_list.delete(0, tk.END)
            for m in data.get('modules', []) if isinstance(data, dict) else data:
                self.module_list.insert(tk.END, m)
            self._log(f'Loaded {self.module_list.size()} modules from {path}')
        except Exception as e:
            messagebox.showerror('Error', f'Failed to load modules: {e}')

    def _on_run_click(self):
        selected = [self.module_list.get(i) for i in self.module_list.curselection()]
        if not selected:
            messagebox.showwarning('No modules', 'Please select at least one module to run.')
            return

        if self._scan_thread and self._scan_thread.is_alive():
            if not messagebox.askyesno('Scan running', 'A scan is already running. Do you want to start another?'):
                return

        # disable run button while scanning
        self.run_btn.configure(state=tk.DISABLED)
        self.status_var.set('Starting scan...')

        self._scan_thread = threading.Thread(target=self._run_scan, args=(selected,), daemon=True)
        self._scan_thread.start()

    def _run_scan(self, modules: List[str]):
        """
        Integrate with RedHawkEngine to run the requested modules. This method is
        run in a background thread.

        The engine is expected to provide a scanning method (try common names).
        Module callbacks are reported to the console and the results tree.
        """
        start_time = datetime.utcnow()
        self._log(f'Scan started at {start_time.isoformat()} with modules: {modules}')

        if RedHawkEngine is None:
            self._log('RedHawkEngine could not be imported. Aborting scan.')
            self._finish_scan()
            return

        try:
            # Create engine instance. If the constructor accepts a callback, try to pass it.
            def module_callback(*args, **kwargs):
                # Best-effort parsing of engine callbacks.
                try:
                    # Common patterns: (module_name, status, data)
                    if len(args) >= 3:
                        module_name, status, data = args[0], args[1], args[2]
                    elif len(args) == 2:
                        module_name, data = args[0], args[1]
                        status = data.get('status') if isinstance(data, dict) and 'status' in data else 'done'
                    elif len(args) == 1:
                        module_name = args[0]
                        status = kwargs.get('status', 'done')
                        data = kwargs.get('data', None)
                    else:
                        module_name = kwargs.get('module') or kwargs.get('name') or 'unknown'
                        status = kwargs.get('status', 'done')
                        data = kwargs.get('data', None)
                except Exception:
                    # fallback generic view
                    module_name = kwargs.get('module', 'unknown')
                    status = kwargs.get('status', 'done')
                    data = None

                # Print raw callback to console for debugging / trace
                self._log(f'[callback] module={module_name} status={status} data={self._short_repr(data)}')

                # Prepare summary to display in results tree
                summary = self._summarize_data(data)
                time_str = datetime.utcnow().strftime('%H:%M:%S')

                # Schedule UI update on main thread
                self.after(0, lambda: self._add_result(module_name, status, summary, time_str))

            # Instantiate engine
            engine = None
            try:
                # Try passing callback into constructor if supported
                engine = RedHawkEngine(callback=module_callback)
            except TypeError:
                try:
                    engine = RedHawkEngine()
                except Exception:
                    engine = RedHawkEngine if isinstance(RedHawkEngine, type) else None

            if engine is None:
                # If engine is a function/class with a run method at module level
                self._log('Failed to instantiate RedHawkEngine.')
                self._finish_scan()
                return

            # Find a runner method on the engine object
            runner = None
            for name in ('run_scan', 'run', 'scan', 'start'):
                runner = getattr(engine, name, None)
                if callable(runner):
                    break
                runner = None

            # If engine has a top-level 'run' accepting callback kwargs, try to use it
            if runner is None and hasattr(engine, 'start_scan'):
                runner = getattr(engine, 'start_scan')

            if runner is None:
                # Maybe engine is a module-like object with a top-level function
                for name in ('run_scan', 'run', 'scan'):
                    runner = getattr(RedHawkEngine, name, None)
                    if callable(runner):
                        break
                    runner = None

            if runner is None:
                self._log('No runnable scan method found on RedHawkEngine. Aborting.')
                self._finish_scan()
                return

            # Run with best-effort set of kwargs
            try:
                # Many engines accept modules list and a callback param
                runner(modules=modules, callback=module_callback)
            except TypeError:
                try:
                    # Some expect positional modules
                    runner(modules)
                except TypeError:
                    try:
                        # As a last resort call without arguments
                        runner()
                    except Exception as e:
                        self._log('Error while starting engine: ' + str(e))
                        self._log(traceback.format_exc())

            # When runner completes it may return a summary object
            self._log('Engine runner finished. Gathering final summary...')

        except Exception as e:
            self._log(f'Unexpected error while running scan: {e}')
            self._log(traceback.format_exc())
        finally:
            self._finish_scan()

    def _summarize_data(self, data: Any) -> str:
        """Return a short one-line summary about result data."""
        try:
            if data is None:
                return ''
            if isinstance(data, str):
                # try to shorten
                return data if len(data) <= 100 else data[:97] + '...'
            if isinstance(data, dict):
                # Common keys: 'issues', 'results', 'count'
                if 'issues' in data and isinstance(data['issues'], (list, tuple)):
                    return f"{len(data['issues'])} issues"
                if 'results' in data and isinstance(data['results'], (list, tuple)):
                    return f"{len(data['results'])} results"
                if 'summary' in data:
                    return str(data['summary'])[:120]
                # fallback key count
                return ', '.join(f'{k}={str(v)[:30]}' for k, v in list(data.items())[:3])
            if isinstance(data, (list, tuple)):
                return f"{len(data)} items"
            return str(data)[:120]
        except Exception:
            return str(data)

    def _short_repr(self, obj: Any) -> str:
        try:
            s = repr(obj)
            return s if len(s) <= 200 else s[:197] + '...'
        except Exception:
            return '<unrepresentable>'

    def _add_result(self, module_name: str, status: str, summary: str, time_str: str):
        # Insert or update a result row
        key = self._find_tree_item(module_name)
        values = (status, summary, time_str)
        if key:
            self.results_tree.item(key, values=values)
        else:
            self.results_tree.insert('', 'end', iid=module_name, text=module_name, values=values)

    def _find_tree_item(self, module_name: str) -> Optional[str]:
        # simple lookup by iid
        try:
            if self.results_tree.exists(module_name):
                return module_name
        except Exception:
            # older tkinter may not have exists()
            for iid in self.results_tree.get_children(''):
                if iid == module_name:
                    return iid
        return None

    def _log(self, message: str):
        ts = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        line = f'[{ts}] {message}\n'
        # Print to stdout as well
        print(line, end='')
        # Append to console widget
        def _append():
            self.console.configure(state='normal')
            self.console.insert(tk.END, line)
            # keep last N chars visible
            self.console.see(tk.END)
            self.console.configure(state='disabled')

        try:
            self.after(0, _append)
        except Exception:
            # If we're shutting down, ignore
            pass

    def _finish_scan(self):
        # Re-enable run button and update status
        def _done():
            self.run_btn.configure(state=tk.NORMAL)
            self.status_var.set('Ready')
            self._log('Scan finished.')

        self.after(0, _done)

    def _on_close(self):
        if self._scan_thread and self._scan_thread.is_alive():
            if not messagebox.askyesno('Quit', 'A scan is running. Are you sure you want to quit?'):
                return
        self.destroy()


if __name__ == '__main__':
    app = ModernInterface()
    app.mainloop()
