"""
Core Engine for RedHawk Framework
Handles module loading, execution, and coordination
"""

import os
import sys
import json
import yaml
import importlib
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any
import threading
import queue

class RedHawkEngine:
    def __init__(self, config_path='config/config.yaml'):
        self.config_path = config_path
        self.config = self.load_config()
        self.modules = {}
        self.results = {}
        self.load_modules()
        
        # Create necessary directories
        self.setup_directories()
    
    def setup_directories(self):
        """Create required directories if they don't exist"""
        dirs = ['data', 'reports', 'logs', 'config']
        for d in dirs:
            Path(d).mkdir(exist_ok=True)
    
    def load_config(self) -> Dict:
        """Load configuration from YAML file"""
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r') as f:
                    return yaml.safe_load(f)
            else:
                # Return default config
                return self.get_default_config()
        except Exception as e:
            print(f"[!] Error loading config: {e}")
            return self.get_default_config()
    
    def get_default_config(self) -> Dict:
        """Return default configuration"""
        return {
            'engine': {
                'max_threads': 10,
                'timeout': 30,
                'user_agent': 'RedHawk/1.0 Security Scanner'
            },
            'output': {
                'format': 'json',
                'directory': 'reports',
                'timestamp': True
            },
            'modules': {
                'dns': {'enabled': True, 'timeout': 10},
                'subdomain': {'enabled': True, 'wordlist': 'data/subdomains.txt'},
                'port_scan': {'enabled': True, 'top_ports': 1000},
                'email': {'enabled': True},
                'whois': {'enabled': True},
                'ssl': {'enabled': True},
                'headers': {'enabled': True},
                'waf': {'enabled': True},
                'technology': {'enabled': True}
            }
        }
    
    def load_modules(self):
        """Dynamically load all modules from modules directory"""
        # Get the project root directory
        if hasattr(sys, '_MEIPASS'):
            # Running as compiled executable
            base_path = Path(sys._MEIPASS)
        else:
            # Running as script
            base_path = Path(__file__).parent.parent
        
        modules_dir = base_path / 'modules'
        
        if not modules_dir.exists():
            print(f"[!] Modules directory not found at: {modules_dir}")
            return
        
        for module_file in modules_dir.glob('*.py'):
            if module_file.name.startswith('_'):
                continue
            
            module_name = module_file.stem
            try:
                spec = importlib.util.spec_from_file_location(
                    f"modules.{module_name}", 
                    module_file
                )
                module = importlib.util.module_from_spec(spec)
                sys.modules[f"modules.{module_name}"] = module
                spec.loader.exec_module(module)
                
                # Get the scanner class from module
                if hasattr(module, 'Scanner'):
                    self.modules[module_name] = module.Scanner()
                    print(f"[+] Loaded module: {module_name}")
            except Exception as e:
                print(f"[!] Error loading module {module_name}: {e}")
    
    def run_module(self, module_name: str, target: str, callback=None) -> Dict:
        """Run a specific module against target"""
        if module_name not in self.modules:
            return {'error': f'Module {module_name} not found'}
        
        try:
            module = self.modules[module_name]
            print(f"[*] Running {module_name} scan...")
            
            result = module.scan(target, self.config)
            
            if callback:
                callback(module_name, result)
            
            return result
        except Exception as e:
            error_msg = f"Error running {module_name}: {str(e)}"
            print(f"[!] {error_msg}")
            return {'error': error_msg}
    
    def run_all_modules(self, target: str, callback=None) -> Dict:
        """Run all enabled modules against target"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        scan_id = f"{target}_{timestamp}"
        
        results = {
            'target': target,
            'scan_id': scan_id,
            'timestamp': timestamp,
            'modules': {}
        }
        
        enabled_modules = [
            name for name, module in self.modules.items()
            if self.config.get('modules', {}).get(name, {}).get('enabled', True)
        ]
        
        print(f"[*] Running {len(enabled_modules)} modules against {target}")
        
        for module_name in enabled_modules:
            result = self.run_module(module_name, target, callback)
            results['modules'][module_name] = result
        
        # Save results
        output_path = self.save_results(results)
        results['output_path'] = output_path
        
        return results
    
    def run_modules_threaded(self, target: str, callback=None) -> Dict:
        """Run modules in parallel using threading"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        scan_id = f"{target}_{timestamp}"
        
        results = {
            'target': target,
            'scan_id': scan_id,
            'timestamp': timestamp,
            'modules': {}
        }
        
        enabled_modules = [
            name for name, module in self.modules.items()
            if self.config.get('modules', {}).get(name, {}).get('enabled', True)
        ]
        
        result_queue = queue.Queue()
        threads = []
        
        def worker(module_name):
            result = self.run_module(module_name, target, callback)
            result_queue.put((module_name, result))
        
        # Start threads
        for module_name in enabled_modules:
            thread = threading.Thread(target=worker, args=(module_name,))
            thread.start()
            threads.append(thread)
        
        # Wait for completion
        for thread in threads:
            thread.join()
        
        # Collect results
        while not result_queue.empty():
            module_name, result = result_queue.get()
            results['modules'][module_name] = result
        
        # Save results
        output_path = self.save_results(results)
        results['output_path'] = output_path
        
        return results
    
    def save_results(self, results: Dict) -> str:
        """Save scan results to file"""
        output_dir = Path(self.config['output']['directory'])
        output_dir.mkdir(exist_ok=True)
        
        filename = f"{results['scan_id']}.json"
        filepath = output_dir / filename
        
        # Clean results to ensure JSON serialization
        cleaned_results = self._clean_for_json(results)
        
        with open(filepath, 'w') as f:
            json.dump(cleaned_results, f, indent=2)
        
        print(f"[+] Results saved to: {filepath}")
        return str(filepath)
    
    def _clean_for_json(self, obj):
        """Recursively clean object for JSON serialization"""
        if isinstance(obj, dict):
            return {
                self._clean_for_json(k): self._clean_for_json(v) 
                for k, v in obj.items()
            }
        elif isinstance(obj, list):
            return [self._clean_for_json(item) for item in obj]
        elif isinstance(obj, bytes):
            # Convert bytes to string
            try:
                return obj.decode('utf-8', errors='ignore')
            except:
                return str(obj)
        elif isinstance(obj, (str, int, float, bool, type(None))):
            return obj
        else:
            # Convert other types to string
            return str(obj)
    
    def generate_report(self, scan_data_path: str, output_format='html'):
        """Generate report from scan data"""
        from utils.report_generator import ReportGenerator
        
        with open(scan_data_path, 'r') as f:
            data = json.load(f)
        
        generator = ReportGenerator()
        report_path = generator.generate(data, output_format)
        
        print(f"[+] Report generated: {report_path}")
        return report_path
    
    def get_available_modules(self) -> List[str]:
        """Return list of available module names"""
        return list(self.modules.keys())
    
    def get_timestamp(self) -> str:
        """Get current timestamp string"""
        return datetime.now().strftime('%Y%m%d_%H%M%S')
    
    def get_module_info(self, module_name: str) -> Dict:
        """Get information about a specific module"""
        if module_name in self.modules:
            module = self.modules[module_name]
            return {
                'name': module_name,
                'description': getattr(module, 'description', 'No description'),
                'enabled': self.config.get('modules', {}).get(module_name, {}).get('enabled', True)
            }
        return {}