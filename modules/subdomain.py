"""
Subdomain Enumeration Module
Discovers subdomains using multiple techniques
"""

import dns.resolver
import requests
import concurrent.futures
from typing import Dict, List, Set
import time
import warnings

# Suppress SSL warnings (expected for security scanning)
warnings.filterwarnings('ignore', message='Unverified HTTPS request')
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Scanner:
    def __init__(self):
        self.name = "Subdomain Scanner"
        self.description = "Subdomain enumeration via brute force and APIs"
        self.found_subdomains = set()
    
    def scan(self, target: str, config: Dict) -> Dict:
        """Main scan function"""
        results = {
            'target': target,
            'subdomains': [],
            'methods': {},
            'statistics': {}
        }
        
        start_time = time.time()
        
        try:
            # Method 1: Wordlist brute force
            print(f"[*] Starting wordlist brute force...")
            wordlist_results = self.wordlist_bruteforce(target, config)
            results['methods']['wordlist'] = len(wordlist_results)
            self.found_subdomains.update(wordlist_results)
            
            # Method 2: Certificate Transparency
            print(f"[*] Checking Certificate Transparency logs...")
            ct_results = self.certificate_transparency(target)
            results['methods']['certificate_transparency'] = len(ct_results)
            self.found_subdomains.update(ct_results)
            
            # Method 3: Common subdomains
            print(f"[*] Checking common subdomains...")
            common_results = self.common_subdomains(target)
            results['methods']['common'] = len(common_results)
            self.found_subdomains.update(common_results)
            
            # Verify all found subdomains
            print(f"[*] Verifying discovered subdomains...")
            verified = self.verify_subdomains(list(self.found_subdomains))
            
            results['subdomains'] = sorted(list(verified))
            results['statistics'] = {
                'total_found': len(verified),
                'scan_time': round(time.time() - start_time, 2)
            }
            
            results['status'] = 'success'
        except Exception as e:
            results['status'] = 'error'
            results['error'] = str(e)
        
        return results
    
    def wordlist_bruteforce(self, domain: str, config: Dict) -> Set[str]:
        """Brute force using wordlist"""
        subdomains = set()
        wordlist_path = config.get('modules', {}).get('subdomain', {}).get('wordlist', 'data/subdomains.txt')
        
        # Create default wordlist if not exists
        if not self._ensure_wordlist(wordlist_path):
            return subdomains
        
        try:
            with open(wordlist_path, 'r') as f:
                words = [line.strip() for line in f if line.strip()]
        except:
            return subdomains
        
        # Use threading for faster scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = {
                executor.submit(self._check_subdomain, f"{word}.{domain}"): word 
                for word in words
            }
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    subdomains.add(result)
        
        return subdomains
    
    def _check_subdomain(self, subdomain: str) -> str:
        """Check if subdomain exists"""
        try:
            dns.resolver.resolve(subdomain, 'A')
            return subdomain
        except:
            return None
    
    def certificate_transparency(self, domain: str) -> Set[str]:
        """Search Certificate Transparency logs"""
        subdomains = set()
        
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry.get('name_value', '')
                    if name:
                        # Handle wildcard and multiple names
                        names = name.split('\n')
                        for n in names:
                            n = n.strip().replace('*.', '')
                            if n.endswith(domain) and n != domain:
                                subdomains.add(n)
        except Exception as e:
            print(f"[!] CT logs error: {e}")
        
        return subdomains
    
    def common_subdomains(self, domain: str) -> Set[str]:
        """Check common subdomain names"""
        common = [
            'www', 'mail', 'ftp', 'smtp', 'pop', 'imap',
            'webmail', 'admin', 'portal', 'api', 'dev',
            'test', 'staging', 'demo', 'beta', 'blog',
            'shop', 'store', 'vpn', 'secure', 'login',
            'mobile', 'app', 'cdn', 'static', 'assets',
            'img', 'images', 'upload', 'download', 'docs',
            'support', 'help', 'forum', 'status', 'monitor',
            'ns1', 'ns2', 'dns', 'mx', 'autodiscover'
        ]
        
        subdomains = set()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = {
                executor.submit(self._check_subdomain, f"{prefix}.{domain}"): prefix
                for prefix in common
            }
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    subdomains.add(result)
        
        return subdomains
    
    def verify_subdomains(self, subdomains: List[str]) -> Set[str]:
        """Verify that subdomains are actually resolvable"""
        verified = set()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = {
                executor.submit(self._verify_single, subdomain): subdomain
                for subdomain in subdomains
            }
            
            for future in concurrent.futures.as_completed(futures):
                subdomain, ips = future.result()
                if ips:
                    verified.add(subdomain)
        
        return verified
    
    def _verify_single(self, subdomain: str) -> tuple:
        """Verify a single subdomain"""
        try:
            answers = dns.resolver.resolve(subdomain, 'A')
            ips = [str(rdata) for rdata in answers]
            return (subdomain, ips)
        except:
            return (subdomain, None)
    
    def _ensure_wordlist(self, path: str) -> bool:
        """Create default wordlist if it doesn't exist"""
        import os
        
        if os.path.exists(path):
            return True
        
        # Create directory if needed
        os.makedirs(os.path.dirname(path), exist_ok=True)
        
        # Default wordlist
        default_words = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1',
            'webdisk', 'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig',
            'admin', 'portal', 'api', 'dev', 'test', 'staging', 'demo', 'beta',
            'www1', 'www2', 'blog', 'shop', 'store', 'vpn', 'remote', 'secure',
            'login', 'mobile', 'app', 'cdn', 'static', 'assets', 'img', 'images',
            'upload', 'download', 'docs', 'support', 'help', 'forum', 'chat',
            'status', 'monitor', 'git', 'svn', 'backup', 'old', 'new', 'temp'
        ]
        
        try:
            with open(path, 'w') as f:
                f.write('\n'.join(default_words))
            return True
        except:
            return False