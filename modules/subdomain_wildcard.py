"""
Enhanced Subdomain Enumeration Module with Wildcard Support
Discovers subdomains using multiple techniques and supports wildcard scanning
"""

import dns.resolver
import requests
import concurrent.futures
from typing import Dict, List, Set
import time
import warnings
import re

# Suppress SSL warnings (expected for security scanning)
warnings.filterwarnings('ignore', message='Unverified HTTPS request')
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Scanner:
    def __init__(self):
        self.name = "Subdomain Scanner (Wildcard)"
        self.description = "Enhanced subdomain enumeration with wildcard domain support"
        self.found_subdomains = set()
    
    def scan(self, target: str, config: Dict) -> Dict:
        """Main scan function with wildcard support"""
        results = {
            'target': target,
            'is_wildcard': False,
            'base_domain': target,
            'subdomains': [],
            'methods': {},
            'statistics': {}
        }
        
        start_time = time.time()
        
        try:
            # Check if wildcard pattern
            if target.startswith('*.'):
                results['is_wildcard'] = True
                results['base_domain'] = target[2:]  # Remove *.
                print(f"[*] Wildcard scan detected: {target}")
                print(f"[*] Base domain: {results['base_domain']}")
                target = results['base_domain']
            
            # Method 1: Certificate Transparency (best for wildcard discovery)
            print(f"[*] Checking Certificate Transparency logs...")
            ct_results = self.certificate_transparency(target)
            results['methods']['certificate_transparency'] = len(ct_results)
            self.found_subdomains.update(ct_results)
            
            # Method 2: DNS enumeration techniques
            print(f"[*] DNS enumeration...")
            dns_results = self.dns_enumeration(target)
            results['methods']['dns_enum'] = len(dns_results)
            self.found_subdomains.update(dns_results)
            
            # Method 3: Wordlist brute force
            print(f"[*] Starting wordlist brute force...")
            wordlist_results = self.wordlist_bruteforce(target, config)
            results['methods']['wordlist'] = len(wordlist_results)
            self.found_subdomains.update(wordlist_results)
            
            # Method 4: Common subdomains
            print(f"[*] Checking common subdomains...")
            common_results = self.common_subdomains(target)
            results['methods']['common'] = len(common_results)
            self.found_subdomains.update(common_results)
            
            # Method 5: Search engine enumeration (passive)
            print(f"[*] Search engine enumeration...")
            search_results = self.search_engine_enum(target)
            results['methods']['search_engines'] = len(search_results)
            self.found_subdomains.update(search_results)
            
            # Verify all found subdomains
            print(f"[*] Verifying discovered subdomains...")
            verified = self.verify_subdomains(list(self.found_subdomains))
            
            results['subdomains'] = sorted(list(verified))
            results['statistics'] = {
                'total_found': len(verified),
                'scan_time': round(time.time() - start_time, 2),
                'methods_used': len(results['methods'])
            }
            
            # Group by TLD for wildcard scans
            if results['is_wildcard']:
                results['grouped'] = self.group_subdomains(verified, target)
            
            results['status'] = 'success'
            
            print(f"[+] Found {len(verified)} subdomains for {target}")
            
        except Exception as e:
            results['status'] = 'error'
            results['error'] = str(e)
        
        return results
    
    def certificate_transparency(self, domain: str) -> Set[str]:
        """Search Certificate Transparency logs - best for wildcard discovery"""
        subdomains = set()
        
        # Try multiple CT sources with increasing timeouts
        ct_sources = [
            {
                'name': 'crt.sh (deduplicated)',
                'url': f"https://crt.sh/?q=%.{domain}&output=json&deduplicate=Y",
                'timeout': 20
            },
            {
                'name': 'crt.sh (full)',
                'url': f"https://crt.sh/?q=%.{domain}&output=json",
                'timeout': 25
            }
        ]
        
        for source in ct_sources:
            try:
                print(f"[*] Trying {source['name']}...")
                response = requests.get(
                    source['url'], 
                    timeout=source['timeout'],
                    headers={'User-Agent': 'RedHawk Security Scanner'}
                )
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        count = 0
                        for entry in data:
                            # Handle different response formats
                            names = []
                            if 'name_value' in entry:
                                names = entry['name_value'].split('\n')
                            elif 'common_name' in entry:
                                names = [entry['common_name']]
                            
                            for name in names:
                                name = name.strip().replace('*.', '')
                                if name.endswith(domain) and name != domain:
                                    subdomains.add(name)
                                    count += 1
                        
                        print(f"[+] {source['name']}: Found {count} subdomains")
                        if count > 0:
                            break  # Success, no need to try other sources
                    except ValueError as e:
                        print(f"[!] {source['name']}: Invalid JSON response")
                        continue
                else:
                    print(f"[!] {source['name']}: HTTP {response.status_code}")
            except requests.exceptions.Timeout:
                print(f"[!] {source['name']}: Timeout (server slow/overloaded)")
                continue
            except requests.exceptions.ConnectionError:
                print(f"[!] {source['name']}: Connection failed")
                continue
            except Exception as e:
                print(f"[!] {source['name']}: {e}")
                continue
        
        if not subdomains:
            print(f"[!] Certificate Transparency: No results (service may be slow)")
        
        return subdomains
    
    def dns_enumeration(self, domain: str) -> Set[str]:
        """DNS-based enumeration techniques"""
        subdomains = set()
        
        # Try AXFR (zone transfer)
        try:
            ns_records = dns.resolver.resolve(domain, 'NS')
            for ns in ns_records:
                ns_str = str(ns).rstrip('.')
                try:
                    import socket
                    ns_ip = socket.gethostbyname(ns_str)
                    zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=5))
                    if zone:
                        for name in zone.nodes.keys():
                            subdomain = f"{name}.{domain}".replace('..', '.')
                            if subdomain != domain:
                                subdomains.add(subdomain)
                except:
                    pass
        except:
            pass
        
        # Try ANY record
        try:
            answers = dns.resolver.resolve(domain, 'ANY')
            for rdata in answers:
                if hasattr(rdata, 'target'):
                    target = str(rdata.target).rstrip('.')
                    if domain in target:
                        subdomains.add(target)
        except:
            pass
        
        return subdomains
    
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
    
    def common_subdomains(self, domain: str) -> Set[str]:
        """Check common subdomain names"""
        common = [
            # Standard subdomains
            'www', 'mail', 'ftp', 'smtp', 'pop', 'imap',
            'webmail', 'admin', 'portal', 'api', 'dev',
            'test', 'staging', 'demo', 'beta', 'blog',
            'shop', 'store', 'vpn', 'secure', 'login',
            'mobile', 'app', 'cdn', 'static', 'assets',
            'img', 'images', 'upload', 'download', 'docs',
            'support', 'help', 'forum', 'status', 'monitor',
            'ns1', 'ns2', 'dns', 'mx', 'autodiscover',
            'cpanel', 'whm', 'webdisk', 'mysql', 'db',
            'remote', 'cloud', 'git', 'svn', 'old', 'new',
            # Government-specific subdomains
            'mfa', 'parliament', 'presidency', 'cabinet',
            'finance', 'treasury', 'revenue', 'tax',
            'health', 'education', 'justice', 'interior',
            'defense', 'foreign', 'trade', 'agriculture',
            'energy', 'water', 'transport', 'housing',
            'immigration', 'customs', 'police', 'fire',
            'emergency', 'registry', 'statistics', 'census',
            'procurement', 'audit', 'archive', 'library',
            'tourism', 'culture', 'sports', 'youth',
            'labor', 'employment', 'pension', 'social'
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
    
    def search_engine_enum(self, domain: str) -> Set[str]:
        """Enumerate subdomains using search engines (passive)"""
        subdomains = set()
        
        # Google dorking patterns
        patterns = [
            f"site:*.{domain}",
            f"site:{domain} -www",
        ]
        
        # Note: This is passive - we're not actually querying search engines
        # to avoid rate limiting. In production, you'd integrate with APIs.
        # For now, we extract from CT logs which often index these.
        
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
    
    def group_subdomains(self, subdomains: Set[str], base_domain: str) -> Dict:
        """Group subdomains by pattern for wildcard analysis"""
        grouped = {
            'by_prefix': {},
            'by_level': {},
            'interesting': []
        }
        
        for subdomain in subdomains:
            # Get prefix (first part)
            parts = subdomain.replace(f".{base_domain}", "").split('.')
            if parts:
                prefix = parts[-1]  # Last part before base domain
                if prefix not in grouped['by_prefix']:
                    grouped['by_prefix'][prefix] = []
                grouped['by_prefix'][prefix].append(subdomain)
            
            # Group by subdomain levels
            level = len(parts)
            if level not in grouped['by_level']:
                grouped['by_level'][level] = []
            grouped['by_level'][level].append(subdomain)
            
            # Identify interesting subdomains
            interesting_keywords = ['admin', 'api', 'dev', 'test', 'staging', 
                                   'internal', 'vpn', 'mail', 'db', 'mysql']
            if any(kw in subdomain.lower() for kw in interesting_keywords):
                grouped['interesting'].append(subdomain)
        
        return grouped
    
    def _ensure_wordlist(self, path: str) -> bool:
        """Create default wordlist if it doesn't exist"""
        import os
        
        if os.path.exists(path):
            return True
        
        # Create directory if needed
        os.makedirs(os.path.dirname(path), exist_ok=True)
        
        # Extended wordlist for better discovery
        default_words = [
            # Common
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1',
            'webdisk', 'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig',
            'admin', 'portal', 'api', 'dev', 'test', 'staging', 'demo', 'beta',
            'www1', 'www2', 'blog', 'shop', 'store', 'vpn', 'remote', 'secure',
            'login', 'mobile', 'app', 'cdn', 'static', 'assets', 'img', 'images',
            'upload', 'download', 'docs', 'support', 'help', 'forum', 'chat',
            'status', 'monitor', 'git', 'svn', 'backup', 'old', 'new', 'temp',
            
            # Infrastructure
            'ns', 'dns', 'mx', 'email', 'direct', 'direct-connect', 'imap',
            'smtp', 'pop3', 'mail2', 'relay', 'gateway', 'proxy', 'firewall',
            
            # Development
            'alpha', 'beta', 'gamma', 'delta', 'preprod', 'production', 'prod',
            'uat', 'qa', 'testing', 'sandbox', 'localhost', 'dev2', 'dev3',
            
            # Services
            'api', 'rest', 'soap', 'ws', 'webservice', 'service', 'services',
            'v1', 'v2', 'mobile', 'ios', 'android', 'app',
            
            # Administrative
            'admin', 'administrator', 'admins', 'root', 'sys', 'system',
            'manage', 'management', 'panel', 'dashboard', 'console', 'control',
            
            # Databases
            'db', 'database', 'mysql', 'mssql', 'postgres', 'postgresql',
            'oracle', 'mongodb', 'redis', 'sql', 'phpmyadmin', 'dbadmin',
            
            # Cloud/CDN
            'cdn', 'cloud', 'aws', 'azure', 's3', 'cloudfront', 'storage',
            
            # Regional
            'us', 'eu', 'asia', 'uk', 'au', 'ca', 'de', 'fr', 'jp', 'cn',
            'east', 'west', 'north', 'south', 'central',
            
            # Misc
            'intranet', 'extranet', 'internal', 'external', 'private', 'public',
            'partners', 'partner', 'vendor', 'suppliers', 'clients', 'customer'
        ]
        
        try:
            with open(path, 'w') as f:
                f.write('\n'.join(default_words))
            return True
        except:
            return False