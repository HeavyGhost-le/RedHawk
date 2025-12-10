"""
HTTP Headers Security Analysis Module
Checks for security-related HTTP headers
"""

import requests
from typing import Dict, List
import warnings

# Suppress SSL warnings (expected for security scanning)
warnings.filterwarnings('ignore', message='Unverified HTTPS request')
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Scanner:
    def __init__(self):
        self.name = "Headers Scanner"
        self.description = "HTTP security headers analysis"
        
        # Security headers to check
        self.security_headers = {
            'Strict-Transport-Security': {
                'recommended': 'max-age=31536000; includeSubDomains',
                'description': 'Enforces HTTPS connections'
            },
            'Content-Security-Policy': {
                'recommended': "default-src 'self'",
                'description': 'Prevents XSS and injection attacks'
            },
            'X-Frame-Options': {
                'recommended': 'DENY',
                'description': 'Prevents clickjacking attacks'
            },
            'X-Content-Type-Options': {
                'recommended': 'nosniff',
                'description': 'Prevents MIME-sniffing'
            },
            'X-XSS-Protection': {
                'recommended': '1; mode=block',
                'description': 'Enables XSS filter'
            },
            'Referrer-Policy': {
                'recommended': 'no-referrer',
                'description': 'Controls referrer information'
            },
            'Permissions-Policy': {
                'recommended': "geolocation=(), microphone=(), camera=()",
                'description': 'Controls browser features'
            }
        }
    
    def scan(self, target: str, config: Dict) -> Dict:
        """Main scan function"""
        results = {
            'target': target,
            'headers': {},
            'missing_headers': [],
            'present_headers': [],
            'insecure_headers': [],
            'vulnerabilities': []
        }
        
        try:
            # Try HTTPS first
            try:
                url = f"https://{target}"
                response = requests.get(url, timeout=10, allow_redirects=True, verify=False)
                results['url'] = url
                results['status_code'] = response.status_code
            except:
                # Fall back to HTTP
                url = f"http://{target}"
                response = requests.get(url, timeout=10, allow_redirects=True)
                results['url'] = url
                results['status_code'] = response.status_code
            
            # Get all headers
            results['headers'] = dict(response.headers)
            
            # Check security headers
            for header, info in self.security_headers.items():
                if header in response.headers:
                    results['present_headers'].append({
                        'header': header,
                        'value': response.headers[header],
                        'description': info['description']
                    })
                else:
                    results['missing_headers'].append({
                        'header': header,
                        'recommended': info['recommended'],
                        'description': info['description']
                    })
            
            # Check for insecure headers
            results['insecure_headers'] = self.check_insecure_headers(response.headers)
            
            # Analyze vulnerabilities
            results['vulnerabilities'] = self.analyze_header_security(results)
            
            results['status'] = 'success'
        except Exception as e:
            results['status'] = 'error'
            results['error'] = str(e)
        
        return results
    
    def check_insecure_headers(self, headers: Dict) -> List[Dict]:
        """Check for headers that reveal sensitive information"""
        insecure = []
        
        # Server header reveals server software
        if 'Server' in headers:
            insecure.append({
                'header': 'Server',
                'value': headers['Server'],
                'issue': 'Reveals server software version',
                'recommendation': 'Remove or obfuscate Server header'
            })
        
        # X-Powered-By reveals technology stack
        if 'X-Powered-By' in headers:
            insecure.append({
                'header': 'X-Powered-By',
                'value': headers['X-Powered-By'],
                'issue': 'Reveals technology stack',
                'recommendation': 'Remove X-Powered-By header'
            })
        
        # X-AspNet-Version reveals ASP.NET version
        if 'X-AspNet-Version' in headers:
            insecure.append({
                'header': 'X-AspNet-Version',
                'value': headers['X-AspNet-Version'],
                'issue': 'Reveals ASP.NET version',
                'recommendation': 'Remove X-AspNet-Version header'
            })
        
        return insecure
    
    def analyze_header_security(self, results: Dict) -> List[Dict]:
        """Analyze headers for security issues"""
        vulns = []
        
        # Missing critical security headers
        for missing in results['missing_headers']:
            severity = 'high' if missing['header'] in ['Strict-Transport-Security', 'Content-Security-Policy'] else 'medium'
            
            vulns.append({
                'severity': severity,
                'type': f"Missing {missing['header']}",
                'description': f"{missing['description']}. Header not present.",
                'recommendation': f"Add header: {missing['header']}: {missing['recommended']}"
            })
        
        # Information disclosure
        for insecure in results['insecure_headers']:
            vulns.append({
                'severity': 'low',
                'type': 'Information Disclosure',
                'description': f"{insecure['issue']}: {insecure['header']}: {insecure['value']}",
                'recommendation': insecure['recommendation']
            })
        
        # Check if site is HTTP only
        if results.get('url', '').startswith('http://'):
            vulns.append({
                'severity': 'high',
                'type': 'No HTTPS',
                'description': 'Site is accessible over unencrypted HTTP',
                'recommendation': 'Implement HTTPS with valid SSL certificate'
            })
        
        return vulns