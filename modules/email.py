"""
Email Reconnaissance Module
Analyzes email security (SPF, DMARC, DKIM) and harvests email addresses
Integrates with Hunter.io API for advanced email discovery
"""

import dns.resolver
import re
import requests
from typing import Dict, List, Set
import concurrent.futures
import warnings

# Suppress SSL warnings (expected for security scanning)
warnings.filterwarnings('ignore', message='Unverified HTTPS request')
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Scanner:
    def __init__(self):
        self.name = "Email Scanner"
        self.description = "Email security analysis and address harvesting with Hunter.io integration"
        # Hunter.io API key (can be overridden in config)
        self.hunter_api_key = "96xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    
    def scan(self, target: str, config: Dict) -> Dict:
        """Main scan function"""
        results = {
            'target': target,
            'mx_records': [],
            'spf': {},
            'dmarc': {},
            'dkim': {},
            'emails_found': [],
            'hunter_results': {},
            'vulnerabilities': []
        }
        
        try:
            # Get MX records
            results['mx_records'] = self.get_mx_records(target)
            
            # Check SPF
            results['spf'] = self.check_spf(target)
            
            # Check DMARC
            results['dmarc'] = self.check_dmarc(target)
            
            # Check DKIM (common selectors)
            results['dkim'] = self.check_dkim(target)
            
            # Harvest emails from public sources
            results['emails_found'] = self.harvest_emails(target)
            
            # Use Hunter.io API for advanced email discovery
            if config.get('use_hunter_api', True):
                hunter_key = config.get('hunter_api_key', self.hunter_api_key)
                if hunter_key:
                    results['hunter_results'] = self.hunter_domain_search(target, hunter_key)
                    # Merge Hunter.io results with emails_found
                    if results['hunter_results'].get('emails'):
                        hunter_emails = [e['value'] for e in results['hunter_results']['emails']]
                        results['emails_found'] = sorted(list(set(results['emails_found'] + hunter_emails)))
            
            # Analyze vulnerabilities
            results['vulnerabilities'] = self.analyze_email_security(results)
            
            results['status'] = 'success'
        except Exception as e:
            results['status'] = 'error'
            results['error'] = str(e)
        
        return results
    
    def hunter_domain_search(self, domain: str, api_key: str, filters: Dict = None) -> Dict:
        """
        Search for emails using Hunter.io Domain Search API
        
        Supports advanced filtering:
        - limit: Max emails to return (default: 100)
        - offset: Pagination offset
        - type: 'personal' or 'generic'
        - seniority: 'junior', 'senior', 'executive'
        - department: 'executive', 'it', 'finance', 'management', etc.
        - verification_status: 'valid', 'accept_all', 'unknown'
        """
        result = {
            'emails': [],
            'organization': None,
            'pattern': None,
            'total': 0,
            'webmail': False,
            'disposable': False,
            'accept_all': False,
            'api_status': 'not_attempted',
            'linked_domains': []
        }
        
        try:
            url = "https://api.hunter.io/v2/domain-search"
            params = {
                'domain': domain,
                'api_key': api_key,
                'limit': 100  # Get maximum emails
            }
            
            # Add optional filters if provided
            if filters:
                if 'type' in filters:  # personal or generic
                    params['type'] = filters['type']
                if 'seniority' in filters:  # junior, senior, executive
                    params['seniority'] = filters['seniority']
                if 'department' in filters:  # it, finance, management, etc.
                    params['department'] = filters['department']
                if 'verification_status' in filters:  # valid, accept_all, unknown
                    params['verification_status'] = filters['verification_status']
                if 'offset' in filters:
                    params['offset'] = filters['offset']
            
            response = requests.get(url, params=params, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('data'):
                    domain_data = data['data']
                    
                    result['organization'] = domain_data.get('organization')
                    result['pattern'] = domain_data.get('pattern')
                    result['webmail'] = domain_data.get('webmail', False)
                    result['disposable'] = domain_data.get('disposable', False)
                    result['accept_all'] = domain_data.get('accept_all', False)
                    result['linked_domains'] = domain_data.get('linked_domains', [])
                    
                    # Get metadata
                    meta = data.get('meta', {})
                    result['total'] = meta.get('results', 0)
                    result['limit'] = meta.get('limit', 0)
                    result['offset'] = meta.get('offset', 0)
                    
                    # Extract emails with full details
                    for email_data in domain_data.get('emails', []):
                        email_info = {
                            'value': email_data.get('value'),
                            'type': email_data.get('type'),
                            'confidence': email_data.get('confidence'),
                            'first_name': email_data.get('first_name'),
                            'last_name': email_data.get('last_name'),
                            'position': email_data.get('position'),
                            'position_raw': email_data.get('position_raw'),
                            'seniority': email_data.get('seniority'),
                            'department': email_data.get('department'),
                            'linkedin': email_data.get('linkedin'),
                            'twitter': email_data.get('twitter'),
                            'phone_number': email_data.get('phone_number'),
                            'sources': len(email_data.get('sources', []))
                        }
                        
                        # Add verification info if available
                        verification = email_data.get('verification')
                        if verification:
                            email_info['verification'] = {
                                'status': verification.get('status'),
                                'date': verification.get('date')
                            }
                        
                        result['emails'].append(email_info)
                    
                    result['api_status'] = 'success'
                else:
                    result['api_status'] = 'no_data'
            
            elif response.status_code == 401:
                result['api_status'] = 'invalid_key'
            elif response.status_code == 429:
                result['api_status'] = 'rate_limited'
            elif response.status_code == 400:
                error_data = response.json()
                error_id = error_data.get('errors', [{}])[0].get('id', 'unknown')
                result['api_status'] = f'error_{error_id}'
            else:
                result['api_status'] = f'error_{response.status_code}'
                
        except Exception as e:
            result['api_status'] = f'error: {str(e)}'
        
        return result
    
    def hunter_email_finder(self, domain: str, first_name: str, last_name: str, api_key: str) -> Dict:
        """
        Find specific email address using Hunter.io Email Finder API
        Useful when you know someone's name but not their email
        """
        result = {
            'email': None,
            'score': None,
            'first_name': first_name,
            'last_name': last_name,
            'position': None,
            'company': None,
            'sources': [],
            'verification': None,
            'api_status': 'not_attempted'
        }
        
        try:
            url = "https://api.hunter.io/v2/email-finder"
            params = {
                'domain': domain,
                'first_name': first_name,
                'last_name': last_name,
                'api_key': api_key
            }
            
            response = requests.get(url, params=params, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('data'):
                    email_data = data['data']
                    result['email'] = email_data.get('email')
                    result['score'] = email_data.get('score')
                    result['position'] = email_data.get('position')
                    result['company'] = email_data.get('company')
                    result['twitter'] = email_data.get('twitter')
                    result['linkedin_url'] = email_data.get('linkedin_url')
                    result['phone_number'] = email_data.get('phone_number')
                    
                    # Sources
                    sources = email_data.get('sources', [])
                    result['sources'] = len(sources)
                    result['source_details'] = sources[:5]  # First 5 sources
                    
                    # Verification
                    verification = email_data.get('verification')
                    if verification:
                        result['verification'] = {
                            'status': verification.get('status'),
                            'date': verification.get('date')
                        }
                    
                    result['api_status'] = 'success'
                else:
                    result['api_status'] = 'not_found'
            
            elif response.status_code == 401:
                result['api_status'] = 'invalid_key'
            elif response.status_code == 429:
                result['api_status'] = 'rate_limited'
            elif response.status_code == 451:
                result['api_status'] = 'claimed_email'  # Person requested removal
            else:
                result['api_status'] = f'error_{response.status_code}'
        
        except Exception as e:
            result['api_status'] = f'error: {str(e)}'
        
        return result
    
    def hunter_email_verifier(self, email: str, api_key: str) -> Dict:
        """Verify email address using Hunter.io API"""
        result = {
            'email': email,
            'status': None,
            'score': None,
            'disposable': None,
            'webmail': None,
            'mx_records': None,
            'smtp_server': None,
            'smtp_check': None
        }
        
        try:
            url = "https://api.hunter.io/v2/email-verifier"
            params = {
                'email': email,
                'api_key': api_key
            }
            
            response = requests.get(url, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('data'):
                    email_data = data['data']
                    result['status'] = email_data.get('status')
                    result['score'] = email_data.get('score')
                    result['disposable'] = email_data.get('disposable')
                    result['webmail'] = email_data.get('webmail')
                    result['mx_records'] = email_data.get('mx_records')
                    result['smtp_server'] = email_data.get('smtp_server')
                    result['smtp_check'] = email_data.get('smtp_check')
        
        except:
            pass
        
        return result
    
    def get_mx_records(self, domain: str) -> List[Dict]:
        """Get MX records"""
        try:
            answers = dns.resolver.resolve(domain, 'MX')
            return [
                {
                    'priority': rdata.preference,
                    'server': str(rdata.exchange).rstrip('.')
                }
                for rdata in sorted(answers, key=lambda x: x.preference)
            ]
        except Exception as e:
            return []
    
    def check_spf(self, domain: str) -> Dict:
        """Check SPF record"""
        result = {
            'exists': False,
            'record': None,
            'mechanisms': [],
            'all_mechanism': None
        }
        
        try:
            answers = dns.resolver.resolve(domain, 'TXT')
            for rdata in answers:
                txt = str(rdata).strip('"')
                if txt.startswith('v=spf1'):
                    result['exists'] = True
                    result['record'] = txt
                    
                    # Parse mechanisms
                    parts = txt.split()
                    for part in parts[1:]:
                        if part.startswith('-all') or part.startswith('~all') or part.startswith('+all') or part == '?all':
                            result['all_mechanism'] = part
                        else:
                            result['mechanisms'].append(part)
                    
                    break
        except:
            pass
        
        return result
    
    def check_dmarc(self, domain: str) -> Dict:
        """Check DMARC record"""
        result = {
            'exists': False,
            'record': None,
            'policy': None,
            'subdomain_policy': None,
            'percentage': None,
            'reporting': []
        }
        
        try:
            dmarc_domain = f"_dmarc.{domain}"
            answers = dns.resolver.resolve(dmarc_domain, 'TXT')
            
            for rdata in answers:
                txt = str(rdata).strip('"')
                if txt.startswith('v=DMARC1'):
                    result['exists'] = True
                    result['record'] = txt
                    
                    # Parse DMARC tags
                    tags = {}
                    for part in txt.split(';'):
                        part = part.strip()
                        if '=' in part:
                            key, value = part.split('=', 1)
                            tags[key.strip()] = value.strip()
                    
                    result['policy'] = tags.get('p')
                    result['subdomain_policy'] = tags.get('sp')
                    result['percentage'] = tags.get('pct', '100')
                    
                    if 'rua' in tags:
                        result['reporting'].append(('aggregate', tags['rua']))
                    if 'ruf' in tags:
                        result['reporting'].append(('forensic', tags['ruf']))
                    
                    break
        except:
            pass
        
        return result
    
    def check_dkim(self, domain: str) -> Dict:
        """Check DKIM with common selectors"""
        result = {
            'selectors_found': [],
            'selectors_tested': []
        }
        
        # Common DKIM selectors
        common_selectors = [
            'default', 'selector1', 'selector2', 'google', 'k1', 'dkim',
            'mail', 'smtp', 'email', 's1', 's2', 'mx', 'mta'
        ]
        
        for selector in common_selectors:
            result['selectors_tested'].append(selector)
            try:
                dkim_domain = f"{selector}._domainkey.{domain}"
                answers = dns.resolver.resolve(dkim_domain, 'TXT')
                
                for rdata in answers:
                    txt = str(rdata).strip('"')
                    if 'v=DKIM1' in txt or 'p=' in txt:
                        result['selectors_found'].append({
                            'selector': selector,
                            'record': txt
                        })
                        break
            except:
                continue
        
        return result
    
    def harvest_emails(self, domain: str) -> List[str]:
        """Harvest email addresses from public sources"""
        emails = set()
        
        # Pattern for email matching
        email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
        
        # Try to get emails from website
        try:
            url = f"http://{domain}"
            response = requests.get(url, timeout=10, allow_redirects=True)
            found_emails = email_pattern.findall(response.text)
            
            for email in found_emails:
                if domain in email:
                    emails.add(email.lower())
        except:
            pass
        
        # Try HTTPS
        try:
            url = f"https://{domain}"
            response = requests.get(url, timeout=10, allow_redirects=True)
            found_emails = email_pattern.findall(response.text)
            
            for email in found_emails:
                if domain in email:
                    emails.add(email.lower())
        except:
            pass
        
        return sorted(list(emails))
    
    def analyze_email_security(self, results: Dict) -> List[Dict]:
        """Analyze email security configuration"""
        vulns = []
        
        # Check SPF
        spf = results['spf']
        if not spf['exists']:
            vulns.append({
                'severity': 'high',
                'type': 'Missing SPF Record',
                'description': 'Domain does not have an SPF record',
                'recommendation': 'Implement SPF record to prevent email spoofing',
                'impact': 'Attackers can spoof emails from your domain'
            })
        elif spf['all_mechanism'] not in ['-all', '~all']:
            vulns.append({
                'severity': 'medium',
                'type': 'Weak SPF Policy',
                'description': f"SPF record uses weak 'all' mechanism: {spf['all_mechanism']}",
                'recommendation': "Use '-all' (hardfail) or '~all' (softfail)",
                'impact': 'Reduced protection against email spoofing'
            })
        
        # Check DMARC
        dmarc = results['dmarc']
        if not dmarc['exists']:
            vulns.append({
                'severity': 'high',
                'type': 'Missing DMARC Record',
                'description': 'Domain does not have a DMARC record',
                'recommendation': 'Implement DMARC with p=quarantine or p=reject',
                'impact': 'No policy enforcement for SPF/DKIM failures'
            })
        elif dmarc['policy'] == 'none':
            vulns.append({
                'severity': 'medium',
                'type': 'DMARC Policy Too Permissive',
                'description': 'DMARC policy is set to "none" (monitoring only)',
                'recommendation': 'Change policy to "quarantine" or "reject"',
                'impact': 'Email authentication failures are not blocked'
            })
        
        # Check DKIM
        dkim = results['dkim']
        if not dkim['selectors_found']:
            vulns.append({
                'severity': 'medium',
                'type': 'DKIM Not Detected',
                'description': 'No DKIM records found with common selectors',
                'recommendation': 'Implement DKIM signing for outbound emails',
                'impact': 'Reduced email authentication and deliverability'
            })
        
        # Check MX records
        if not results['mx_records']:
            vulns.append({
                'severity': 'low',
                'type': 'No MX Records',
                'description': 'Domain has no MX records configured',
                'recommendation': 'Configure MX records if email service is needed',
                'impact': 'Cannot receive emails'
            })
        
        return vulns
