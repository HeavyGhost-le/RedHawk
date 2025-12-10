"""
WHOIS Information Module
Retrieves domain registration and ownership information
"""

import socket
import re
from typing import Dict
from datetime import datetime

class Scanner:
    def __init__(self):
        self.name = "WHOIS Scanner"
        self.description = "Domain registration and ownership information"
        
        self.whois_servers = {
            'com': 'whois.verisign-grs.com',
            'net': 'whois.verisign-grs.com',
            'org': 'whois.pir.org',
            'info': 'whois.afilias.net',
            'biz': 'whois.biz',
            'io': 'whois.nic.io',
            'co': 'whois.nic.co',
            'uk': 'whois.nic.uk',
            'de': 'whois.denic.de',
            'fr': 'whois.afnic.fr',
        }
    
    def scan(self, target: str, config: Dict) -> Dict:
        """Main scan function"""
        results = {
            'target': target,
            'raw_data': None,
            'parsed': {},
            'privacy_protected': False
        }
        
        try:
            # Get WHOIS data
            raw_data = self.query_whois(target)
            results['raw_data'] = raw_data
            
            if raw_data:
                # Parse WHOIS data
                results['parsed'] = self.parse_whois(raw_data)
                
                # Check for privacy protection
                results['privacy_protected'] = self.check_privacy_protection(raw_data)
            
            results['status'] = 'success'
        except Exception as e:
            results['status'] = 'error'
            results['error'] = str(e)
        
        return results
    
    def query_whois(self, domain: str) -> str:
        """Query WHOIS server for domain"""
        # Get TLD
        tld = domain.split('.')[-1].lower()
        
        # Get appropriate WHOIS server
        whois_server = self.whois_servers.get(tld, 'whois.iana.org')
        
        try:
            # Connect to WHOIS server
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((whois_server, 43))
            
            # Send query
            query = f"{domain}\r\n"
            sock.send(query.encode())
            
            # Receive response
            response = b""
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                response += data
            
            sock.close()
            
            return response.decode('utf-8', errors='ignore')
        except Exception as e:
            return None
    
    def parse_whois(self, raw_data: str) -> Dict:
        """Parse WHOIS data into structured format"""
        parsed = {
            'registrar': None,
            'creation_date': None,
            'expiration_date': None,
            'updated_date': None,
            'status': [],
            'nameservers': [],
            'registrant': {},
            'admin': {},
            'tech': {}
        }
        
        lines = raw_data.split('\n')
        
        for line in lines:
            line = line.strip()
            
            if not line or line.startswith('%') or line.startswith('#'):
                continue
            
            # Registrar
            if 'registrar:' in line.lower():
                parsed['registrar'] = line.split(':', 1)[1].strip()
            
            # Dates
            if 'creation date:' in line.lower() or 'created:' in line.lower():
                parsed['creation_date'] = self.extract_date(line)
            
            if 'expiration date:' in line.lower() or 'expires:' in line.lower() or 'registry expiry date:' in line.lower():
                parsed['expiration_date'] = self.extract_date(line)
            
            if 'updated date:' in line.lower() or 'last updated:' in line.lower():
                parsed['updated_date'] = self.extract_date(line)
            
            # Status
            if 'status:' in line.lower() or 'domain status:' in line.lower():
                status = line.split(':', 1)[1].strip()
                if status:
                    parsed['status'].append(status)
            
            # Nameservers
            if 'name server:' in line.lower() or 'nserver:' in line.lower():
                ns = line.split(':', 1)[1].strip()
                if ns and ns not in parsed['nameservers']:
                    parsed['nameservers'].append(ns.lower())
        
        return parsed
    
    def extract_date(self, line: str) -> str:
        """Extract date from WHOIS line"""
        try:
            # Split on colon
            parts = line.split(':', 1)
            if len(parts) < 2:
                return None
            
            date_str = parts[1].strip()
            
            # Remove timezone info if present
            date_str = re.sub(r'[+-]\d{2}:?\d{2}$', '', date_str).strip()
            
            return date_str
        except:
            return None
    
    def check_privacy_protection(self, raw_data: str) -> bool:
        """Check if domain has privacy protection"""
        privacy_keywords = [
            'privacy', 'proxy', 'redacted', 'whoisguard', 'private',
            'protected', 'data redacted', 'not disclosed'
        ]
        
        raw_lower = raw_data.lower()
        return any(keyword in raw_lower for keyword in privacy_keywords)