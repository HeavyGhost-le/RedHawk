"""
SSL/TLS Analysis Module
Analyzes SSL certificates and configuration
"""

import ssl
import socket
from datetime import datetime
from typing import Dict, List
import OpenSSL
import warnings

# Suppress SSL warnings (expected for security scanning)
warnings.filterwarnings('ignore', message='Unverified HTTPS request')
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Scanner:
    def __init__(self):
        self.name = "SSL Scanner"
        self.description = "SSL/TLS certificate and configuration analysis"
    
    def scan(self, target: str, config: Dict) -> Dict:
        """Main scan function"""
        results = {
            'target': target,
            'certificates': [],
            'protocol_versions': {},
            'cipher_suites': [],
            'vulnerabilities': []
        }
        
        try:
            # Get certificate info
            cert_info = self.get_certificate_info(target)
            if cert_info:
                results['certificates'].append(cert_info)
            
            # Test SSL/TLS versions
            results['protocol_versions'] = self.test_ssl_versions(target)
            
            # Get cipher suites
            results['cipher_suites'] = self.get_cipher_suites(target)
            
            # Analyze for vulnerabilities
            results['vulnerabilities'] = self.analyze_ssl_security(results)
            
            results['status'] = 'success'
        except Exception as e:
            results['status'] = 'error'
            results['error'] = str(e)
        
        return results
    
    def get_certificate_info(self, hostname: str, port: int = 443) -> Dict:
        """Get SSL certificate information"""
        try:
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    cert_dict = ssock.getpeercert()
                    
                    # Parse with OpenSSL for more details
                    x509 = OpenSSL.crypto.load_certificate(
                        OpenSSL.crypto.FILETYPE_ASN1, cert_der
                    )
                    
                    # Extract information
                    cert_info = {
                        'subject': {k.decode('utf-8') if isinstance(k, bytes) else k: 
                                   v.decode('utf-8') if isinstance(v, bytes) else v 
                                   for k, v in dict(x509.get_subject().get_components()).items()},
                        'issuer': {k.decode('utf-8') if isinstance(k, bytes) else k: 
                                  v.decode('utf-8') if isinstance(v, bytes) else v 
                                  for k, v in dict(x509.get_issuer().get_components()).items()},
                        'version': x509.get_version(),
                        'serial_number': str(x509.get_serial_number()),
                        'not_before': self.parse_asn1_time(x509.get_notBefore()),
                        'not_after': self.parse_asn1_time(x509.get_notAfter()),
                        'signature_algorithm': x509.get_signature_algorithm().decode() if isinstance(x509.get_signature_algorithm(), bytes) else str(x509.get_signature_algorithm()),
                        'san': self.get_san_from_cert(cert_dict),
                        'key_size': x509.get_pubkey().bits()
                    }
                    
                    # Check if expired or expiring soon
                    not_after = datetime.strptime(
                        cert_info['not_after'], '%Y-%m-%d %H:%M:%S'
                    )
                    days_until_expiry = (not_after - datetime.now()).days
                    cert_info['days_until_expiry'] = days_until_expiry
                    cert_info['expired'] = days_until_expiry < 0
                    cert_info['expiring_soon'] = 0 < days_until_expiry < 30
                    
                    return cert_info
        except Exception as e:
            return {'error': str(e)}
    
    def parse_asn1_time(self, asn1_time):
        """Parse ASN1 time format"""
        try:
            time_str = asn1_time.decode('ascii')
            # Format: YYYYMMDDHHMMSSZ
            if len(time_str) == 15 and time_str.endswith('Z'):
                dt = datetime.strptime(time_str, '%Y%m%d%H%M%SZ')
                return dt.strftime('%Y-%m-%d %H:%M:%S')
        except:
            return str(asn1_time)
    
    def get_san_from_cert(self, cert_dict: Dict) -> List[str]:
        """Extract Subject Alternative Names"""
        san_list = []
        
        if 'subjectAltName' in cert_dict:
            for san_type, san_value in cert_dict['subjectAltName']:
                if san_type == 'DNS':
                    san_list.append(san_value)
        
        return san_list
    
    def test_ssl_versions(self, hostname: str, port: int = 443) -> Dict:
        """Test which SSL/TLS versions are supported"""
        versions = {
            'SSLv2': False,
            'SSLv3': False,
            'TLSv1.0': False,
            'TLSv1.1': False,
            'TLSv1.2': False,
            'TLSv1.3': False
        }
        
        protocol_map = {
            'TLSv1.0': ssl.PROTOCOL_TLSv1,
            'TLSv1.1': ssl.PROTOCOL_TLSv1_1,
            'TLSv1.2': ssl.PROTOCOL_TLSv1_2,
        }
        
        # Add TLS 1.3 if available
        if hasattr(ssl, 'PROTOCOL_TLS_CLIENT'):
            protocol_map['TLSv1.3'] = ssl.PROTOCOL_TLS_CLIENT
        
        for version_name, protocol in protocol_map.items():
            try:
                context = ssl.SSLContext(protocol)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((hostname, port), timeout=5) as sock:
                    with context.wrap_socket(sock) as ssock:
                        versions[version_name] = True
            except:
                versions[version_name] = False
        
        return versions
    
    def get_cipher_suites(self, hostname: str, port: int = 443) -> List[str]:
        """Get supported cipher suites"""
        ciphers = []
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cipher = ssock.cipher()
                    if cipher:
                        ciphers.append({
                            'name': cipher[0],
                            'protocol': cipher[1],
                            'bits': cipher[2]
                        })
        except:
            pass
        
        return ciphers
    
    def analyze_ssl_security(self, results: Dict) -> List[Dict]:
        """Analyze SSL/TLS configuration for vulnerabilities"""
        vulns = []
        
        # Check for old/insecure protocol versions
        protocols = results.get('protocol_versions', {})
        
        if protocols.get('SSLv2'):
            vulns.append({
                'severity': 'critical',
                'type': 'SSLv2 Enabled',
                'description': 'Server supports the insecure SSLv2 protocol',
                'recommendation': 'Disable SSLv2 immediately',
                'cve': 'CVE-2016-0800'
            })
        
        if protocols.get('SSLv3'):
            vulns.append({
                'severity': 'high',
                'type': 'SSLv3 Enabled',
                'description': 'Server supports the insecure SSLv3 protocol (POODLE)',
                'recommendation': 'Disable SSLv3',
                'cve': 'CVE-2014-3566'
            })
        
        if protocols.get('TLSv1.0'):
            vulns.append({
                'severity': 'medium',
                'type': 'TLS 1.0 Enabled',
                'description': 'Server supports deprecated TLS 1.0',
                'recommendation': 'Disable TLS 1.0, use TLS 1.2 or higher'
            })
        
        if protocols.get('TLSv1.1'):
            vulns.append({
                'severity': 'medium',
                'type': 'TLS 1.1 Enabled',
                'description': 'Server supports deprecated TLS 1.1',
                'recommendation': 'Disable TLS 1.1, use TLS 1.2 or higher'
            })
        
        # Check certificate
        if results.get('certificates'):
            cert = results['certificates'][0]
            
            if cert.get('expired'):
                vulns.append({
                    'severity': 'critical',
                    'type': 'Expired Certificate',
                    'description': 'SSL certificate has expired',
                    'recommendation': 'Renew SSL certificate immediately'
                })
            
            elif cert.get('expiring_soon'):
                vulns.append({
                    'severity': 'medium',
                    'type': 'Certificate Expiring Soon',
                    'description': f"Certificate expires in {cert['days_until_expiry']} days",
                    'recommendation': 'Renew SSL certificate'
                })
            
            # Check key size
            key_size = cert.get('key_size', 0)
            if key_size < 2048:
                vulns.append({
                    'severity': 'high',
                    'type': 'Weak Key Size',
                    'description': f'Certificate uses {key_size}-bit key (minimum 2048 required)',
                    'recommendation': 'Use at least 2048-bit RSA or 256-bit ECC keys'
                })
        
        return vulns