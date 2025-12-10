"""
DNS Reconnaissance Module
Performs comprehensive DNS enumeration and analysis
"""

import dns.resolver
import dns.zone
import dns.query
import dns.dnssec
from typing import Dict, List
import socket

class Scanner:
    def __init__(self):
        self.name = "DNS Scanner"
        self.description = "DNS enumeration, DNSSEC check, zone transfer attempts"
    
    def scan(self, target: str, config: Dict) -> Dict:
        """Main scan function"""
        results = {
            'target': target,
            'records': {},
            'dnssec': {},
            'zone_transfer': {},
            'nameservers': [],
            'vulnerabilities': []
        }
        
        try:
            # Get A records
            results['records']['A'] = self.get_a_records(target)
            
            # Get AAAA records (IPv6)
            results['records']['AAAA'] = self.get_aaaa_records(target)
            
            # Get MX records
            results['records']['MX'] = self.get_mx_records(target)
            
            # Get NS records
            results['records']['NS'] = self.get_ns_records(target)
            results['nameservers'] = results['records']['NS']
            
            # Get TXT records
            results['records']['TXT'] = self.get_txt_records(target)
            
            # Get CNAME records
            results['records']['CNAME'] = self.get_cname_records(target)
            
            # Get SOA record
            results['records']['SOA'] = self.get_soa_record(target)
            
            # Check DNSSEC
            results['dnssec'] = self.check_dnssec(target)
            
            # Check for zone transfer
            results['zone_transfer'] = self.check_zone_transfer(target, results['nameservers'])
            
            # Analyze for vulnerabilities
            results['vulnerabilities'] = self.analyze_vulnerabilities(results)
            
            results['status'] = 'success'
        except Exception as e:
            results['status'] = 'error'
            results['error'] = str(e)
        
        return results
    
    def get_a_records(self, domain: str) -> List[str]:
        """Get A records"""
        try:
            answers = dns.resolver.resolve(domain, 'A')
            return [str(rdata) for rdata in answers]
        except Exception as e:
            return []
    
    def get_aaaa_records(self, domain: str) -> List[str]:
        """Get AAAA records (IPv6)"""
        try:
            answers = dns.resolver.resolve(domain, 'AAAA')
            return [str(rdata) for rdata in answers]
        except Exception as e:
            return []
    
    def get_mx_records(self, domain: str) -> List[Dict]:
        """Get MX records"""
        try:
            answers = dns.resolver.resolve(domain, 'MX')
            return [
                {
                    'priority': rdata.preference,
                    'server': str(rdata.exchange).rstrip('.')
                }
                for rdata in answers
            ]
        except Exception as e:
            return []
    
    def get_ns_records(self, domain: str) -> List[str]:
        """Get NS records"""
        try:
            answers = dns.resolver.resolve(domain, 'NS')
            return [str(rdata).rstrip('.') for rdata in answers]
        except Exception as e:
            return []
    
    def get_txt_records(self, domain: str) -> List[str]:
        """Get TXT records"""
        try:
            answers = dns.resolver.resolve(domain, 'TXT')
            return [str(rdata) for rdata in answers]
        except Exception as e:
            return []
    
    def get_cname_records(self, domain: str) -> List[str]:
        """Get CNAME records"""
        try:
            answers = dns.resolver.resolve(domain, 'CNAME')
            return [str(rdata).rstrip('.') for rdata in answers]
        except Exception as e:
            return []
    
    def get_soa_record(self, domain: str) -> Dict:
        """Get SOA record"""
        try:
            answers = dns.resolver.resolve(domain, 'SOA')
            soa = answers[0]
            return {
                'mname': str(soa.mname).rstrip('.'),
                'rname': str(soa.rname).rstrip('.'),
                'serial': soa.serial,
                'refresh': soa.refresh,
                'retry': soa.retry,
                'expire': soa.expire,
                'minimum': soa.minimum
            }
        except Exception as e:
            return {}
    
    def check_dnssec(self, domain: str) -> Dict:
        """Check DNSSEC configuration"""
        result = {
            'enabled': False,
            'dnskey_found': False,
            'ds_found': False,
            'rrsig_found': False
        }
        
        try:
            # Check for DNSKEY records
            dnskey_answers = dns.resolver.resolve(domain, 'DNSKEY')
            if dnskey_answers:
                result['dnskey_found'] = True
        except:
            pass
        
        try:
            # Check for DS records
            ds_answers = dns.resolver.resolve(domain, 'DS')
            if ds_answers:
                result['ds_found'] = True
        except:
            pass
        
        try:
            # Check for RRSIG records
            rrsig_answers = dns.resolver.resolve(domain, 'RRSIG')
            if rrsig_answers:
                result['rrsig_found'] = True
        except:
            pass
        
        result['enabled'] = (result['dnskey_found'] or 
                            result['ds_found'] or 
                            result['rrsig_found'])
        
        return result
    
    def check_zone_transfer(self, domain: str, nameservers: List[str]) -> Dict:
        """Attempt DNS zone transfer"""
        result = {
            'vulnerable': False,
            'nameservers_tested': [],
            'successful_transfers': []
        }
        
        for ns in nameservers:
            result['nameservers_tested'].append(ns)
            try:
                # Resolve nameserver to IP
                ns_ip = socket.gethostbyname(ns)
                
                # Attempt zone transfer
                zone = dns.zone.from_xfr(
                    dns.query.xfr(ns_ip, domain, timeout=5)
                )
                
                if zone:
                    result['vulnerable'] = True
                    result['successful_transfers'].append({
                        'nameserver': ns,
                        'ip': ns_ip,
                        'records_count': len(zone.nodes)
                    })
            except Exception as e:
                continue
        
        return result
    
    def analyze_vulnerabilities(self, results: Dict) -> List[Dict]:
        """Analyze results for vulnerabilities"""
        vulns = []
        
        # Check for missing DNSSEC
        if not results['dnssec'].get('enabled', False):
            vulns.append({
                'severity': 'medium',
                'type': 'Missing DNSSEC',
                'description': 'Domain does not have DNSSEC enabled',
                'recommendation': 'Enable DNSSEC to prevent DNS spoofing attacks'
            })
        
        # Check for zone transfer vulnerability
        if results['zone_transfer'].get('vulnerable', False):
            vulns.append({
                'severity': 'high',
                'type': 'DNS Zone Transfer',
                'description': 'DNS zone transfer is allowed from external sources',
                'recommendation': 'Restrict zone transfers to authorized secondary nameservers only',
                'affected_nameservers': results['zone_transfer']['successful_transfers']
            })
        
        # Check for missing SPF/DMARC in TXT records
        txt_records = results['records'].get('TXT', [])
        has_spf = any('v=spf1' in str(record).lower() for record in txt_records)
        has_dmarc = any('v=dmarc1' in str(record).lower() for record in txt_records)
        
        if not has_spf:
            vulns.append({
                'severity': 'medium',
                'type': 'Missing SPF Record',
                'description': 'Domain does not have SPF record configured',
                'recommendation': 'Configure SPF record to prevent email spoofing'
            })
        
        if not has_dmarc:
            vulns.append({
                'severity': 'medium',
                'type': 'Missing DMARC Record',
                'description': 'Domain does not have DMARC record configured',
                'recommendation': 'Configure DMARC record for email authentication'
            })
        
        return vulns