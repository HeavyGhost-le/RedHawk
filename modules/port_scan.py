"""
Port Scanning Module
Fast and efficient port scanning with service detection
"""

import socket
import concurrent.futures
from typing import Dict, List
import time

class Scanner:
    def __init__(self):
        self.name = "Port Scanner"
        self.description = "Fast port scanning with service detection"
        
        # Common ports and their services
        self.common_ports = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 465: 'SMTPS',
            587: 'SMTP', 993: 'IMAPS', 995: 'POP3S', 3306: 'MySQL', 3389: 'RDP',
            5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-Proxy',
            8443: 'HTTPS-Alt', 27017: 'MongoDB', 1433: 'MSSQL', 1521: 'Oracle'
        }
    
    def scan(self, target: str, config: Dict) -> Dict:
        """Main scan function"""
        results = {
            'target': target,
            'open_ports': [],
            'closed_ports': [],
            'filtered_ports': [],
            'statistics': {}
        }
        
        start_time = time.time()
        
        try:
            # Resolve hostname to IP
            ip = socket.gethostbyname(target)
            results['ip'] = ip
            
            # Get ports to scan
            scan_mode = config.get('modules', {}).get('port_scan', {}).get('mode', 'common')
            
            if scan_mode == 'common':
                ports = list(self.common_ports.keys())
            elif scan_mode == 'top1000':
                ports = self.get_top_ports(1000)
            elif scan_mode == 'full':
                ports = range(1, 65536)
            else:
                ports = list(self.common_ports.keys())
            
            print(f"[*] Scanning {len(ports)} ports on {target} ({ip})...")
            
            # Scan ports with threading
            open_ports = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
                futures = {
                    executor.submit(self._scan_port, ip, port): port 
                    for port in ports
                }
                
                for future in concurrent.futures.as_completed(futures):
                    port = futures[future]
                    status, banner = future.result()
                    
                    if status == 'open':
                        port_info = {
                            'port': port,
                            'service': self.common_ports.get(port, 'Unknown'),
                            'banner': banner
                        }
                        open_ports.append(port_info)
                        print(f"[+] Port {port} ({port_info['service']}) is open")
            
            results['open_ports'] = sorted(open_ports, key=lambda x: x['port'])
            results['statistics'] = {
                'total_scanned': len(ports),
                'open': len(open_ports),
                'scan_time': round(time.time() - start_time, 2)
            }
            
            # Analyze vulnerabilities
            results['vulnerabilities'] = self.analyze_open_ports(open_ports)
            
            results['status'] = 'success'
        except Exception as e:
            results['status'] = 'error'
            results['error'] = str(e)
        
        return results
    
    def _scan_port(self, ip: str, port: int) -> tuple:
        """Scan a single port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            
            banner = None
            if result == 0:
                # Try to grab banner
                try:
                    sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                except:
                    pass
                
                sock.close()
                return ('open', banner)
            else:
                sock.close()
                return ('closed', None)
        except socket.timeout:
            return ('filtered', None)
        except Exception as e:
            return ('closed', None)
    
    def get_top_ports(self, count: int) -> List[int]:
        """Get list of top N most common ports"""
        # Nmap's top 1000 ports (simplified version)
        top_ports = [
            80, 443, 22, 21, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080,
            1723, 111, 995, 993, 5900, 1025, 587, 8888, 199, 1720, 465, 548,
            113, 81, 6001, 10000, 514, 5060, 179, 1026, 2000, 8443, 8000, 32768,
            554, 26, 1433, 49152, 2001, 515, 8008, 49154, 1027, 5666, 646, 5000,
            5631, 631, 49153, 8081, 2049, 88, 79, 5800, 106, 2121, 1110, 49155,
            6000, 513, 990, 5357, 427, 49156, 543, 544, 5101, 144, 7, 389, 8009
        ]
        
        return top_ports[:count]
    
    def analyze_open_ports(self, open_ports: List[Dict]) -> List[Dict]:
        """Analyze open ports for vulnerabilities"""
        vulns = []
        
        for port_info in open_ports:
            port = port_info['port']
            service = port_info['service']
            
            # Check for dangerous ports
            if port == 23:  # Telnet
                vulns.append({
                    'severity': 'high',
                    'type': 'Insecure Protocol',
                    'port': port,
                    'service': service,
                    'description': 'Telnet transmits data in cleartext',
                    'recommendation': 'Disable Telnet and use SSH instead'
                })
            
            elif port == 21:  # FTP
                vulns.append({
                    'severity': 'medium',
                    'type': 'Insecure Protocol',
                    'port': port,
                    'service': service,
                    'description': 'FTP may transmit credentials in cleartext',
                    'recommendation': 'Use SFTP or FTPS instead'
                })
            
            elif port == 3389:  # RDP
                vulns.append({
                    'severity': 'medium',
                    'type': 'Remote Access Exposed',
                    'port': port,
                    'service': service,
                    'description': 'RDP exposed to internet increases attack surface',
                    'recommendation': 'Use VPN or restrict access by IP'
                })
            
            elif port in [3306, 5432, 1433, 27017]:  # Databases
                vulns.append({
                    'severity': 'high',
                    'type': 'Database Exposed',
                    'port': port,
                    'service': service,
                    'description': 'Database port accessible from internet',
                    'recommendation': 'Restrict database access to internal network only'
                })
            
            elif port in [8080, 8000, 8888]:  # Alt HTTP
                vulns.append({
                    'severity': 'low',
                    'type': 'Alternative HTTP Port',
                    'port': port,
                    'service': service,
                    'description': 'Alternative HTTP port may be development/admin interface',
                    'recommendation': 'Verify this service should be publicly accessible'
                })
        
        return vulns