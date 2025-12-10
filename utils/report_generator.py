"""
Report Generator Utility
Generates HTML and PDF reports from scan results
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict

class ReportGenerator:
    def __init__(self):
        self.template = self.get_html_template()
    
    def generate(self, data: Dict, output_format: str = 'html') -> str:
        """Generate report from scan data"""
        if output_format == 'html':
            return self.generate_html(data)
        elif output_format == 'json':
            return self.generate_json(data)
        else:
            raise ValueError(f"Unsupported format: {output_format}")
    
    def generate_html(self, data: Dict) -> str:
        """Generate HTML report"""
        output_dir = Path('reports')
        output_dir.mkdir(exist_ok=True)
        
        filename = f"{data['scan_id']}_report.html"
        filepath = output_dir / filename
        
        # Generate HTML content
        html = self.create_html_report(data)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html)
        
        return str(filepath)
    
    def generate_json(self, data: Dict) -> str:
        """Generate JSON report"""
        output_dir = Path('reports')
        output_dir.mkdir(exist_ok=True)
        
        filename = f"{data['scan_id']}_report.json"
        filepath = output_dir / filename
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        
        return str(filepath)
    
    def create_html_report(self, data: Dict) -> str:
        """Create HTML report content"""
        target = data.get('target', 'Unknown')
        timestamp = data.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        
        # Build vulnerability summary
        all_vulns = []
        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0
        
        for module_name, module_data in data.get('modules', {}).items():
            for vuln in module_data.get('vulnerabilities', []):
                vuln['module'] = module_name
                all_vulns.append(vuln)
                
                severity = vuln.get('severity', 'unknown').lower()
                if severity == 'critical':
                    critical_count += 1
                elif severity == 'high':
                    high_count += 1
                elif severity == 'medium':
                    medium_count += 1
                elif severity == 'low':
                    low_count += 1
        
        # Generate module results HTML
        modules_html = ""
        for module_name, module_data in data.get('modules', {}).items():
            if module_data.get('status') != 'success':
                continue
            
            modules_html += f"""
            <div class="module-section">
                <h3>{module_name.upper()}</h3>
                <div class="module-content">
                    {self.format_module_data(module_data)}
                </div>
            </div>
            """
        
        # Generate vulnerabilities HTML
        vulns_html = ""
        for vuln in all_vulns:
            severity = vuln.get('severity', 'unknown').lower()
            severity_class = f"severity-{severity}"
            
            vulns_html += f"""
            <div class="vuln-item {severity_class}">
                <div class="vuln-header">
                    <span class="vuln-severity">{severity.upper()}</span>
                    <span class="vuln-type">{vuln.get('type', 'Unknown')}</span>
                    <span class="vuln-module">[{vuln.get('module', 'unknown')}]</span>
                </div>
                <div class="vuln-description">{vuln.get('description', '')}</div>
                <div class="vuln-recommendation"><strong>Recommendation:</strong> {vuln.get('recommendation', 'N/A')}</div>
            </div>
            """
        
        # Fill template
        html = self.template.format(
            target=target,
            timestamp=timestamp,
            total_vulns=len(all_vulns),
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            modules_html=modules_html,
            vulns_html=vulns_html if vulns_html else "<p>No vulnerabilities detected</p>"
        )
        
        return html
    
    def format_module_data(self, data: Dict) -> str:
        """Format module data as HTML"""
        html = "<table class='data-table'>"
        
        for key, value in data.items():
            if key in ['status', 'vulnerabilities', 'target']:
                continue
            
            if isinstance(value, dict):
                html += f"<tr><td colspan='2'><strong>{key}</strong></td></tr>"
                html += self.format_dict(value)
            elif isinstance(value, list) and value:
                html += f"<tr><td colspan='2'><strong>{key}</strong></td></tr>"
                html += self.format_list(value)
            else:
                html += f"<tr><td>{key}</td><td>{value}</td></tr>"
        
        html += "</table>"
        return html
    
    def format_dict(self, d: Dict, indent: int = 1) -> str:
        """Format dictionary as HTML table rows"""
        html = ""
        for key, value in d.items():
            indent_str = "&nbsp;" * (indent * 4)
            if isinstance(value, dict):
                html += f"<tr><td>{indent_str}{key}</td><td></td></tr>"
                html += self.format_dict(value, indent + 1)
            elif isinstance(value, list):
                html += f"<tr><td>{indent_str}{key}</td><td>{len(value)} items</td></tr>"
            else:
                html += f"<tr><td>{indent_str}{key}</td><td>{value}</td></tr>"
        return html
    
    def format_list(self, lst: list) -> str:
        """Format list as HTML table rows"""
        html = ""
        for item in lst:
            if isinstance(item, dict):
                item_str = ", ".join(f"{k}: {v}" for k, v in item.items())
                html += f"<tr><td>&nbsp;&nbsp;•</td><td>{item_str}</td></tr>"
            else:
                html += f"<tr><td>&nbsp;&nbsp;•</td><td>{item}</td></tr>"
        return html
    
    def get_html_template(self) -> str:
        """Return HTML template"""
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RedHawk Security Report - {target}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Courier New', monospace; background: #1e1e1e; color: #ffffff; padding: 20px; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{ color: #00ff41; border-bottom: 2px solid #00ff41; padding-bottom: 10px; margin-bottom: 20px; }}
        h2 {{ color: #00ff41; margin-top: 30px; margin-bottom: 15px; }}
        h3 {{ color: #00ccff; margin-bottom: 10px; }}
        .info-box {{ background: #2d2d2d; padding: 15px; border-left: 4px solid #00ff41; margin-bottom: 20px; }}
        .stats {{ display: flex; gap: 20px; margin-bottom: 30px; }}
        .stat-box {{ background: #2d2d2d; padding: 15px; border-radius: 5px; flex: 1; text-align: center; }}
        .stat-number {{ font-size: 32px; font-weight: bold; margin-bottom: 5px; }}
        .severity-critical {{ color: #ff0000; }}
        .severity-high {{ color: #ff6600; }}
        .severity-medium {{ color: #ffaa00; }}
        .severity-low {{ color: #ffff00; }}
        .module-section {{ background: #2d2d2d; padding: 20px; margin-bottom: 20px; border-radius: 5px; }}
        .module-content {{ margin-top: 15px; }}
        .data-table {{ width: 100%; border-collapse: collapse; }}
        .data-table td {{ padding: 8px; border-bottom: 1px solid #444; }}
        .data-table td:first-child {{ font-weight: bold; width: 30%; }}
        .vuln-item {{ background: #2d2d2d; padding: 15px; margin-bottom: 15px; border-radius: 5px; border-left: 4px solid; }}
        .vuln-item.severity-critical {{ border-left-color: #ff0000; }}
        .vuln-item.severity-high {{ border-left-color: #ff6600; }}
        .vuln-item.severity-medium {{ border-left-color: #ffaa00; }}
        .vuln-item.severity-low {{ border-left-color: #ffff00; }}
        .vuln-header {{ display: flex; gap: 15px; margin-bottom: 10px; align-items: center; }}
        .vuln-severity {{ font-weight: bold; padding: 3px 8px; border-radius: 3px; font-size: 12px; }}
        .severity-critical .vuln-severity {{ background: #ff0000; color: white; }}
        .severity-high .vuln-severity {{ background: #ff6600; color: white; }}
        .severity-medium .vuln-severity {{ background: #ffaa00; color: black; }}
        .severity-low .vuln-severity {{ background: #ffff00; color: black; }}
        .vuln-type {{ color: #00ff41; font-weight: bold; }}
        .vuln-module {{ color: #888; font-size: 12px; }}
        .vuln-description {{ margin: 10px 0; line-height: 1.6; }}
        .vuln-recommendation {{ color: #00ccff; margin-top: 10px; padding: 10px; background: #1a1a1a; border-radius: 3px; }}
        .footer {{ margin-top: 50px; padding-top: 20px; border-top: 1px solid #444; text-align: center; color: #888; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🦅 RedHawk Security Assessment Report</h1>
        
        <div class="info-box">
            <strong>Target:</strong> {target}<br>
            <strong>Scan Date:</strong> {timestamp}<br>
            <strong>Report Generated:</strong> {timestamp}
        </div>
        
        <h2>Executive Summary</h2>
        <div class="stats">
            <div class="stat-box">
                <div class="stat-number severity-critical">{critical_count}</div>
                <div>Critical</div>
            </div>
            <div class="stat-box">
                <div class="stat-number severity-high">{high_count}</div>
                <div>High</div>
            </div>
            <div class="stat-box">
                <div class="stat-number severity-medium">{medium_count}</div>
                <div>Medium</div>
            </div>
            <div class="stat-box">
                <div class="stat-number severity-low">{low_count}</div>
                <div>Low</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">{total_vulns}</div>
                <div>Total Issues</div>
            </div>
        </div>
        
        <h2>Scan Results</h2>
        {modules_html}
        
        <h2>Vulnerabilities</h2>
        {vulns_html}
        
        <div class="footer">
            <p>Report generated by RedHawk Security Framework</p>
            <p>For authorized security testing purposes only</p>
        </div>
    </div>
</body>
</html>
        """