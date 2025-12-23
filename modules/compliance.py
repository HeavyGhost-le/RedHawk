"""
RedHawk Compliance Checker Module
Check compliance with security standards (GDPR, PCI DSS, HIPAA, OWASP)
"""

import asyncio
import aiohttp
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class ComplianceLevel(Enum):
    """Compliance levels"""
    COMPLIANT = "compliant"
    PARTIAL = "partial"
    NON_COMPLIANT = "non_compliant"
    UNKNOWN = "unknown"


@dataclass
class ComplianceCheck:
    """Individual compliance check"""
    check_id: str
    standard: str
    requirement: str
    description: str
    status: ComplianceLevel
    findings: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    severity: str = "medium"  # low, medium, high, critical


@dataclass
class ComplianceResult:
    """Overall compliance results"""
    checks: List[ComplianceCheck]
    by_standard: Dict[str, Dict] = field(default_factory=dict)
    overall_score: float = 0.0
    critical_issues: List[str] = field(default_factory=list)


class ComplianceChecker:
    """
    Compliance Checker Module
    
    Standards:
    - GDPR (General Data Protection Regulation)
    - PCI DSS (Payment Card Industry Data Security Standard)
    - HIPAA (Health Insurance Portability and Accountability Act)
    - OWASP Top 10
    - CIS Benchmarks
    """
    
    def __init__(self, target: str, scan_results: Dict, config: Dict = None):
        self.target = target
        self.scan_results = scan_results
        self.config = config or {}
        self.session: Optional[aiohttp.ClientSession] = None
        
        # Standards to check
        self.enabled_standards = self.config.get('standards', [
            'owasp', 'gdpr', 'pci_dss', 'hipaa'
        ])
    
    async def __aenter__(self):
        timeout = aiohttp.ClientTimeout(total=30)
        self.session = aiohttp.ClientSession(timeout=timeout)
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def check(self) -> ComplianceResult:
        """
        Run compliance checks
        
        Returns:
            ComplianceResult with all findings
        """
        logger.info(f"Starting compliance checks for {self.target}")
        
        checks = []
        
        # Run checks for each enabled standard
        if 'owasp' in self.enabled_standards:
            owasp_checks = await self._check_owasp_top10()
            checks.extend(owasp_checks)
        
        if 'gdpr' in self.enabled_standards:
            gdpr_checks = await self._check_gdpr()
            checks.extend(gdpr_checks)
        
        if 'pci_dss' in self.enabled_standards:
            pci_checks = await self._check_pci_dss()
            checks.extend(pci_checks)
        
        if 'hipaa' in self.enabled_standards:
            hipaa_checks = await self._check_hipaa()
            checks.extend(hipaa_checks)
        
        # Compile results
        result = ComplianceResult(checks=checks)
        result.by_standard = self._group_by_standard(checks)
        result.overall_score = self._calculate_score(checks)
        result.critical_issues = self._find_critical_issues(checks)
        
        logger.info(f"Compliance checks complete. Score: {result.overall_score:.1f}%")
        return result
    
    async def _check_owasp_top10(self) -> List[ComplianceCheck]:
        """Check OWASP Top 10 2021 compliance"""
        checks = []
        
        # A01:2021 – Broken Access Control
        check = ComplianceCheck(
            check_id="OWASP-A01",
            standard="OWASP Top 10 2021",
            requirement="A01: Broken Access Control",
            description="Ensure proper access controls are in place",
            status=ComplianceLevel.UNKNOWN
        )
        
        # Check from scan results
        if self._has_admin_without_auth():
            check.status = ComplianceLevel.NON_COMPLIANT
            check.findings.append("Admin panels without authentication detected")
            check.severity = "critical"
            check.recommendations.append("Implement authentication on admin interfaces")
        else:
            check.status = ComplianceLevel.COMPLIANT
        
        checks.append(check)
        
        # A02:2021 – Cryptographic Failures
        check = ComplianceCheck(
            check_id="OWASP-A02",
            standard="OWASP Top 10 2021",
            requirement="A02: Cryptographic Failures",
            description="Protect sensitive data with proper encryption",
            status=ComplianceLevel.UNKNOWN
        )
        
        ssl_results = self.scan_results.get('ssl', {})
        if ssl_results.get('weak_protocols'):
            check.status = ComplianceLevel.NON_COMPLIANT
            check.findings.append("Weak SSL/TLS protocols detected")
            check.severity = "high"
            check.recommendations.append("Disable SSLv3, TLS 1.0, and TLS 1.1")
        else:
            check.status = ComplianceLevel.COMPLIANT
        
        checks.append(check)
        
        # A03:2021 – Injection
        check = ComplianceCheck(
            check_id="OWASP-A03",
            standard="OWASP Top 10 2021",
            requirement="A03: Injection",
            description="Prevent SQL, NoSQL, OS, and LDAP injection",
            status=ComplianceLevel.PARTIAL
        )
        
        # This requires active testing (out of scope for passive scan)
        check.findings.append("Active testing required for comprehensive injection checks")
        check.recommendations.append("Use parameterized queries and input validation")
        
        checks.append(check)
        
        # A04:2021 – Insecure Design
        check = ComplianceCheck(
            check_id="OWASP-A04",
            standard="OWASP Top 10 2021",
            requirement="A04: Insecure Design",
            description="Establish secure design patterns",
            status=ComplianceLevel.PARTIAL
        )
        
        checks.append(check)
        
        # A05:2021 – Security Misconfiguration
        check = ComplianceCheck(
            check_id="OWASP-A05",
            standard="OWASP Top 10 2021",
            requirement="A05: Security Misconfiguration",
            description="Ensure secure configuration across the stack",
            status=ComplianceLevel.UNKNOWN
        )
        
        headers = self.scan_results.get('headers', {})
        missing_headers = []
        
        if not headers.get('strict-transport-security'):
            missing_headers.append("Strict-Transport-Security")
        if not headers.get('x-content-type-options'):
            missing_headers.append("X-Content-Type-Options")
        if not headers.get('x-frame-options'):
            missing_headers.append("X-Frame-Options")
        
        if missing_headers:
            check.status = ComplianceLevel.PARTIAL
            check.findings.append(f"Missing security headers: {', '.join(missing_headers)}")
            check.severity = "medium"
            check.recommendations.append("Implement all recommended security headers")
        else:
            check.status = ComplianceLevel.COMPLIANT
        
        checks.append(check)
        
        # A06:2021 – Vulnerable and Outdated Components
        check = ComplianceCheck(
            check_id="OWASP-A06",
            standard="OWASP Top 10 2021",
            requirement="A06: Vulnerable and Outdated Components",
            description="Keep all components up to date",
            status=ComplianceLevel.PARTIAL
        )
        
        check.findings.append("Component version scanning requires additional tools")
        check.recommendations.append("Regularly update all dependencies and frameworks")
        
        checks.append(check)
        
        # A07:2021 – Identification and Authentication Failures
        check = ComplianceCheck(
            check_id="OWASP-A07",
            standard="OWASP Top 10 2021",
            requirement="A07: Identification and Authentication Failures",
            description="Ensure proper authentication and session management",
            status=ComplianceLevel.PARTIAL
        )
        
        if not headers.get('set-cookie', '').get('secure'):
            check.findings.append("Cookies not marked as Secure")
            check.recommendations.append("Set Secure flag on all cookies")
        
        checks.append(check)
        
        return checks
    
    async def _check_gdpr(self) -> List[ComplianceCheck]:
        """Check GDPR compliance"""
        checks = []
        
        # Check for cookie consent
        check = ComplianceCheck(
            check_id="GDPR-01",
            standard="GDPR",
            requirement="Cookie Consent",
            description="Obtain consent before setting non-essential cookies",
            status=ComplianceLevel.UNKNOWN
        )
        
        try:
            async with self.session.get(self.target) as response:
                html = await response.text()
                
                # Check for common cookie consent implementations
                if any(x in html.lower() for x in ['cookie consent', 'cookie banner', 'gdpr']):
                    check.status = ComplianceLevel.COMPLIANT
                    check.findings.append("Cookie consent mechanism detected")
                else:
                    check.status = ComplianceLevel.NON_COMPLIANT
                    check.findings.append("No cookie consent mechanism found")
                    check.severity = "high"
                    check.recommendations.append("Implement cookie consent banner")
        except Exception:
            pass
        
        checks.append(check)
        
        # Check for privacy policy
        check = ComplianceCheck(
            check_id="GDPR-02",
            standard="GDPR",
            requirement="Privacy Policy",
            description="Maintain accessible privacy policy",
            status=ComplianceLevel.UNKNOWN
        )
        
        privacy_urls = ['/privacy', '/privacy-policy', '/legal/privacy']
        found_privacy = False
        
        for url in privacy_urls:
            try:
                full_url = self.target.rstrip('/') + url
                async with self.session.head(full_url) as response:
                    if response.status == 200:
                        found_privacy = True
                        break
            except Exception:
                pass
        
        if found_privacy:
            check.status = ComplianceLevel.COMPLIANT
            check.findings.append("Privacy policy page found")
        else:
            check.status = ComplianceLevel.NON_COMPLIANT
            check.findings.append("No privacy policy page found")
            check.severity = "high"
            check.recommendations.append("Create and link to privacy policy")
        
        checks.append(check)
        
        # Check for data encryption (HTTPS)
        check = ComplianceCheck(
            check_id="GDPR-03",
            standard="GDPR",
            requirement="Data Encryption",
            description="Encrypt data in transit",
            status=ComplianceLevel.UNKNOWN
        )
        
        if self.target.startswith('https://'):
            check.status = ComplianceLevel.COMPLIANT
            check.findings.append("HTTPS in use")
        else:
            check.status = ComplianceLevel.NON_COMPLIANT
            check.findings.append("Not using HTTPS")
            check.severity = "critical"
            check.recommendations.append("Implement HTTPS site-wide")
        
        checks.append(check)
        
        return checks
    
    async def _check_pci_dss(self) -> List[ComplianceCheck]:
        """Check PCI DSS compliance"""
        checks = []
        
        # Requirement 4: Encrypt transmission of cardholder data
        check = ComplianceCheck(
            check_id="PCI-4.1",
            standard="PCI DSS",
            requirement="4.1: Use strong cryptography for cardholder data",
            description="Encrypt transmission of cardholder data across open networks",
            status=ComplianceLevel.UNKNOWN
        )
        
        ssl_results = self.scan_results.get('ssl', {})
        if ssl_results.get('tls_1_2_supported') or ssl_results.get('tls_1_3_supported'):
            check.status = ComplianceLevel.COMPLIANT
            check.findings.append("Strong TLS protocols in use")
        else:
            check.status = ComplianceLevel.NON_COMPLIANT
            check.findings.append("Modern TLS protocols not detected")
            check.severity = "critical"
            check.recommendations.append("Enable TLS 1.2 or higher")
        
        checks.append(check)
        
        # Requirement 6: Develop secure systems
        check = ComplianceCheck(
            check_id="PCI-6.5",
            standard="PCI DSS",
            requirement="6.5: Address common coding vulnerabilities",
            description="Protect against common web application vulnerabilities",
            status=ComplianceLevel.PARTIAL
        )
        
        headers = self.scan_results.get('headers', {})
        if headers.get('x-content-type-options') and headers.get('x-frame-options'):
            check.status = ComplianceLevel.PARTIAL
            check.findings.append("Some security headers implemented")
        else:
            check.status = ComplianceLevel.NON_COMPLIANT
            check.findings.append("Missing critical security headers")
            check.severity = "high"
        
        checks.append(check)
        
        return checks
    
    async def _check_hipaa(self) -> List[ComplianceCheck]:
        """Check HIPAA compliance basics"""
        checks = []
        
        # Encryption at rest and in transit
        check = ComplianceCheck(
            check_id="HIPAA-01",
            standard="HIPAA",
            requirement="Encryption",
            description="Encrypt ePHI at rest and in transit",
            status=ComplianceLevel.UNKNOWN
        )
        
        if self.target.startswith('https://'):
            check.status = ComplianceLevel.PARTIAL
            check.findings.append("HTTPS in use for data in transit")
            check.recommendations.append("Ensure encryption at rest is also implemented")
        else:
            check.status = ComplianceLevel.NON_COMPLIANT
            check.findings.append("HTTPS not in use")
            check.severity = "critical"
            check.recommendations.append("Implement HTTPS immediately")
        
        checks.append(check)
        
        # Access controls
        check = ComplianceCheck(
            check_id="HIPAA-02",
            standard="HIPAA",
            requirement="Access Controls",
            description="Implement proper access controls for ePHI",
            status=ComplianceLevel.PARTIAL
        )
        
        check.findings.append("Access control assessment requires additional testing")
        check.recommendations.append("Implement role-based access control (RBAC)")
        check.recommendations.append("Ensure audit logs are maintained")
        
        checks.append(check)
        
        return checks
    
    def _has_admin_without_auth(self) -> bool:
        """Check if admin panels exist without authentication"""
        content_discovery = self.scan_results.get('content_discovery', {})
        if content_discovery:
            for item in content_discovery.get('discovered', []):
                if 'admin' in item.get('url', '').lower():
                    if item.get('status') == 200:
                        return True
        return False
    
    def _group_by_standard(self, checks: List[ComplianceCheck]) -> Dict:
        """Group checks by standard"""
        by_standard = {}
        
        for check in checks:
            standard = check.standard
            if standard not in by_standard:
                by_standard[standard] = {
                    'total': 0,
                    'compliant': 0,
                    'partial': 0,
                    'non_compliant': 0,
                    'unknown': 0
                }
            
            by_standard[standard]['total'] += 1
            
            if check.status == ComplianceLevel.COMPLIANT:
                by_standard[standard]['compliant'] += 1
            elif check.status == ComplianceLevel.PARTIAL:
                by_standard[standard]['partial'] += 1
            elif check.status == ComplianceLevel.NON_COMPLIANT:
                by_standard[standard]['non_compliant'] += 1
            else:
                by_standard[standard]['unknown'] += 1
        
        return by_standard
    
    def _calculate_score(self, checks: List[ComplianceCheck]) -> float:
        """Calculate overall compliance score"""
        if not checks:
            return 0.0
        
        points = 0
        max_points = len(checks)
        
        for check in checks:
            if check.status == ComplianceLevel.COMPLIANT:
                points += 1
            elif check.status == ComplianceLevel.PARTIAL:
                points += 0.5
        
        return (points / max_points) * 100
    
    def _find_critical_issues(self, checks: List[ComplianceCheck]) -> List[str]:
        """Find critical compliance issues"""
        issues = []
        
        for check in checks:
            if check.severity == 'critical' and check.status == ComplianceLevel.NON_COMPLIANT:
                issues.append(f"{check.check_id}: {check.requirement}")
        
        return issues
    
    def generate_report(self, result: ComplianceResult) -> Dict:
        """Generate compliance report"""
        return {
            'target': self.target,
            'overall_score': f"{result.overall_score:.1f}%",
            'critical_issues': result.critical_issues,
            'by_standard': result.by_standard,
            'total_checks': len(result.checks),
            'checks': [
                {
                    'id': c.check_id,
                    'standard': c.standard,
                    'requirement': c.requirement,
                    'status': c.status.value,
                    'severity': c.severity,
                    'findings': c.findings,
                    'recommendations': c.recommendations
                }
                for c in result.checks
            ]
        }


# Integration with RedHawk
async def run_compliance_check(target: str, scan_results: Dict, config: Dict = None) -> Dict:
    """
    Run compliance checks
    
    Usage:
        config = {'standards': ['owasp', 'gdpr', 'pci_dss']}
        results = await run_compliance_check('https://example.com', scan_results, config)
    """
    async with ComplianceChecker(target, scan_results, config) as checker:
        results = await checker.check()
        return checker.generate_report(results)


if __name__ == '__main__':
    import sys
    import json
    
    if len(sys.argv) < 2:
        print("Usage: python compliance.py <target_url>")
        sys.exit(1)
    
    target = sys.argv[1]
    
    # Mock scan results for testing
    mock_results = {
        'ssl': {'tls_1_2_supported': True},
        'headers': {
            'strict-transport-security': True,
            'x-content-type-options': True,
            'x-frame-options': True
        }
    }
    
    async def main():
        results = await run_compliance_check(target, mock_results)
        print(json.dumps(results, indent=2))
    
    asyncio.run(main())
