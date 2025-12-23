"""
RedHawk JavaScript Analyzer Module
Extract secrets, API keys, and endpoints from JavaScript files
"""

import re
import asyncio
import aiohttp
from typing import Dict, List, Set, Optional, Tuple
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import logging
import base64

logger = logging.getLogger(__name__)


@dataclass
class Secret:
    """Represents a discovered secret"""
    type: str
    value: str
    file: str
    line_number: int
    context: str
    severity: str  # critical, high, medium, low


@dataclass
class JSFile:
    """Represents a JavaScript file"""
    url: str
    size: int
    content: str
    secrets: List[Secret] = field(default_factory=list)
    endpoints: Set[str] = field(default_factory=set)
    external_urls: Set[str] = field(default_factory=set)
    comments: List[str] = field(default_factory=list)
    is_minified: bool = False
    is_webpack: bool = False
    source_map_url: Optional[str] = None


@dataclass
class JSAnalysisResult:
    """Results from JavaScript analysis"""
    js_files: List[JSFile]
    total_secrets: int = 0
    total_endpoints: int = 0
    critical_findings: List[str] = field(default_factory=list)


class JSAnalyzer:
    """
    JavaScript Analysis Module
    
    Analyzes JavaScript files to extract:
    - API keys and secrets
    - Hardcoded credentials
    - API endpoints
    - External URLs
    - Source maps
    """
    
    def __init__(self, target: str, config: Dict = None):
        self.target = target.rstrip('/')
        self.config = config or {}
        self.session: Optional[aiohttp.ClientSession] = None
        
        # Patterns for secret detection
        self.secret_patterns = {
            'aws_access_key': {
                'pattern': r'AKIA[0-9A-Z]{16}',
                'severity': 'critical',
                'description': 'AWS Access Key'
            },
            'aws_secret_key': {
                'pattern': r'aws[_-]?secret[_-]?(?:access[_-]?)?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9/+=]{40})["\']',
                'severity': 'critical',
                'description': 'AWS Secret Key'
            },
            'google_api_key': {
                'pattern': r'AIza[0-9A-Za-z\\-_]{35}',
                'severity': 'high',
                'description': 'Google API Key'
            },
            'google_oauth': {
                'pattern': r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
                'severity': 'high',
                'description': 'Google OAuth Client ID'
            },
            'github_token': {
                'pattern': r'ghp_[a-zA-Z0-9]{36}',
                'severity': 'critical',
                'description': 'GitHub Personal Access Token'
            },
            'slack_token': {
                'pattern': r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32}',
                'severity': 'high',
                'description': 'Slack Token'
            },
            'stripe_key': {
                'pattern': r'sk_live_[0-9a-zA-Z]{24}',
                'severity': 'critical',
                'description': 'Stripe Live Secret Key'
            },
            'mailgun_api': {
                'pattern': r'key-[0-9a-zA-Z]{32}',
                'severity': 'high',
                'description': 'Mailgun API Key'
            },
            'twilio_api': {
                'pattern': r'SK[a-z0-9]{32}',
                'severity': 'high',
                'description': 'Twilio API Key'
            },
            'private_key': {
                'pattern': r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',
                'severity': 'critical',
                'description': 'Private Key'
            },
            'api_key_generic': {
                'pattern': r'api[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']',
                'severity': 'medium',
                'description': 'Generic API Key'
            },
            'secret_generic': {
                'pattern': r'secret["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-!@#$%^&*()+=]{16,})["\']',
                'severity': 'medium',
                'description': 'Generic Secret'
            },
            'password': {
                'pattern': r'password["\']?\s*[:=]\s*["\']([^"\']{8,})["\']',
                'severity': 'high',
                'description': 'Hardcoded Password'
            },
            'jwt_token': {
                'pattern': r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',
                'severity': 'high',
                'description': 'JWT Token'
            },
            'basic_auth': {
                'pattern': r'basic\s+[a-zA-Z0-9+/]+=*',
                'severity': 'high',
                'description': 'Basic Auth Credentials'
            }
        }
        
        # Patterns for endpoint detection
        self.endpoint_patterns = [
            r'["\']/(api|v\d+|rest|graphql)/[a-zA-Z0-9/_-]+["\']',
            r'["\']https?://[a-zA-Z0-9.-]+/[a-zA-Z0-9/_-]+["\']',
            r'fetch\(["\']([^"\']+)["\']',
            r'axios\.[a-z]+\(["\']([^"\']+)["\']',
            r'\.get\(["\']([^"\']+)["\']',
            r'\.post\(["\']([^"\']+)["\']',
            r'\.put\(["\']([^"\']+)["\']',
            r'\.delete\(["\']([^"\']+)["\']',
        ]
        
        # Common JS file locations
        self.common_js_paths = [
            '/js/', '/javascript/', '/static/js/', '/assets/js/',
            '/dist/', '/build/', '/webpack/', '/bundle/',
            '/scripts/', '/app/', '/src/'
        ]
    
    async def __aenter__(self):
        timeout = aiohttp.ClientTimeout(total=30)
        self.session = aiohttp.ClientSession(timeout=timeout)
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def analyze(self) -> JSAnalysisResult:
        """
        Main analysis function
        
        Returns:
            JSAnalysisResult with all findings
        """
        logger.info(f"Starting JavaScript analysis for {self.target}")
        
        # 1. Discover JavaScript files
        js_urls = await self._discover_js_files()
        logger.info(f"Found {len(js_urls)} JavaScript files")
        
        # 2. Analyze each file
        js_files = []
        for url in js_urls:
            try:
                js_file = await self._analyze_file(url)
                if js_file:
                    js_files.append(js_file)
            except Exception as e:
                logger.error(f"Error analyzing {url}: {e}")
        
        # 3. Compile results
        result = JSAnalysisResult(js_files=js_files)
        result.total_secrets = sum(len(f.secrets) for f in js_files)
        result.total_endpoints = sum(len(f.endpoints) for f in js_files)
        
        # 4. Generate critical findings
        result.critical_findings = self._generate_findings(js_files)
        
        logger.info(f"Analysis complete. Found {result.total_secrets} secrets, "
                   f"{result.total_endpoints} endpoints")
        
        return result
    
    async def _discover_js_files(self) -> Set[str]:
        """Discover JavaScript files on the target"""
        js_urls = set()
        
        # 1. Crawl main page for <script> tags
        main_page_js = await self._extract_js_from_html(self.target)
        js_urls.update(main_page_js)
        
        # 2. Check common JS locations
        for path in self.common_js_paths:
            url = urljoin(self.target, path)
            try:
                async with self.session.get(url) as response:
                    if response.status == 200:
                        # Try to list directory or find JS files
                        text = await response.text()
                        found_js = self._extract_js_urls_from_text(text, url)
                        js_urls.update(found_js)
            except Exception:
                pass
        
        # 3. Common file names
        common_files = [
            'app.js', 'main.js', 'bundle.js', 'vendor.js',
            'app.min.js', 'main.min.js', 'bundle.min.js',
            'application.js', 'scripts.js', 'jquery.js'
        ]
        
        for filename in common_files:
            for path in self.common_js_paths:
                url = urljoin(self.target, path + filename)
                if await self._check_url_exists(url):
                    js_urls.add(url)
        
        return js_urls
    
    async def _extract_js_from_html(self, url: str) -> Set[str]:
        """Extract JavaScript URLs from HTML page"""
        js_urls = set()
        
        try:
            async with self.session.get(url) as response:
                if response.status == 200:
                    html = await response.text()
                    soup = BeautifulSoup(html, 'html.parser')
                    
                    # Find <script src="...">
                    for script in soup.find_all('script', src=True):
                        js_url = urljoin(url, script['src'])
                        js_urls.add(js_url)
        
        except Exception as e:
            logger.debug(f"Error extracting JS from {url}: {e}")
        
        return js_urls
    
    def _extract_js_urls_from_text(self, text: str, base_url: str) -> Set[str]:
        """Extract JS URLs from text content"""
        js_urls = set()
        
        # Find .js files
        pattern = r'["\']([^"\']*\.js(?:\?[^"\']*)?)["\']'
        matches = re.findall(pattern, text)
        
        for match in matches:
            js_url = urljoin(base_url, match)
            js_urls.add(js_url)
        
        return js_urls
    
    async def _check_url_exists(self, url: str) -> bool:
        """Check if URL exists"""
        try:
            async with self.session.head(url) as response:
                return response.status == 200
        except Exception:
            return False
    
    async def _analyze_file(self, url: str) -> Optional[JSFile]:
        """Analyze single JavaScript file"""
        try:
            async with self.session.get(url) as response:
                if response.status != 200:
                    return None
                
                content = await response.text()
                
                js_file = JSFile(
                    url=url,
                    size=len(content),
                    content=content
                )
                
                # Detect file characteristics
                js_file.is_minified = self._is_minified(content)
                js_file.is_webpack = 'webpack' in content.lower()
                js_file.source_map_url = self._find_source_map(content)
                
                # Extract secrets
                js_file.secrets = self._extract_secrets(content, url)
                
                # Extract endpoints
                js_file.endpoints = self._extract_endpoints(content)
                
                # Extract external URLs
                js_file.external_urls = self._extract_external_urls(content)
                
                # Extract comments
                js_file.comments = self._extract_comments(content)
                
                return js_file
        
        except Exception as e:
            logger.error(f"Error analyzing file {url}: {e}")
            return None
    
    def _is_minified(self, content: str) -> bool:
        """Check if JavaScript is minified"""
        lines = content.split('\n')
        if len(lines) < 10:
            return False
        
        # Check average line length
        avg_length = sum(len(line) for line in lines[:10]) / 10
        return avg_length > 200
    
    def _find_source_map(self, content: str) -> Optional[str]:
        """Find source map URL"""
        pattern = r'//[#@]\s*sourceMappingURL=([^\s]+)'
        match = re.search(pattern, content)
        return match.group(1) if match else None
    
    def _extract_secrets(self, content: str, file_url: str) -> List[Secret]:
        """Extract secrets from JavaScript content"""
        secrets = []
        lines = content.split('\n')
        
        for secret_type, pattern_info in self.secret_patterns.items():
            pattern = pattern_info['pattern']
            severity = pattern_info['severity']
            description = pattern_info['description']
            
            for line_num, line in enumerate(lines, 1):
                matches = re.finditer(pattern, line, re.IGNORECASE)
                
                for match in matches:
                    # Get context (surrounding text)
                    start = max(0, match.start() - 20)
                    end = min(len(line), match.end() + 20)
                    context = line[start:end]
                    
                    secret = Secret(
                        type=description,
                        value=match.group(0),
                        file=file_url,
                        line_number=line_num,
                        context=context,
                        severity=severity
                    )
                    
                    secrets.append(secret)
        
        return secrets
    
    def _extract_endpoints(self, content: str) -> Set[str]:
        """Extract API endpoints from JavaScript"""
        endpoints = set()
        
        for pattern in self.endpoint_patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0] if match else ''
                
                # Clean and validate endpoint
                endpoint = match.strip('\'"')
                if endpoint and len(endpoint) > 3:
                    endpoints.add(endpoint)
        
        return endpoints
    
    def _extract_external_urls(self, content: str) -> Set[str]:
        """Extract external URLs"""
        urls = set()
        
        pattern = r'https?://[a-zA-Z0-9.-]+(?:/[^\s"\'>]*)?'
        matches = re.findall(pattern, content)
        
        for url in matches:
            # Exclude own domain
            parsed = urlparse(url)
            target_parsed = urlparse(self.target)
            
            if parsed.netloc != target_parsed.netloc:
                urls.add(url)
        
        return urls
    
    def _extract_comments(self, content: str) -> List[str]:
        """Extract comments from JavaScript"""
        comments = []
        
        # Single-line comments
        single_line = re.findall(r'//(.+)$', content, re.MULTILINE)
        comments.extend(single_line)
        
        # Multi-line comments
        multi_line = re.findall(r'/\*(.+?)\*/', content, re.DOTALL)
        comments.extend(multi_line)
        
        return [c.strip() for c in comments if c.strip()]
    
    def _generate_findings(self, js_files: List[JSFile]) -> List[str]:
        """Generate critical findings summary"""
        findings = []
        
        # Count secrets by severity
        critical = sum(1 for f in js_files for s in f.secrets if s.severity == 'critical')
        high = sum(1 for f in js_files for s in f.secrets if s.severity == 'high')
        
        if critical > 0:
            findings.append(f"CRITICAL: Found {critical} critical secrets (API keys, private keys)")
        
        if high > 0:
            findings.append(f"HIGH: Found {high} high-severity secrets")
        
        # Check for common issues
        for js_file in js_files:
            if js_file.is_minified and not js_file.source_map_url:
                findings.append(f"INFO: {js_file.url} is minified without source map")
            
            # Check for hardcoded credentials
            password_secrets = [s for s in js_file.secrets if 'password' in s.type.lower()]
            if password_secrets:
                findings.append(f"HIGH: Hardcoded credentials found in {js_file.url}")
        
        return findings
    
    def generate_report(self, result: JSAnalysisResult) -> Dict:
        """Generate comprehensive report"""
        return {
            'target': self.target,
            'total_js_files': len(result.js_files),
            'total_secrets': result.total_secrets,
            'total_endpoints': result.total_endpoints,
            'critical_findings': result.critical_findings,
            'secrets_by_severity': {
                'critical': sum(1 for f in result.js_files for s in f.secrets if s.severity == 'critical'),
                'high': sum(1 for f in result.js_files for s in f.secrets if s.severity == 'high'),
                'medium': sum(1 for f in result.js_files for s in f.secrets if s.severity == 'medium'),
                'low': sum(1 for f in result.js_files for s in f.secrets if s.severity == 'low'),
            },
            'files': [
                {
                    'url': f.url,
                    'size': f.size,
                    'is_minified': f.is_minified,
                    'secrets_count': len(f.secrets),
                    'endpoints_count': len(f.endpoints),
                    'secrets': [
                        {
                            'type': s.type,
                            'severity': s.severity,
                            'line': s.line_number,
                            'context': s.context
                        }
                        for s in f.secrets
                    ],
                    'endpoints': list(f.endpoints),
                }
                for f in result.js_files
            ]
        }


# Integration with RedHawk
async def run_js_analysis(target: str, config: Dict = None) -> Dict:
    """
    Run JavaScript analysis
    
    Usage:
        results = await run_js_analysis('https://example.com')
    """
    async with JSAnalyzer(target, config) as analyzer:
        results = await analyzer.analyze()
        return analyzer.generate_report(results)


if __name__ == '__main__':
    import sys
    import json
    
    if len(sys.argv) < 2:
        print("Usage: python js_analyzer.py <target_url>")
        sys.exit(1)
    
    target = sys.argv[1]
    
    async def main():
        results = await run_js_analysis(target)
        print(json.dumps(results, indent=2))
    
    asyncio.run(main())
