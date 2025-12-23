"""
RedHawk Content Discovery Module
Intelligent directory and file discovery with technology-specific wordlists
"""

import asyncio
import aiohttp
from typing import Dict, List, Set, Optional
from dataclasses import dataclass, field
from urllib.parse import urljoin
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class DiscoveredContent:
    """Represents discovered content"""
    url: str
    status_code: int
    content_type: str
    content_length: int
    response_time: float
    category: str  # backup, admin, api, config, sensitive
    risk_level: str  # critical, high, medium, low


@dataclass
class ContentDiscoveryResult:
    """Results from content discovery"""
    discovered: List[DiscoveredContent]
    total_requests: int = 0
    total_found: int = 0
    critical_findings: List[str] = field(default_factory=list)


class ContentDiscovery:
    """
    Intelligent Content Discovery Module
    
    Features:
    - Technology-specific wordlists
    - Backup file detection
    - Git repository exposure
    - Admin panel discovery
    - API documentation pages
    - Config file detection
    """
    
    def __init__(self, target: str, config: Dict = None):
        self.target = target.rstrip('/')
        self.config = config or {}
        self.session: Optional[aiohttp.ClientSession] = None
        
        # Wordlists
        self.common_files = [
            # Admin panels
            'admin', 'admin.php', 'admin/', 'administrator',
            'cpanel', 'wp-admin', 'wp-login.php',
            'phpmyadmin', 'pma', 'mysql',
            'dashboard', 'panel', 'console',
            
            # API documentation
            'api', 'api/', 'api/docs', 'api-docs',
            'swagger', 'swagger.json', 'swagger.yaml', 'swagger-ui',
            'openapi.json', 'docs', 'documentation',
            
            # Config files
            'config', 'config.php', 'config.json', 'config.yaml',
            'configuration', 'settings', 'settings.php',
            '.env', '.env.local', '.env.production',
            'web.config', 'app.config', 'database.yml',
            
            # Backup files
            'backup', 'backups', 'backup.zip', 'backup.tar.gz',
            'db_backup', 'database.sql', 'dump.sql',
            'old', 'bak', 'copy',
            
            # Version control
            '.git', '.git/', '.git/config', '.gitignore',
            '.svn', '.hg', '.bzr',
            
            # Sensitive files
            'phpinfo.php', 'info.php', 'test.php',
            'robots.txt', 'sitemap.xml',
            'crossdomain.xml', 'clientaccesspolicy.xml',
            '.htaccess', '.htpasswd',
            
            # Common directories
            'uploads', 'upload', 'files', 'assets',
            'images', 'img', 'css', 'js',
            'includes', 'include', 'lib', 'libs',
            'src', 'source', 'dist', 'build',
            'tmp', 'temp', 'cache',
        ]
        
        # Backup extensions
        self.backup_extensions = [
            '.bak', '.backup', '.old', '.orig', '.save',
            '.swp', '.swo', '.tmp', '~',
            '.1', '.2', '.copy', '_copy',
            '.zip', '.tar', '.tar.gz', '.tgz', '.rar'
        ]
        
        # Technology-specific paths
        self.tech_specific = {
            'wordpress': [
                'wp-admin', 'wp-content', 'wp-includes',
                'wp-config.php', 'xmlrpc.php',
                'wp-json', 'wp-admin/install.php'
            ],
            'drupal': [
                'admin', 'user/login', 'node',
                'sites/default/settings.php',
                'CHANGELOG.txt', 'INSTALL.txt'
            ],
            'joomla': [
                'administrator', 'components', 'modules',
                'configuration.php', 'htaccess.txt'
            ],
            'django': [
                'admin/', 'api/', 'static/', 'media/',
                'settings.py', 'manage.py'
            ],
            'laravel': [
                'artisan', 'storage', 'public',
                '.env', 'composer.json'
            ],
            'asp_net': [
                'admin.aspx', 'login.aspx',
                'web.config', 'Global.asax',
                'bin/', 'App_Data/'
            ]
        }
    
    async def __aenter__(self):
        timeout = aiohttp.ClientTimeout(total=10)
        connector = aiohttp.TCPConnector(limit=20)
        self.session = aiohttp.ClientSession(timeout=timeout, connector=connector)
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def discover(self, technology: Optional[str] = None) -> ContentDiscoveryResult:
        """
        Main discovery function
        
        Args:
            technology: Specific technology to target (wordpress, drupal, etc.)
        
        Returns:
            ContentDiscoveryResult with findings
        """
        logger.info(f"Starting content discovery for {self.target}")
        
        discovered = []
        
        # 1. Common files and directories
        common_results = await self._discover_common()
        discovered.extend(common_results)
        
        # 2. Backup files
        backup_results = await self._discover_backups()
        discovered.extend(backup_results)
        
        # 3. Git exposure
        git_results = await self._check_git_exposure()
        discovered.extend(git_results)
        
        # 4. Technology-specific
        if technology and technology in self.tech_specific:
            tech_results = await self._discover_tech_specific(technology)
            discovered.extend(tech_results)
        
        # 5. Generate backup variations
        if discovered:
            backup_var_results = await self._discover_backup_variations(discovered)
            discovered.extend(backup_var_results)
        
        result = ContentDiscoveryResult(
            discovered=discovered,
            total_requests=len(self.common_files) * 2,  # Approximate
            total_found=len(discovered)
        )
        
        result.critical_findings = self._generate_findings(discovered)
        
        logger.info(f"Discovery complete. Found {len(discovered)} resources")
        return result
    
    async def _discover_common(self) -> List[DiscoveredContent]:
        """Discover common files and directories"""
        discovered = []
        
        tasks = []
        for path in self.common_files:
            url = urljoin(self.target, path)
            tasks.append(self._check_url(url, 'common'))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, DiscoveredContent):
                discovered.append(result)
        
        return discovered
    
    async def _discover_backups(self) -> List[DiscoveredContent]:
        """Discover backup files"""
        discovered = []
        
        # Common file names to check for backups
        base_names = ['index', 'config', 'database', 'backup', 'admin']
        
        tasks = []
        for base in base_names:
            for ext in self.backup_extensions:
                url = urljoin(self.target, base + ext)
                tasks.append(self._check_url(url, 'backup'))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, DiscoveredContent):
                discovered.append(result)
        
        return discovered
    
    async def _check_git_exposure(self) -> List[DiscoveredContent]:
        """Check for exposed .git directory"""
        discovered = []
        
        git_files = [
            '.git/config',
            '.git/HEAD',
            '.git/index',
            '.git/logs/HEAD',
            '.git/refs/heads/master',
            '.git/refs/heads/main',
        ]
        
        tasks = []
        for git_file in git_files:
            url = urljoin(self.target, git_file)
            tasks.append(self._check_url(url, 'sensitive'))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, DiscoveredContent):
                discovered.append(result)
        
        return discovered
    
    async def _discover_tech_specific(self, technology: str) -> List[DiscoveredContent]:
        """Discover technology-specific paths"""
        discovered = []
        
        paths = self.tech_specific.get(technology, [])
        
        tasks = []
        for path in paths:
            url = urljoin(self.target, path)
            tasks.append(self._check_url(url, 'tech_specific'))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, DiscoveredContent):
                discovered.append(result)
        
        return discovered
    
    async def _discover_backup_variations(self, discovered: List[DiscoveredContent]) -> List[DiscoveredContent]:
        """Create and check backup variations of discovered files"""
        new_discovered = []
        
        tasks = []
        for content in discovered[:10]:  # Limit to first 10 to avoid too many requests
            path = content.url.replace(self.target, '').lstrip('/')
            
            for ext in ['.bak', '.old', '.backup', '~']:
                url = urljoin(self.target, path + ext)
                tasks.append(self._check_url(url, 'backup'))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, DiscoveredContent):
                new_discovered.append(result)
        
        return new_discovered
    
    async def _check_url(self, url: str, category: str) -> Optional[DiscoveredContent]:
        """Check if URL exists and gather information"""
        try:
            import time
            start_time = time.time()
            
            async with self.session.get(url, allow_redirects=False) as response:
                response_time = time.time() - start_time
                
                # Consider 200, 401, 403 as "found"
                if response.status in [200, 401, 403]:
                    content_type = response.headers.get('content-type', 'unknown')
                    content_length = int(response.headers.get('content-length', 0))
                    
                    # Determine risk level
                    risk_level = self._assess_risk(url, response.status, category)
                    
                    content = DiscoveredContent(
                        url=url,
                        status_code=response.status,
                        content_type=content_type,
                        content_length=content_length,
                        response_time=response_time,
                        category=category,
                        risk_level=risk_level
                    )
                    
                    logger.info(f"Found: {url} [{response.status}] - {risk_level}")
                    return content
        
        except asyncio.TimeoutError:
            logger.debug(f"Timeout: {url}")
        except Exception as e:
            logger.debug(f"Error checking {url}: {e}")
        
        return None
    
    def _assess_risk(self, url: str, status: int, category: str) -> str:
        """Assess risk level of discovered content"""
        url_lower = url.lower()
        
        # Critical risk indicators
        if any(x in url_lower for x in ['.git/', '.env', 'config', 'backup.sql', 'database']):
            return 'critical'
        
        # High risk indicators
        if category == 'backup':
            return 'high'
        
        if any(x in url_lower for x in ['admin', 'phpinfo', '.bak', 'web.config']):
            return 'high'
        
        # Medium risk
        if category == 'api' or status == 403:
            return 'medium'
        
        # Low risk
        return 'low'
    
    def _generate_findings(self, discovered: List[DiscoveredContent]) -> List[str]:
        """Generate critical findings summary"""
        findings = []
        
        # Count by risk level
        critical = [d for d in discovered if d.risk_level == 'critical']
        high = [d for d in discovered if d.risk_level == 'high']
        
        if critical:
            findings.append(f"CRITICAL: Found {len(critical)} critical exposures")
            for c in critical[:3]:  # Show top 3
                findings.append(f"  - {c.url} [{c.status_code}]")
        
        if high:
            findings.append(f"HIGH: Found {len(high)} high-risk resources")
        
        # Check for specific issues
        git_exposed = [d for d in discovered if '.git/' in d.url]
        if git_exposed:
            findings.append("CRITICAL: Git repository exposed - source code may be accessible")
        
        env_files = [d for d in discovered if '.env' in d.url]
        if env_files:
            findings.append("CRITICAL: Environment files exposed - may contain credentials")
        
        backups = [d for d in discovered if d.category == 'backup']
        if backups:
            findings.append(f"HIGH: Found {len(backups)} backup files")
        
        admin_panels = [d for d in discovered if 'admin' in d.url.lower()]
        if admin_panels:
            findings.append(f"MEDIUM: Found {len(admin_panels)} admin panels")
        
        return findings
    
    def generate_report(self, result: ContentDiscoveryResult) -> Dict:
        """Generate comprehensive report"""
        return {
            'target': self.target,
            'total_found': result.total_found,
            'total_requests': result.total_requests,
            'critical_findings': result.critical_findings,
            'by_risk_level': {
                'critical': len([d for d in result.discovered if d.risk_level == 'critical']),
                'high': len([d for d in result.discovered if d.risk_level == 'high']),
                'medium': len([d for d in result.discovered if d.risk_level == 'medium']),
                'low': len([d for d in result.discovered if d.risk_level == 'low']),
            },
            'by_category': {
                'backup': len([d for d in result.discovered if d.category == 'backup']),
                'admin': len([d for d in result.discovered if 'admin' in d.url.lower()]),
                'config': len([d for d in result.discovered if 'config' in d.url.lower()]),
                'sensitive': len([d for d in result.discovered if d.category == 'sensitive']),
            },
            'discovered': [
                {
                    'url': d.url,
                    'status': d.status_code,
                    'size': d.content_length,
                    'type': d.content_type,
                    'category': d.category,
                    'risk': d.risk_level,
                    'response_time': f"{d.response_time:.3f}s"
                }
                for d in sorted(result.discovered, 
                              key=lambda x: {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}[x.risk_level])
            ]
        }


# Integration with RedHawk
async def run_content_discovery(target: str, technology: str = None, config: Dict = None) -> Dict:
    """
    Run content discovery scan
    
    Usage:
        results = await run_content_discovery('https://example.com', 'wordpress')
    """
    async with ContentDiscovery(target, config) as scanner:
        results = await scanner.discover(technology)
        return scanner.generate_report(results)


if __name__ == '__main__':
    import sys
    import json
    
    if len(sys.argv) < 2:
        print("Usage: python content_discovery.py <target_url> [technology]")
        print("Technologies: wordpress, drupal, joomla, django, laravel, asp_net")
        sys.exit(1)
    
    target = sys.argv[1]
    tech = sys.argv[2] if len(sys.argv) > 2 else None
    
    async def main():
        results = await run_content_discovery(target, tech)
        print(json.dumps(results, indent=2))
    
    asyncio.run(main())
