"""
RedHawk OSINT (Open Source Intelligence) Module
Gather intelligence from public sources
"""

import asyncio
import aiohttp
import re
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime
import logging
import base64
import json

logger = logging.getLogger(__name__)


@dataclass
class Employee:
    """Represents an employee"""
    name: str
    position: Optional[str] = None
    email: Optional[str] = None
    linkedin: Optional[str] = None
    twitter: Optional[str] = None


@dataclass
class Repository:
    """Represents a GitHub repository"""
    name: str
    url: str
    description: str
    stars: int
    forks: int
    language: str
    last_updated: str


@dataclass
class BreachData:
    """Represents breach information"""
    service: str
    breach_date: str
    data_classes: List[str]
    verified: bool


@dataclass
class OSINTResult:
    """Results from OSINT gathering"""
    github_repos: List[Repository] = field(default_factory=list)
    breach_data: List[BreachData] = field(default_factory=list)
    employees: List[Employee] = field(default_factory=list)
    social_media: Dict = field(default_factory=dict)
    domain_info: Dict = field(default_factory=dict)
    technologies: Set[str] = field(default_factory=set)


class OSINTScanner:
    """
    OSINT Intelligence Module
    
    Features:
    - GitHub repository discovery
    - Breach database checks
    - Employee enumeration
    - Social media presence
    - Domain history
    - Technology detection
    """
    
    def __init__(self, target: str, config: Dict = None):
        self.target = target
        self.domain = self._extract_domain(target)
        self.config = config or {}
        self.session: Optional[aiohttp.ClientSession] = None
        
        # API keys from config
        self.github_token = self.config.get('github_token')
        self.hibp_api_key = self.config.get('hibp_api_key')
        self.hunter_api_key = self.config.get('hunter_api_key')
    
    def _extract_domain(self, target: str) -> str:
        """Extract domain from target"""
        from urllib.parse import urlparse
        parsed = urlparse(target if '://' in target else f'http://{target}')
        return parsed.netloc or parsed.path
    
    async def __aenter__(self):
        timeout = aiohttp.ClientTimeout(total=30)
        self.session = aiohttp.ClientSession(timeout=timeout)
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def gather(self) -> OSINTResult:
        """
        Main OSINT gathering function
        
        Returns:
            OSINTResult with all gathered intelligence
        """
        logger.info(f"Starting OSINT gathering for {self.domain}")
        
        result = OSINTResult()
        
        # Run all OSINT tasks concurrently
        tasks = [
            self._search_github(),
            self._check_breaches(),
            self._find_employees(),
            self._check_social_media(),
            self._get_domain_info(),
            self._detect_technologies()
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Unpack results
        result.github_repos = results[0] if not isinstance(results[0], Exception) else []
        result.breach_data = results[1] if not isinstance(results[1], Exception) else []
        result.employees = results[2] if not isinstance(results[2], Exception) else []
        result.social_media = results[3] if not isinstance(results[3], Exception) else {}
        result.domain_info = results[4] if not isinstance(results[4], Exception) else {}
        result.technologies = results[5] if not isinstance(results[5], Exception) else set()
        
        logger.info(f"OSINT gathering complete")
        return result
    
    async def _search_github(self) -> List[Repository]:
        """Search GitHub for related repositories"""
        repos = []
        
        if not self.github_token:
            logger.warning("GitHub token not configured, skipping GitHub search")
            return repos
        
        try:
            # Search for repositories
            search_terms = [
                self.domain.replace('.', ' '),
                self.domain.split('.')[0]
            ]
            
            for term in search_terms:
                url = f"https://api.github.com/search/repositories?q={term}&sort=stars"
                headers = {
                    'Authorization': f'token {self.github_token}',
                    'Accept': 'application/vnd.github.v3+json'
                }
                
                async with self.session.get(url, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        for item in data.get('items', [])[:5]:  # Top 5 results
                            repo = Repository(
                                name=item['full_name'],
                                url=item['html_url'],
                                description=item.get('description', ''),
                                stars=item['stargazers_count'],
                                forks=item['forks_count'],
                                language=item.get('language', 'Unknown'),
                                last_updated=item['updated_at']
                            )
                            repos.append(repo)
        
        except Exception as e:
            logger.error(f"Error searching GitHub: {e}")
        
        return repos
    
    async def _check_breaches(self) -> List[BreachData]:
        """Check HaveIBeenPwned for breaches"""
        breaches = []
        
        if not self.hibp_api_key:
            logger.warning("HIBP API key not configured, skipping breach check")
            return breaches
        
        try:
            url = f"https://haveibeenpwned.com/api/v3/breaches?domain={self.domain}"
            headers = {
                'hibp-api-key': self.hibp_api_key,
                'User-Agent': 'RedHawk Security Scanner'
            }
            
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    for item in data:
                        breach = BreachData(
                            service=item['Name'],
                            breach_date=item['BreachDate'],
                            data_classes=item['DataClasses'],
                            verified=item['IsVerified']
                        )
                        breaches.append(breach)
        
        except Exception as e:
            logger.error(f"Error checking breaches: {e}")
        
        return breaches
    
    async def _find_employees(self) -> List[Employee]:
        """Find employees through various sources"""
        employees = []
        
        # Method 1: Hunter.io (if API key available)
        if self.hunter_api_key:
            hunter_employees = await self._find_employees_hunter()
            employees.extend(hunter_employees)
        
        # Method 2: LinkedIn scraping (careful with ToS)
        # Note: This should respect LinkedIn's terms of service
        linkedin_employees = await self._find_employees_linkedin()
        employees.extend(linkedin_employees)
        
        return employees
    
    async def _find_employees_hunter(self) -> List[Employee]:
        """Find employees using Hunter.io API"""
        employees = []
        
        try:
            url = f"https://api.hunter.io/v2/domain-search?domain={self.domain}&api_key={self.hunter_api_key}"
            
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    for email_data in data.get('data', {}).get('emails', []):
                        employee = Employee(
                            name=f"{email_data.get('first_name', '')} {email_data.get('last_name', '')}",
                            position=email_data.get('position'),
                            email=email_data.get('value'),
                            linkedin=email_data.get('linkedin'),
                            twitter=email_data.get('twitter')
                        )
                        employees.append(employee)
        
        except Exception as e:
            logger.error(f"Error finding employees via Hunter.io: {e}")
        
        return employees
    
    async def _find_employees_linkedin(self) -> List[Employee]:
        """Find employees via LinkedIn (respecting ToS)"""
        employees = []
        
        # Note: This is a placeholder
        # In production, use LinkedIn's official API or partner services
        # Direct scraping violates LinkedIn's ToS
        
        try:
            # Use Google search to find LinkedIn profiles
            # This is a safer approach than direct LinkedIn scraping
            company_name = self.domain.split('.')[0]
            search_query = f"site:linkedin.com/in {company_name}"
            
            # Implementation would use a search API or respect robots.txt
            # For now, this is a placeholder
            pass
        
        except Exception as e:
            logger.error(f"Error finding employees via LinkedIn: {e}")
        
        return employees
    
    async def _check_social_media(self) -> Dict:
        """Check social media presence"""
        social_media = {
            'twitter': None,
            'facebook': None,
            'instagram': None,
            'youtube': None,
            'github': None
        }
        
        company_name = self.domain.split('.')[0]
        
        # Check Twitter
        twitter_url = f"https://twitter.com/{company_name}"
        if await self._check_url_exists(twitter_url):
            social_media['twitter'] = twitter_url
        
        # Check Facebook
        facebook_url = f"https://facebook.com/{company_name}"
        if await self._check_url_exists(facebook_url):
            social_media['facebook'] = facebook_url
        
        # Check GitHub
        github_url = f"https://github.com/{company_name}"
        if await self._check_url_exists(github_url):
            social_media['github'] = github_url
        
        return social_media
    
    async def _get_domain_info(self) -> Dict:
        """Get domain information"""
        info = {
            'domain': self.domain,
            'created_date': None,
            'registrar': None,
            'age_days': None
        }
        
        try:
            # Use WHOIS data (requires python-whois)
            import whois
            w = whois.whois(self.domain)
            
            if w.creation_date:
                creation_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
                info['created_date'] = str(creation_date)
                age = (datetime.now() - creation_date).days
                info['age_days'] = age
            
            if w.registrar:
                info['registrar'] = w.registrar
        
        except Exception as e:
            logger.error(f"Error getting domain info: {e}")
        
        return info
    
    async def _detect_technologies(self) -> Set[str]:
        """Detect technologies used on the website"""
        technologies = set()
        
        try:
            async with self.session.get(self.target) as response:
                if response.status == 200:
                    html = await response.text()
                    headers = dict(response.headers)
                    
                    # Server detection
                    if 'server' in headers:
                        technologies.add(f"Server: {headers['server']}")
                    
                    # Framework detection
                    html_lower = html.lower()
                    
                    if 'wp-content' in html_lower or 'wordpress' in html_lower:
                        technologies.add('WordPress')
                    
                    if 'drupal' in html_lower:
                        technologies.add('Drupal')
                    
                    if 'joomla' in html_lower:
                        technologies.add('Joomla')
                    
                    if 'react' in html_lower or 'reactjs' in html_lower:
                        technologies.add('React')
                    
                    if 'vue' in html_lower or 'vuejs' in html_lower:
                        technologies.add('Vue.js')
                    
                    if 'angular' in html_lower:
                        technologies.add('Angular')
                    
                    # Check for specific headers
                    if 'x-powered-by' in headers:
                        technologies.add(f"Powered by: {headers['x-powered-by']}")
        
        except Exception as e:
            logger.error(f"Error detecting technologies: {e}")
        
        return technologies
    
    async def _check_url_exists(self, url: str) -> bool:
        """Check if URL exists"""
        try:
            async with self.session.head(url, allow_redirects=True) as response:
                return response.status == 200
        except Exception:
            return False
    
    def generate_report(self, result: OSINTResult) -> Dict:
        """Generate comprehensive OSINT report"""
        return {
            'target': self.target,
            'domain': self.domain,
            'github_repositories': [
                {
                    'name': r.name,
                    'url': r.url,
                    'description': r.description,
                    'stars': r.stars,
                    'language': r.language
                }
                for r in result.github_repos
            ],
            'breach_data': [
                {
                    'service': b.service,
                    'breach_date': b.breach_date,
                    'compromised_data': b.data_classes,
                    'verified': b.verified
                }
                for b in result.breach_data
            ],
            'employees_found': len(result.employees),
            'employees': [
                {
                    'name': e.name,
                    'position': e.position,
                    'email': e.email,
                    'linkedin': e.linkedin
                }
                for e in result.employees[:10]  # Limit to 10 for report
            ],
            'social_media': result.social_media,
            'domain_info': result.domain_info,
            'technologies': list(result.technologies),
            'summary': {
                'total_github_repos': len(result.github_repos),
                'total_breaches': len(result.breach_data),
                'total_employees': len(result.employees),
                'social_media_accounts': sum(1 for v in result.social_media.values() if v),
                'technologies_detected': len(result.technologies)
            }
        }


# Integration with RedHawk
async def run_osint(target: str, config: Dict = None) -> Dict:
    """
    Run OSINT gathering
    
    Usage:
        config = {
            'github_token': 'your_token',
            'hibp_api_key': 'your_key',
            'hunter_api_key': 'your_key'
        }
        results = await run_osint('example.com', config)
    """
    async with OSINTScanner(target, config) as scanner:
        results = await scanner.gather()
        return scanner.generate_report(results)


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python osint.py <target>")
        sys.exit(1)
    
    target = sys.argv[1]
    
    async def main():
        results = await run_osint(target)
        print(json.dumps(results, indent=2))
    
    asyncio.run(main())
