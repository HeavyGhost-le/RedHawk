"""
RedHawk API Scanner Module
Advanced API endpoint discovery and security assessment
"""

import re
import json
import asyncio
import aiohttp
from typing import Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse
from dataclasses import dataclass, asdict
import logging

logger = logging.getLogger(__name__)


@dataclass
class APIEndpoint:
    """Represents a discovered API endpoint"""
    url: str
    method: str
    status_code: Optional[int] = None
    response_time: Optional[float] = None
    auth_required: bool = False
    rate_limited: bool = False
    api_version: Optional[str] = None
    content_type: Optional[str] = None
    vulnerabilities: List[str] = None
    
    def __post_init__(self):
        if self.vulnerabilities is None:
            self.vulnerabilities = []


@dataclass
class APIDiscoveryResult:
    """Results from API scanning"""
    endpoints: List[APIEndpoint]
    swagger_url: Optional[str] = None
    openapi_url: Optional[str] = None
    graphql_url: Optional[str] = None
    api_versions: Set[str] = None
    authentication_methods: Set[str] = None
    
    def __post_init__(self):
        if self.api_versions is None:
            self.api_versions = set()
        if self.authentication_methods is None:
            self.authentication_methods = set()


class APIScanner:
    """
    Advanced API Scanner for RedHawk
    
    Features:
    - REST API endpoint discovery
    - GraphQL schema enumeration
    - Swagger/OpenAPI detection
    - Authentication testing
    - Rate limiting detection
    - API versioning analysis
    """
    
    def __init__(self, target: str, config: Dict = None):
        self.target = target.rstrip('/')
        self.config = config or {}
        self.session: Optional[aiohttp.ClientSession] = None
        self.discovered_endpoints: Set[str] = set()
        
        # Common API paths
        self.api_paths = [
            '/api', '/api/v1', '/api/v2', '/api/v3',
            '/rest', '/rest/api', '/graphql',
            '/swagger', '/swagger.json', '/swagger.yaml',
            '/openapi.json', '/api-docs',
            '/v1', '/v2', '/v3',
            '/.well-known/openapi.json'
        ]
        
        # Common API endpoints
        self.common_endpoints = [
            '/users', '/user', '/auth', '/login', '/register',
            '/profile', '/account', '/settings',
            '/admin', '/dashboard', '/health', '/status',
            '/search', '/query', '/data',
            '/products', '/items', '/posts', '/comments'
        ]
        
        # HTTP methods to test
        self.http_methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']
    
    async def __aenter__(self):
        """Async context manager entry"""
        timeout = aiohttp.ClientTimeout(total=30)
        self.session = aiohttp.ClientSession(timeout=timeout)
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    async def scan(self) -> APIDiscoveryResult:
        """
        Main scanning function
        
        Returns:
            APIDiscoveryResult with all discovered endpoints and metadata
        """
        logger.info(f"Starting API scan for {self.target}")
        
        results = APIDiscoveryResult(endpoints=[])
        
        # 1. Detect API documentation
        swagger_url = await self._detect_swagger()
        openapi_url = await self._detect_openapi()
        graphql_url = await self._detect_graphql()
        
        results.swagger_url = swagger_url
        results.openapi_url = openapi_url
        results.graphql_url = graphql_url
        
        # 2. Parse API documentation if found
        if swagger_url:
            endpoints = await self._parse_swagger(swagger_url)
            results.endpoints.extend(endpoints)
        
        if openapi_url:
            endpoints = await self._parse_openapi(openapi_url)
            results.endpoints.extend(endpoints)
        
        # 3. Discover endpoints through fuzzing
        fuzzed_endpoints = await self._fuzz_endpoints()
        results.endpoints.extend(fuzzed_endpoints)
        
        # 4. Extract API versions
        results.api_versions = self._extract_versions(results.endpoints)
        
        # 5. Detect authentication methods
        results.authentication_methods = await self._detect_auth_methods()
        
        # 6. Test each endpoint
        await self._test_endpoints(results.endpoints)
        
        logger.info(f"Scan complete. Found {len(results.endpoints)} endpoints")
        return results
    
    async def _detect_swagger(self) -> Optional[str]:
        """Detect Swagger documentation"""
        swagger_paths = [
            '/swagger.json', '/swagger.yaml',
            '/swagger/v1/swagger.json',
            '/api/swagger.json',
            '/swagger-ui.html'
        ]
        
        for path in swagger_paths:
            url = urljoin(self.target, path)
            try:
                async with self.session.get(url) as response:
                    if response.status == 200:
                        content_type = response.headers.get('content-type', '')
                        if 'json' in content_type or 'yaml' in content_type:
                            logger.info(f"Found Swagger documentation at {url}")
                            return url
            except Exception as e:
                logger.debug(f"Error checking {url}: {e}")
        
        return None
    
    async def _detect_openapi(self) -> Optional[str]:
        """Detect OpenAPI specification"""
        openapi_paths = [
            '/openapi.json', '/openapi.yaml',
            '/api/openapi.json',
            '/.well-known/openapi.json'
        ]
        
        for path in openapi_paths:
            url = urljoin(self.target, path)
            try:
                async with self.session.get(url) as response:
                    if response.status == 200:
                        logger.info(f"Found OpenAPI specification at {url}")
                        return url
            except Exception as e:
                logger.debug(f"Error checking {url}: {e}")
        
        return None
    
    async def _detect_graphql(self) -> Optional[str]:
        """Detect GraphQL endpoint"""
        graphql_paths = ['/graphql', '/api/graphql', '/v1/graphql']
        
        introspection_query = {
            "query": """
                {
                    __schema {
                        queryType { name }
                        mutationType { name }
                    }
                }
            """
        }
        
        for path in graphql_paths:
            url = urljoin(self.target, path)
            try:
                async with self.session.post(url, json=introspection_query) as response:
                    if response.status == 200:
                        data = await response.json()
                        if '__schema' in data.get('data', {}):
                            logger.info(f"Found GraphQL endpoint at {url}")
                            return url
            except Exception as e:
                logger.debug(f"Error checking {url}: {e}")
        
        return None
    
    async def _parse_swagger(self, swagger_url: str) -> List[APIEndpoint]:
        """Parse Swagger documentation"""
        endpoints = []
        
        try:
            async with self.session.get(swagger_url) as response:
                if response.status == 200:
                    spec = await response.json()
                    
                    # Extract base path
                    base_path = spec.get('basePath', '')
                    paths = spec.get('paths', {})
                    
                    for path, methods in paths.items():
                        full_path = urljoin(self.target, base_path + path)
                        
                        for method, details in methods.items():
                            if method.upper() in self.http_methods:
                                endpoint = APIEndpoint(
                                    url=full_path,
                                    method=method.upper(),
                                    api_version=spec.get('info', {}).get('version')
                                )
                                
                                # Check if authentication is required
                                if 'security' in details or 'security' in spec:
                                    endpoint.auth_required = True
                                
                                endpoints.append(endpoint)
        
        except Exception as e:
            logger.error(f"Error parsing Swagger: {e}")
        
        return endpoints
    
    async def _parse_openapi(self, openapi_url: str) -> List[APIEndpoint]:
        """Parse OpenAPI specification"""
        # Similar to Swagger parsing
        return await self._parse_swagger(openapi_url)
    
    async def _fuzz_endpoints(self) -> List[APIEndpoint]:
        """Discover endpoints through intelligent fuzzing"""
        endpoints = []
        
        # Test common API base paths
        for base_path in self.api_paths:
            base_url = urljoin(self.target, base_path)
            
            # Test common endpoints under each base
            for endpoint_path in self.common_endpoints:
                full_url = urljoin(base_url, endpoint_path)
                
                # Test with GET first (least invasive)
                try:
                    async with self.session.get(full_url, allow_redirects=False) as response:
                        if response.status in [200, 201, 401, 403, 405]:
                            endpoint = APIEndpoint(
                                url=full_url,
                                method='GET',
                                status_code=response.status,
                                content_type=response.headers.get('content-type')
                            )
                            
                            # 401/403 suggests auth required
                            if response.status in [401, 403]:
                                endpoint.auth_required = True
                            
                            # 405 Method Not Allowed - try other methods
                            if response.status == 405:
                                await self._test_methods(full_url, endpoint)
                            
                            endpoints.append(endpoint)
                            self.discovered_endpoints.add(full_url)
                
                except Exception as e:
                    logger.debug(f"Error fuzzing {full_url}: {e}")
                
                # Rate limiting protection
                await asyncio.sleep(0.1)
        
        return endpoints
    
    async def _test_methods(self, url: str, endpoint: APIEndpoint):
        """Test different HTTP methods on an endpoint"""
        for method in self.http_methods:
            if method == 'GET':
                continue  # Already tested
            
            try:
                async with self.session.request(method, url) as response:
                    if response.status not in [404, 405]:
                        # This method is supported
                        endpoint.vulnerabilities.append(
                            f"Endpoint supports {method} method"
                        )
            except Exception:
                pass
    
    async def _test_endpoints(self, endpoints: List[APIEndpoint]):
        """Test discovered endpoints for vulnerabilities"""
        for endpoint in endpoints:
            # Check for rate limiting
            endpoint.rate_limited = await self._check_rate_limit(endpoint.url)
            
            # Check for common vulnerabilities
            await self._check_vulnerabilities(endpoint)
    
    async def _check_rate_limit(self, url: str) -> bool:
        """Check if endpoint has rate limiting"""
        try:
            # Make 5 rapid requests
            for _ in range(5):
                async with self.session.get(url) as response:
                    if response.status == 429:  # Too Many Requests
                        return True
            return False
        except Exception:
            return False
    
    async def _check_vulnerabilities(self, endpoint: APIEndpoint):
        """Check endpoint for common vulnerabilities"""
        # Check for missing authentication
        if not endpoint.auth_required and 'admin' in endpoint.url.lower():
            endpoint.vulnerabilities.append(
                "Admin endpoint without authentication"
            )
        
        # Check for verbose error messages
        try:
            async with self.session.get(endpoint.url + '/../../etc/passwd') as response:
                text = await response.text()
                if 'root:' in text or 'syntax error' in text.lower():
                    endpoint.vulnerabilities.append(
                        "Verbose error messages detected"
                    )
        except Exception:
            pass
        
        # Check for CORS misconfiguration
        try:
            headers = {'Origin': 'https://evil.com'}
            async with self.session.options(endpoint.url, headers=headers) as response:
                cors_header = response.headers.get('Access-Control-Allow-Origin', '')
                if cors_header == '*' or 'evil.com' in cors_header:
                    endpoint.vulnerabilities.append(
                        "CORS misconfiguration detected"
                    )
        except Exception:
            pass
    
    def _extract_versions(self, endpoints: List[APIEndpoint]) -> Set[str]:
        """Extract API versions from endpoints"""
        versions = set()
        version_pattern = re.compile(r'v(\d+\.?\d*)')
        
        for endpoint in endpoints:
            if endpoint.api_version:
                versions.add(endpoint.api_version)
            
            match = version_pattern.search(endpoint.url)
            if match:
                versions.add(match.group(1))
        
        return versions
    
    async def _detect_auth_methods(self) -> Set[str]:
        """Detect authentication methods"""
        auth_methods = set()
        
        # Common auth endpoints
        auth_endpoints = ['/login', '/auth', '/oauth', '/token']
        
        for endpoint in auth_endpoints:
            url = urljoin(self.target, endpoint)
            try:
                async with self.session.options(url) as response:
                    www_auth = response.headers.get('WWW-Authenticate', '')
                    if www_auth:
                        if 'Bearer' in www_auth:
                            auth_methods.add('Bearer Token')
                        if 'Basic' in www_auth:
                            auth_methods.add('Basic Auth')
                    
                    # Check for OAuth
                    if 'oauth' in endpoint.lower():
                        auth_methods.add('OAuth 2.0')
            except Exception:
                pass
        
        return auth_methods
    
    def generate_report(self, results: APIDiscoveryResult) -> Dict:
        """Generate a comprehensive report"""
        return {
            'target': self.target,
            'total_endpoints': len(results.endpoints),
            'api_versions': list(results.api_versions),
            'authentication_methods': list(results.authentication_methods),
            'swagger_url': results.swagger_url,
            'openapi_url': results.openapi_url,
            'graphql_url': results.graphql_url,
            'endpoints': [asdict(ep) for ep in results.endpoints],
            'vulnerabilities': [
                {'endpoint': ep.url, 'issues': ep.vulnerabilities}
                for ep in results.endpoints if ep.vulnerabilities
            ]
        }


# Integration with RedHawk
async def run_api_scan(target: str, config: Dict = None) -> Dict:
    """
    Run API scan and return results
    
    Usage:
        results = await run_api_scan('https://api.example.com')
    """
    async with APIScanner(target, config) as scanner:
        results = await scanner.scan()
        return scanner.generate_report(results)


# CLI interface
if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python api_scanner.py <target_url>")
        sys.exit(1)
    
    target = sys.argv[1]
    
    async def main():
        results = await run_api_scan(target)
        print(json.dumps(results, indent=2))
    
    asyncio.run(main())
