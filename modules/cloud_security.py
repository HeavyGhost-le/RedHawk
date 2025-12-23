"""
RedHawk Cloud Security Module
Scan for exposed cloud storage and misconfigurations
"""

import re
import asyncio
import aiohttp
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, asdict
import logging
from urllib.parse import urlparse
import xml.etree.ElementTree as ET

logger = logging.getLogger(__name__)


@dataclass
class CloudResource:
    """Represents a discovered cloud resource"""
    resource_type: str  # s3, azure_blob, gcs
    url: str
    bucket_name: str
    is_public: bool = False
    is_listable: bool = False
    permissions: List[str] = None
    files_found: List[str] = None
    vulnerabilities: List[str] = None
    metadata: Dict = None
    
    def __post_init__(self):
        if self.permissions is None:
            self.permissions = []
        if self.files_found is None:
            self.files_found = []
        if self.vulnerabilities is None:
            self.vulnerabilities = []
        if self.metadata is None:
            self.metadata = {}


@dataclass
class CloudScanResult:
    """Results from cloud security scan"""
    resources: List[CloudResource]
    total_exposed: int = 0
    total_listable: int = 0
    critical_findings: List[str] = None
    
    def __post_init__(self):
        if self.critical_findings is None:
            self.critical_findings = []
        self.total_exposed = sum(1 for r in self.resources if r.is_public)
        self.total_listable = sum(1 for r in self.resources if r.is_listable)


class CloudSecurityScanner:
    """
    Cloud Security Scanner for RedHawk
    
    Features:
    - AWS S3 bucket enumeration
    - Azure Blob Storage detection
    - Google Cloud Storage checks
    - Misconfigured cloud resources
    - Public exposure detection
    - Permission analysis
    """
    
    def __init__(self, target: str, config: Dict = None):
        self.target = target
        self.domain = urlparse(target).netloc or target
        self.config = config or {}
        self.session: Optional[aiohttp.ClientSession] = None
        
        # Cloud storage patterns
        self.s3_patterns = [
            'https://{bucket}.s3.amazonaws.com',
            'https://{bucket}.s3-{region}.amazonaws.com',
            'https://s3.amazonaws.com/{bucket}',
            'https://s3-{region}.amazonaws.com/{bucket}'
        ]
        
        self.azure_patterns = [
            'https://{account}.blob.core.windows.net/{container}',
            'https://{account}.blob.core.windows.net'
        ]
        
        self.gcs_patterns = [
            'https://storage.googleapis.com/{bucket}',
            'https://{bucket}.storage.googleapis.com'
        ]
        
        # AWS regions
        self.aws_regions = [
            'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
            'eu-west-1', 'eu-central-1', 'ap-southeast-1', 'ap-northeast-1'
        ]
        
        # Common bucket name patterns
        self.bucket_variations = []
    
    async def __aenter__(self):
        """Async context manager entry"""
        timeout = aiohttp.ClientTimeout(total=30)
        self.session = aiohttp.ClientSession(timeout=timeout)
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    def _generate_bucket_names(self) -> List[str]:
        """Generate possible bucket names based on domain"""
        domain_parts = self.domain.replace('www.', '').split('.')
        company = domain_parts[0]
        
        variations = [
            company,
            f"{company}-backup",
            f"{company}-backups",
            f"{company}-data",
            f"{company}-assets",
            f"{company}-files",
            f"{company}-uploads",
            f"{company}-media",
            f"{company}-images",
            f"{company}-documents",
            f"{company}-public",
            f"{company}-private",
            f"{company}-prod",
            f"{company}-production",
            f"{company}-dev",
            f"{company}-development",
            f"{company}-staging",
            f"{company}-test",
            f"{company}-qa",
            f"{company}-logs",
            f"{company}-archive",
            f"{company}-website",
            f"{company}-web",
            f"{company}-app",
            f"{company}-api",
            self.domain.replace('.', '-'),
            self.domain.replace('.', ''),
        ]
        
        return variations
    
    async def scan(self) -> CloudScanResult:
        """
        Main cloud security scanning function
        
        Returns:
            CloudScanResult with all findings
        """
        logger.info(f"Starting cloud security scan for {self.target}")
        
        resources = []
        
        # Generate bucket names to test
        bucket_names = self._generate_bucket_names()
        
        # 1. Scan AWS S3
        s3_resources = await self._scan_s3_buckets(bucket_names)
        resources.extend(s3_resources)
        
        # 2. Scan Azure Blob Storage
        azure_resources = await self._scan_azure_storage(bucket_names)
        resources.extend(azure_resources)
        
        # 3. Scan Google Cloud Storage
        gcs_resources = await self._scan_gcs_buckets(bucket_names)
        resources.extend(gcs_resources)
        
        # 4. Analyze discovered resources
        for resource in resources:
            await self._analyze_resource(resource)
        
        result = CloudScanResult(resources=resources)
        
        # Generate critical findings
        result.critical_findings = self._generate_findings(resources)
        
        logger.info(f"Cloud scan complete. Found {len(resources)} resources, "
                   f"{result.total_exposed} exposed, {result.total_listable} listable")
        
        return result
    
    async def _scan_s3_buckets(self, bucket_names: List[str]) -> List[CloudResource]:
        """Scan for AWS S3 buckets"""
        resources = []
        
        for bucket_name in bucket_names:
            # Try without region first
            url = f"https://{bucket_name}.s3.amazonaws.com"
            resource = await self._check_s3_bucket(url, bucket_name)
            
            if resource:
                resources.append(resource)
                continue
            
            # Try with regions
            for region in self.aws_regions:
                url = f"https://{bucket_name}.s3-{region}.amazonaws.com"
                resource = await self._check_s3_bucket(url, bucket_name, region)
                
                if resource:
                    resources.append(resource)
                    break
            
            await asyncio.sleep(0.1)  # Rate limiting
        
        return resources
    
    async def _check_s3_bucket(self, url: str, bucket_name: str, 
                               region: str = None) -> Optional[CloudResource]:
        """Check if S3 bucket exists and is accessible"""
        try:
            async with self.session.get(url) as response:
                resource = CloudResource(
                    resource_type='AWS S3',
                    url=url,
                    bucket_name=bucket_name
                )
                
                if region:
                    resource.metadata['region'] = region
                
                # Bucket exists
                if response.status == 200:
                    resource.is_public = True
                    resource.is_listable = True
                    
                    # Try to list contents
                    text = await response.text()
                    files = self._parse_s3_listing(text)
                    resource.files_found = files[:10]  # First 10 files
                    
                    resource.vulnerabilities.append(
                        "Bucket is publicly accessible and listable"
                    )
                    
                    logger.warning(f"Found publicly accessible S3 bucket: {url}")
                    return resource
                
                # Bucket exists but access denied
                elif response.status == 403:
                    resource.is_public = False
                    resource.vulnerabilities.append(
                        "Bucket exists but is not publicly accessible"
                    )
                    logger.info(f"Found private S3 bucket: {url}")
                    return resource
                
                # Check for authenticated access
                elif response.status == 401:
                    resource.is_public = False
                    resource.vulnerabilities.append(
                        "Bucket requires authentication"
                    )
                    return resource
        
        except Exception as e:
            logger.debug(f"Error checking S3 bucket {url}: {e}")
        
        return None
    
    def _parse_s3_listing(self, xml_content: str) -> List[str]:
        """Parse S3 bucket listing XML"""
        files = []
        try:
            root = ET.fromstring(xml_content)
            # S3 uses namespace
            ns = {'s3': 'http://s3.amazonaws.com/doc/2006-03-01/'}
            
            for content in root.findall('.//s3:Contents', ns):
                key = content.find('s3:Key', ns)
                if key is not None and key.text:
                    files.append(key.text)
            
            # Try without namespace if above fails
            if not files:
                for content in root.findall('.//Contents'):
                    key = content.find('Key')
                    if key is not None and key.text:
                        files.append(key.text)
        
        except Exception as e:
            logger.debug(f"Error parsing S3 listing: {e}")
        
        return files
    
    async def _scan_azure_storage(self, account_names: List[str]) -> List[CloudResource]:
        """Scan for Azure Blob Storage"""
        resources = []
        
        for account_name in account_names:
            # Clean account name (Azure has strict naming)
            account_name = account_name.lower().replace('_', '').replace('-', '')[:24]
            
            url = f"https://{account_name}.blob.core.windows.net"
            resource = await self._check_azure_storage(url, account_name)
            
            if resource:
                resources.append(resource)
            
            await asyncio.sleep(0.1)
        
        return resources
    
    async def _check_azure_storage(self, url: str, account_name: str) -> Optional[CloudResource]:
        """Check Azure Blob Storage account"""
        try:
            # Try to list containers
            list_url = f"{url}/?comp=list"
            
            async with self.session.get(list_url) as response:
                resource = CloudResource(
                    resource_type='Azure Blob Storage',
                    url=url,
                    bucket_name=account_name
                )
                
                if response.status == 200:
                    resource.is_public = True
                    resource.is_listable = True
                    
                    # Parse container listing
                    text = await response.text()
                    containers = self._parse_azure_listing(text)
                    resource.files_found = containers
                    
                    resource.vulnerabilities.append(
                        "Storage account is publicly accessible"
                    )
                    
                    logger.warning(f"Found publicly accessible Azure storage: {url}")
                    return resource
                
                elif response.status in [403, 401]:
                    resource.is_public = False
                    logger.info(f"Found private Azure storage: {url}")
                    return resource
        
        except Exception as e:
            logger.debug(f"Error checking Azure storage {url}: {e}")
        
        return None
    
    def _parse_azure_listing(self, xml_content: str) -> List[str]:
        """Parse Azure container listing"""
        containers = []
        try:
            root = ET.fromstring(xml_content)
            for container in root.findall('.//Container'):
                name = container.find('Name')
                if name is not None and name.text:
                    containers.append(name.text)
        except Exception as e:
            logger.debug(f"Error parsing Azure listing: {e}")
        
        return containers
    
    async def _scan_gcs_buckets(self, bucket_names: List[str]) -> List[CloudResource]:
        """Scan for Google Cloud Storage buckets"""
        resources = []
        
        for bucket_name in bucket_names:
            url = f"https://storage.googleapis.com/{bucket_name}"
            resource = await self._check_gcs_bucket(url, bucket_name)
            
            if resource:
                resources.append(resource)
            
            await asyncio.sleep(0.1)
        
        return resources
    
    async def _check_gcs_bucket(self, url: str, bucket_name: str) -> Optional[CloudResource]:
        """Check Google Cloud Storage bucket"""
        try:
            async with self.session.get(url) as response:
                resource = CloudResource(
                    resource_type='Google Cloud Storage',
                    url=url,
                    bucket_name=bucket_name
                )
                
                if response.status == 200:
                    resource.is_public = True
                    resource.is_listable = True
                    
                    # Try to parse listing
                    text = await response.text()
                    files = self._parse_gcs_listing(text)
                    resource.files_found = files[:10]
                    
                    resource.vulnerabilities.append(
                        "Bucket is publicly accessible"
                    )
                    
                    logger.warning(f"Found publicly accessible GCS bucket: {url}")
                    return resource
                
                elif response.status in [403, 401]:
                    resource.is_public = False
                    logger.info(f"Found private GCS bucket: {url}")
                    return resource
        
        except Exception as e:
            logger.debug(f"Error checking GCS bucket {url}: {e}")
        
        return None
    
    def _parse_gcs_listing(self, xml_content: str) -> List[str]:
        """Parse GCS bucket listing"""
        files = []
        try:
            root = ET.fromstring(xml_content)
            for item in root.findall('.//Contents'):
                key = item.find('Key')
                if key is not None and key.text:
                    files.append(key.text)
        except Exception as e:
            logger.debug(f"Error parsing GCS listing: {e}")
        
        return files
    
    async def _analyze_resource(self, resource: CloudResource):
        """Analyze resource for sensitive data and misconfigurations"""
        # Check for sensitive file patterns
        sensitive_patterns = [
            r'\.env$', r'\.config$', r'\.key$', r'\.pem$',
            r'password', r'secret', r'credential', r'backup',
            r'\.sql$', r'\.db$', r'\.dump$'
        ]
        
        for file_name in resource.files_found:
            for pattern in sensitive_patterns:
                if re.search(pattern, file_name, re.IGNORECASE):
                    resource.vulnerabilities.append(
                        f"Potentially sensitive file exposed: {file_name}"
                    )
                    break
        
        # Additional checks for public resources
        if resource.is_public:
            resource.vulnerabilities.append(
                "CRITICAL: Resource is publicly accessible without authentication"
            )
        
        if resource.is_listable:
            resource.vulnerabilities.append(
                "WARNING: Resource allows directory listing"
            )
    
    def _generate_findings(self, resources: List[CloudResource]) -> List[str]:
        """Generate critical findings summary"""
        findings = []
        
        public_count = sum(1 for r in resources if r.is_public)
        listable_count = sum(1 for r in resources if r.is_listable)
        
        if public_count > 0:
            findings.append(
                f"CRITICAL: Found {public_count} publicly accessible cloud resources"
            )
        
        if listable_count > 0:
            findings.append(
                f"HIGH: Found {listable_count} cloud resources with directory listing enabled"
            )
        
        # Check for sensitive files
        for resource in resources:
            sensitive_files = [v for v in resource.vulnerabilities 
                             if 'sensitive file' in v.lower()]
            if sensitive_files:
                findings.append(
                    f"HIGH: {resource.bucket_name} contains potentially sensitive files"
                )
        
        return findings
    
    def generate_report(self, results: CloudScanResult) -> Dict:
        """Generate comprehensive report"""
        return {
            'target': self.target,
            'total_resources_found': len(results.resources),
            'total_exposed': results.total_exposed,
            'total_listable': results.total_listable,
            'critical_findings': results.critical_findings,
            'resources': [asdict(r) for r in results.resources],
            'summary': {
                's3_buckets': len([r for r in results.resources if r.resource_type == 'AWS S3']),
                'azure_storage': len([r for r in results.resources if r.resource_type == 'Azure Blob Storage']),
                'gcs_buckets': len([r for r in results.resources if r.resource_type == 'Google Cloud Storage'])
            }
        }


# Integration with RedHawk
async def run_cloud_scan(target: str, config: Dict = None) -> Dict:
    """
    Run cloud security scan
    
    Usage:
        results = await run_cloud_scan('example.com')
    """
    async with CloudSecurityScanner(target, config) as scanner:
        results = await scanner.scan()
        return scanner.generate_report(results)


if __name__ == '__main__':
    import sys
    import json
    
    if len(sys.argv) < 2:
        print("Usage: python cloud_security.py <target>")
        sys.exit(1)
    
    target = sys.argv[1]
    
    async def main():
        results = await run_cloud_scan(target)
        print(json.dumps(results, indent=2))
    
    asyncio.run(main())
