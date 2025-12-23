"""
RedHawk Ethics & Rate Limiting
Responsible scanning practices
"""

import asyncio
import time
from typing import Optional
import logging

logger = logging.getLogger(__name__)


class EthicsChecker:
    """Ethical scanning enforcement"""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.rate_limit = self.config.get('rate_limit', 10)
        self.respect_robots = self.config.get('respect_robots', True)
        self.last_request_time = {}
    
    async def check_permission(self, target: str) -> bool:
        """Check if scanning is permitted"""
        # Check robots.txt
        if self.respect_robots:
            if not await self._check_robots_txt(target):
                logger.warning(f"Scanning disallowed by robots.txt: {target}")
                return False
        
        return True
    
    async def _check_robots_txt(self, target: str) -> bool:
        """Check robots.txt for scanning permission"""
        try:
            async with aiohttp.ClientSession() as session:
                robots_url = f"{target}/robots.txt"
                async with session.get(robots_url) as response:
                    if response.status == 200:
                        text = await response.text()
                        # Simple check for disallow all
                        if "User-agent: *" in text and "Disallow: /" in text:
                            return False
        except Exception:
            pass
        
        return True
    
    async def rate_limit_wait(self, target: str):
        """Enforce rate limiting"""
        if target in self.last_request_time:
            elapsed = time.time() - self.last_request_time[target]
            wait_time = (1.0 / self.rate_limit) - elapsed
            
            if wait_time > 0:
                await asyncio.sleep(wait_time)
        
        self.last_request_time[target] = time.time()
