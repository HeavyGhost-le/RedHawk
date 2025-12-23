"""
RedHawk Performance Optimization Engine
Intelligent caching, connection pooling, and async operations
"""

import asyncio
import time
import hashlib
import pickle
from typing import Any, Callable, Dict, Optional, Tuple
from functools import wraps
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import logging
from collections import OrderedDict
import aiohttp
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger(__name__)


@dataclass
class CacheEntry:
    """Represents a cached item"""
    key: str
    value: Any
    timestamp: datetime
    ttl: int  # Time to live in seconds
    hits: int = 0
    
    def is_expired(self) -> bool:
        """Check if cache entry has expired"""
        return datetime.now() > self.timestamp + timedelta(seconds=self.ttl)
    
    def access(self):
        """Record cache hit"""
        self.hits += 1


class LRUCache:
    """
    Least Recently Used Cache with TTL support
    """
    
    def __init__(self, max_size: int = 1000, default_ttl: int = 3600):
        self.max_size = max_size
        self.default_ttl = default_ttl
        self.cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self.stats = {
            'hits': 0,
            'misses': 0,
            'evictions': 0,
            'expirations': 0
        }
    
    def _generate_key(self, *args, **kwargs) -> str:
        """Generate cache key from arguments"""
        key_data = pickle.dumps((args, sorted(kwargs.items())))
        return hashlib.md5(key_data).hexdigest()
    
    def get(self, key: str) -> Optional[Any]:
        """Retrieve item from cache"""
        if key not in self.cache:
            self.stats['misses'] += 1
            return None
        
        entry = self.cache[key]
        
        # Check expiration
        if entry.is_expired():
            self.cache.pop(key)
            self.stats['expirations'] += 1
            self.stats['misses'] += 1
            return None
        
        # Move to end (most recently used)
        self.cache.move_to_end(key)
        entry.access()
        self.stats['hits'] += 1
        
        return entry.value
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None):
        """Store item in cache"""
        if key in self.cache:
            self.cache.pop(key)
        
        # Evict oldest if at capacity
        elif len(self.cache) >= self.max_size:
            self.cache.popitem(last=False)
            self.stats['evictions'] += 1
        
        entry = CacheEntry(
            key=key,
            value=value,
            timestamp=datetime.now(),
            ttl=ttl or self.default_ttl
        )
        
        self.cache[key] = entry
    
    def clear(self):
        """Clear all cache entries"""
        self.cache.clear()
    
    def get_stats(self) -> Dict:
        """Get cache statistics"""
        total_requests = self.stats['hits'] + self.stats['misses']
        hit_rate = (self.stats['hits'] / total_requests * 100) if total_requests > 0 else 0
        
        return {
            **self.stats,
            'size': len(self.cache),
            'max_size': self.max_size,
            'hit_rate': f"{hit_rate:.2f}%"
        }


class ConnectionPool:
    """
    Connection pool for HTTP requests
    """
    
    def __init__(self, max_connections: int = 100, max_per_host: int = 10):
        self.max_connections = max_connections
        self.max_per_host = max_per_host
        self.connector = None
        self.session: Optional[aiohttp.ClientSession] = None
    
    async def __aenter__(self):
        """Create connection pool"""
        self.connector = aiohttp.TCPConnector(
            limit=self.max_connections,
            limit_per_host=self.max_per_host,
            ttl_dns_cache=300,  # DNS cache for 5 minutes
            use_dns_cache=True
        )
        
        timeout = aiohttp.ClientTimeout(total=30, connect=10)
        
        self.session = aiohttp.ClientSession(
            connector=self.connector,
            timeout=timeout
        )
        
        return self.session
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Close connection pool"""
        if self.session:
            await self.session.close()
        if self.connector:
            await self.connector.close()


class RateLimiter:
    """
    Token bucket rate limiter
    """
    
    def __init__(self, rate: int = 10, per: float = 1.0):
        """
        Args:
            rate: Number of requests
            per: Time period in seconds
        """
        self.rate = rate
        self.per = per
        self.tokens = rate
        self.last_update = time.time()
        self.lock = asyncio.Lock()
    
    async def acquire(self):
        """Wait until a token is available"""
        async with self.lock:
            now = time.time()
            elapsed = now - self.last_update
            
            # Refill tokens
            self.tokens = min(
                self.rate,
                self.tokens + elapsed * (self.rate / self.per)
            )
            self.last_update = now
            
            # Wait if no tokens available
            if self.tokens < 1:
                wait_time = (1 - self.tokens) * (self.per / self.rate)
                await asyncio.sleep(wait_time)
                self.tokens = 0
            else:
                self.tokens -= 1


class AdaptiveTimeout:
    """
    Adaptive timeout that adjusts based on response times
    """
    
    def __init__(self, initial: float = 10.0, min_timeout: float = 5.0, 
                 max_timeout: float = 60.0):
        self.current = initial
        self.min_timeout = min_timeout
        self.max_timeout = max_timeout
        self.response_times = []
        self.max_samples = 100
    
    def record(self, response_time: float):
        """Record a response time"""
        self.response_times.append(response_time)
        if len(self.response_times) > self.max_samples:
            self.response_times.pop(0)
        
        # Adjust timeout based on average + 2 std deviations
        if len(self.response_times) >= 10:
            avg = sum(self.response_times) / len(self.response_times)
            std = (sum((x - avg) ** 2 for x in self.response_times) / 
                   len(self.response_times)) ** 0.5
            
            new_timeout = avg + (2 * std)
            self.current = max(
                self.min_timeout,
                min(self.max_timeout, new_timeout)
            )
    
    def get_timeout(self) -> float:
        """Get current timeout value"""
        return self.current


class PerformanceMonitor:
    """
    Monitor and track performance metrics
    """
    
    def __init__(self):
        self.metrics = {
            'requests_total': 0,
            'requests_success': 0,
            'requests_failed': 0,
            'total_time': 0.0,
            'avg_response_time': 0.0,
            'min_response_time': float('inf'),
            'max_response_time': 0.0
        }
        self.lock = asyncio.Lock()
    
    async def record_request(self, duration: float, success: bool = True):
        """Record request metrics"""
        async with self.lock:
            self.metrics['requests_total'] += 1
            if success:
                self.metrics['requests_success'] += 1
            else:
                self.metrics['requests_failed'] += 1
            
            self.metrics['total_time'] += duration
            self.metrics['avg_response_time'] = (
                self.metrics['total_time'] / self.metrics['requests_total']
            )
            self.metrics['min_response_time'] = min(
                self.metrics['min_response_time'], duration
            )
            self.metrics['max_response_time'] = max(
                self.metrics['max_response_time'], duration
            )
    
    def get_metrics(self) -> Dict:
        """Get current metrics"""
        return self.metrics.copy()
    
    def get_summary(self) -> str:
        """Get formatted summary"""
        m = self.metrics
        return f"""
Performance Summary:
  Total Requests: {m['requests_total']}
  Successful: {m['requests_success']}
  Failed: {m['requests_failed']}
  Success Rate: {m['requests_success']/m['requests_total']*100:.2f}%
  Avg Response Time: {m['avg_response_time']:.3f}s
  Min Response Time: {m['min_response_time']:.3f}s
  Max Response Time: {m['max_response_time']:.3f}s
"""


def cached(ttl: int = 3600, cache_instance: Optional[LRUCache] = None):
    """
    Decorator for caching function results
    
    Usage:
        @cached(ttl=300)
        async def expensive_function(arg1, arg2):
            ...
    """
    if cache_instance is None:
        cache_instance = LRUCache()
    
    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Generate cache key
            cache_key = cache_instance._generate_key(func.__name__, *args, **kwargs)
            
            # Try to get from cache
            cached_result = cache_instance.get(cache_key)
            if cached_result is not None:
                logger.debug(f"Cache hit for {func.__name__}")
                return cached_result
            
            # Execute function
            logger.debug(f"Cache miss for {func.__name__}")
            result = await func(*args, **kwargs)
            
            # Store in cache
            cache_instance.set(cache_key, result, ttl)
            
            return result
        
        return wrapper
    return decorator


def rate_limited(rate: int = 10, per: float = 1.0):
    """
    Decorator for rate limiting
    
    Usage:
        @rate_limited(rate=5, per=1.0)  # 5 requests per second
        async def api_call():
            ...
    """
    limiter = RateLimiter(rate, per)
    
    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            await limiter.acquire()
            return await func(*args, **kwargs)
        return wrapper
    return decorator


def monitored(monitor: Optional[PerformanceMonitor] = None):
    """
    Decorator for monitoring performance
    
    Usage:
        @monitored()
        async def scan_target(url):
            ...
    """
    if monitor is None:
        monitor = PerformanceMonitor()
    
    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            start = time.time()
            success = True
            
            try:
                result = await func(*args, **kwargs)
                return result
            except Exception as e:
                success = False
                raise e
            finally:
                duration = time.time() - start
                await monitor.record_request(duration, success)
        
        return wrapper
    return decorator


class ParallelExecutor:
    """
    Execute tasks in parallel with configurable concurrency
    """
    
    def __init__(self, max_workers: int = 10):
        self.max_workers = max_workers
        self.semaphore = asyncio.Semaphore(max_workers)
    
    async def execute_task(self, task: Callable, *args, **kwargs):
        """Execute single task with semaphore"""
        async with self.semaphore:
            return await task(*args, **kwargs)
    
    async def execute_all(self, tasks: list) -> list:
        """
        Execute all tasks in parallel
        
        Args:
            tasks: List of (callable, args, kwargs) tuples
        
        Returns:
            List of results in same order as tasks
        """
        coroutines = [
            self.execute_task(task, *args, **kwargs)
            for task, args, kwargs in tasks
        ]
        
        return await asyncio.gather(*coroutines, return_exceptions=True)


class BatchProcessor:
    """
    Process items in batches for efficiency
    """
    
    def __init__(self, batch_size: int = 100, delay: float = 0.1):
        self.batch_size = batch_size
        self.delay = delay
    
    async def process(self, items: list, processor: Callable) -> list:
        """
        Process items in batches
        
        Args:
            items: List of items to process
            processor: Async function to process each item
        
        Returns:
            List of results
        """
        results = []
        
        for i in range(0, len(items), self.batch_size):
            batch = items[i:i + self.batch_size]
            
            # Process batch in parallel
            batch_results = await asyncio.gather(
                *[processor(item) for item in batch],
                return_exceptions=True
            )
            
            results.extend(batch_results)
            
            # Delay between batches
            if i + self.batch_size < len(items):
                await asyncio.sleep(self.delay)
        
        return results


# Global instances
default_cache = LRUCache(max_size=1000, default_ttl=3600)
default_monitor = PerformanceMonitor()


# Usage example
if __name__ == '__main__':
    
    # Example: Cached DNS lookup
    @cached(ttl=300, cache_instance=default_cache)
    @rate_limited(rate=5, per=1.0)
    @monitored(monitor=default_monitor)
    async def dns_lookup(domain: str):
        """Simulated DNS lookup"""
        await asyncio.sleep(0.5)  # Simulate network delay
        return f"IP for {domain}"
    
    async def main():
        # Test caching
        print("First call (should be slow):")
        result = await dns_lookup("example.com")
        print(result)
        
        print("\nSecond call (should be fast - cached):")
        result = await dns_lookup("example.com")
        print(result)
        
        # Get stats
        print("\nCache Stats:")
        print(default_cache.get_stats())
        
        print("\nPerformance Stats:")
        print(default_monitor.get_summary())
    
    asyncio.run(main())
