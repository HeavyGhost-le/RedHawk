"""
RedHawk Smart Scanning Logic
ML-based prioritization and adaptive scanning
"""

import asyncio
from typing import Dict, List
import logging

logger = logging.getLogger(__name__)


class SmartScanner:
    """Smart scanning with ML prioritization"""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.timeout_base = 10.0
        self.failed_targets = set()
    
    async def scan_targets(self, targets: List[str], modules: List) -> List[Dict]:
        """Smart scan with prioritization"""
        # Prioritize targets
        prioritized = self._prioritize_targets(targets)
        
        results = []
        for target in prioritized:
            if target in self.failed_targets:
                continue
            
            try:
                result = await self._scan_target(target, modules)
                results.append(result)
            except asyncio.TimeoutError:
                logger.warning(f"Timeout scanning {target}")
                self.failed_targets.add(target)
                self._adjust_timeout(increase=True)
            except Exception as e:
                logger.error(f"Error scanning {target}: {e}")
        
        return results
    
    def _prioritize_targets(self, targets: List[str]) -> List[str]:
        """Prioritize targets by criticality"""
        # Simple keyword-based prioritization
        critical_keywords = ['admin', 'api', 'mail', 'vpn', 'auth']
        
        def priority_score(target: str) -> int:
            score = 0
            target_lower = target.lower()
            for keyword in critical_keywords:
                if keyword in target_lower:
                    score += 10
            return score
        
        return sorted(targets, key=priority_score, reverse=True)
    
    async def _scan_target(self, target: str, modules: List) -> Dict:
        """Scan single target"""
        result = {'target': target, 'modules': {}}
        
        for module in modules:
            try:
                module_result = await asyncio.wait_for(
                    module.scan(target),
                    timeout=self.timeout_base
                )
                result['modules'][module.name] = module_result
            except asyncio.TimeoutError:
                raise
        
        return result
    
    def _adjust_timeout(self, increase: bool = True):
        """Adaptively adjust timeout"""
        if increase:
            self.timeout_base = min(self.timeout_base * 1.5, 60.0)
        else:
            self.timeout_base = max(self.timeout_base * 0.8, 5.0)
        
        logger.info(f"Adjusted timeout to {self.timeout_base:.1f}s")
