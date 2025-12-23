"""
RedHawk Automation & Workflow Module
Scheduled scanning, webhooks, CI/CD integration
"""

import asyncio
import aiohttp
from typing import Dict, Callable, Optional
from datetime import datetime, timedelta
import schedule
import logging

logger = logging.getLogger(__name__)


class Automation:
    """Automation and workflow management"""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.scheduled_jobs = []
        self.webhooks = self.config.get('webhooks', {})
    
    def schedule_scan(self, target: str, interval: str, callback: Callable):
        """Schedule recurring scan"""
        if interval == 'daily':
            schedule.every().day.at("02:00").do(callback, target)
        elif interval == 'weekly':
            schedule.every().week.do(callback, target)
        elif interval == 'hourly':
            schedule.every().hour.do(callback, target)
        
        logger.info(f"Scheduled {interval} scan for {target}")
    
    async def send_webhook(self, event: str, data: Dict):
        """Send webhook notification"""
        webhook_url = self.webhooks.get(event)
        
        if not webhook_url:
            return
        
        payload = {
            'event': event,
            'timestamp': datetime.now().isoformat(),
            'data': data
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(webhook_url, json=payload) as response:
                    if response.status == 200:
                        logger.info(f"Webhook sent for {event}")
                    else:
                        logger.error(f"Webhook failed: {response.status}")
        except Exception as e:
            logger.error(f"Error sending webhook: {e}")
    
    async def send_slack_notification(self, message: str):
        """Send Slack notification"""
        slack_url = self.config.get('slack_webhook')
        
        if not slack_url:
            return
        
        payload = {'text': message}
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(slack_url, json=payload) as response:
                    logger.info("Slack notification sent")
        except Exception as e:
            logger.error(f"Error sending Slack notification: {e}")
    
    def run_scheduler(self):
        """Run scheduled jobs"""
        while True:
            schedule.run_pending()
            asyncio.sleep(60)


def setup_automation(config: Dict) -> Automation:
    """Setup automation"""
    return Automation(config)
