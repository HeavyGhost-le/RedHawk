"""
RedHawk Database Module
SQLite and PostgreSQL support for scan history
"""

import sqlite3
import json
from datetime import datetime
from typing import Dict, List, Optional
import logging

logger = logging.getLogger(__name__)


class Database:
    """Database for scan results"""
    
    def __init__(self, db_path: str = 'redhawk.db'):
        self.db_path = db_path
        self.conn = None
        self._init_db()
    
    def _init_db(self):
        """Initialize database"""
        self.conn = sqlite3.connect(self.db_path)
        cursor = self.conn.cursor()
        
        # Create tables
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                scan_type TEXT,
                timestamp TEXT NOT NULL,
                results TEXT,
                status TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                severity TEXT,
                type TEXT,
                description TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            )
        ''')
        
        self.conn.commit()
    
    def save_scan(self, target: str, scan_type: str, results: Dict) -> int:
        """Save scan results"""
        cursor = self.conn.cursor()
        
        cursor.execute('''
            INSERT INTO scans (target, scan_type, timestamp, results, status)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            target,
            scan_type,
            datetime.now().isoformat(),
            json.dumps(results),
            'completed'
        ))
        
        self.conn.commit()
        return cursor.lastrowid
    
    def get_scan_history(self, target: str, limit: int = 10) -> List[Dict]:
        """Get scan history for target"""
        cursor = self.conn.cursor()
        
        cursor.execute('''
            SELECT id, scan_type, timestamp, status
            FROM scans
            WHERE target = ?
            ORDER BY timestamp DESC
            LIMIT ?
        ''', (target, limit))
        
        rows = cursor.fetchall()
        
        return [
            {
                'id': row[0],
                'scan_type': row[1],
                'timestamp': row[2],
                'status': row[3]
            }
            for row in rows
        ]
    
    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()
