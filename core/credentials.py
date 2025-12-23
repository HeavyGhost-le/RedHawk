"""
RedHawk Credentials Management
Secure storage for API keys and secrets
"""

import os
import json
from pathlib import Path
from cryptography.fernet import Fernet
import logging

logger = logging.getLogger(__name__)


class CredentialManager:
    """Secure credential storage"""
    
    def __init__(self, keyfile: str = '.redhawk_key'):
        self.keyfile = Path.home() / keyfile
        self.credentials_file = Path.home() / '.redhawk_credentials'
        self.cipher = self._load_or_create_key()
    
    def _load_or_create_key(self) -> Fernet:
        """Load or create encryption key"""
        if self.keyfile.exists():
            key = self.keyfile.read_bytes()
        else:
            key = Fernet.generate_key()
            self.keyfile.write_bytes(key)
            self.keyfile.chmod(0o600)
        
        return Fernet(key)
    
    def store(self, name: str, value: str):
        """Store credential"""
        credentials = self._load_credentials()
        credentials[name] = value
        self._save_credentials(credentials)
        logger.info(f"Stored credential: {name}")
    
    def get(self, name: str) -> str:
        """Retrieve credential"""
        credentials = self._load_credentials()
        return credentials.get(name)
    
    def delete(self, name: str):
        """Delete credential"""
        credentials = self._load_credentials()
        if name in credentials:
            del credentials[name]
            self._save_credentials(credentials)
            logger.info(f"Deleted credential: {name}")
    
    def list(self) -> list:
        """List all credential names"""
        credentials = self._load_credentials()
        return list(credentials.keys())
    
    def _load_credentials(self) -> Dict:
        """Load credentials from file"""
        if not self.credentials_file.exists():
            return {}
        
        encrypted_data = self.credentials_file.read_bytes()
        decrypted_data = self.cipher.decrypt(encrypted_data)
        return json.loads(decrypted_data)
    
    def _save_credentials(self, credentials: Dict):
        """Save credentials to file"""
        json_data = json.dumps(credentials)
        encrypted_data = self.cipher.encrypt(json_data.encode())
        self.credentials_file.write_bytes(encrypted_data)
        self.credentials_file.chmod(0o600)
