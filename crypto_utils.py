"""
Secure private key encryption utilities for Exodia Digital
Never logs plaintext private keys to console - this is our security moat
"""
import os
import secrets
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class SecureKeyManager:
    def __init__(self):
        self.salt = self._get_or_create_salt()
        self.key = self._derive_key()
        self.fernet = Fernet(self.key)
    
    def _get_or_create_salt(self) -> bytes:
        """Get or create encryption salt"""
        salt_b64 = os.environ.get('ENCRYPTION_SALT')
        if not salt_b64:
            salt = secrets.token_bytes(16)
            # In production, this should be set via environment
            os.environ['ENCRYPTION_SALT'] = base64.b64encode(salt).decode()
            return salt
        return base64.b64decode(salt_b64)
    
    def _derive_key(self) -> bytes:
        """Derive encryption key from salt and session secret"""
        password = os.environ.get('SESSION_SECRET', 'default-key-change-in-production').encode()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password))
    
    def encrypt_private_key(self, private_key: str) -> str:
        """
        Encrypt private key - NEVER logs plaintext
        Returns base64 encoded encrypted data
        """
        try:
            encrypted_data = self.fernet.encrypt(private_key.encode())
            return base64.b64encode(encrypted_data).decode()
        except Exception as e:
            # Never log the actual private key in error messages
            raise Exception("Private key encryption failed")
    
    def decrypt_private_key(self, encrypted_key: str) -> str:
        """
        Decrypt private key - NEVER logs plaintext to console
        This is our security moat - no plaintext logging
        """
        try:
            encrypted_data = base64.b64decode(encrypted_key)
            decrypted_data = self.fernet.decrypt(encrypted_data)
            return decrypted_data.decode()
        except Exception as e:
            # Never log decryption details that could leak information
            raise Exception("Private key decryption failed")
    
    def is_encrypted(self, key_data: str) -> bool:
        """Check if key data appears to be encrypted"""
        try:
            # Try to decode as base64 - encrypted keys should be base64
            base64.b64decode(key_data)
            # Check if it looks like a raw private key (starts with common patterns)
            if any(key_data.startswith(prefix) for prefix in ['1', '2', '3', '4', '5', 'K', 'L']):
                return False  # Likely unencrypted
            return True  # Likely encrypted
        except:
            return False  # Invalid format

# Global instance
_key_manager = SecureKeyManager()

def encrypt_private_key(private_key: str) -> str:
    """Encrypt private key securely"""
    return _key_manager.encrypt_private_key(private_key)

def decrypt_private_key(encrypted_key: str) -> str:
    """Decrypt private key securely"""
    return _key_manager.decrypt_private_key(encrypted_key)

def is_encrypted(key_data: str) -> bool:
    """Check if key appears encrypted"""
    return _key_manager.is_encrypted(key_data)