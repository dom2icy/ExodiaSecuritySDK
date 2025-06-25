"""
Enterprise Security Manager for Exodia Digital
Implements proper AES-256-GCM encryption and JWT authentication
Based on Node.js crypto patterns for consistency
"""
import os
import json
import jwt
import time
import redis
import logging
import secrets
import base64
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from flask import g

# Configure logging
logger = logging.getLogger(__name__)

class EnterpriseSecurityManager:
    """
    Enterprise-grade security manager with proper AES-256-GCM encryption
    Follows Node.js crypto patterns for consistency
    """
    
    def __init__(self):
        self.redis_client = None
        self.encryption_key = self._get_or_create_encryption_key()
        self.access_token_secret = self._get_or_create_jwt_secret('ACCESS_TOKEN_SECRET')
        self.refresh_token_secret = self._get_or_create_jwt_secret('REFRESH_TOKEN_SECRET')
        
        try:
            redis_url = os.environ.get('REDIS_URL', 'redis://localhost:6379')
            self.redis_client = redis.from_url(redis_url, decode_responses=True)
            self.redis_client.ping()
        except Exception as e:
            logger.warning(f"Redis unavailable, using in-memory storage: {e}")
            self.redis_client = None
    
    def _get_or_create_encryption_key(self) -> bytes:
        """Get or create AES-256 encryption key (32 bytes)"""
        key_b64 = os.environ.get('ENCRYPTION_KEY')
        if not key_b64:
            key = secrets.token_bytes(32)
            key_b64 = base64.b64encode(key).decode()
            logger.warning("ENCRYPTION_KEY not found in environment, generated temporary key")
        else:
            key = base64.b64decode(key_b64)
        return key
    
    def _get_or_create_jwt_secret(self, env_name: str) -> str:
        """Get or create JWT signing secret"""
        secret = os.environ.get(env_name)
        if not secret:
            secret = base64.b64encode(secrets.token_bytes(32)).decode()
            logger.warning(f"{env_name} not found in environment, generated temporary secret")
        return secret
    
    def encrypt_sensitive_data(self, text: str, context: str = None, user_id: str = None) -> str:
        """
        Encrypt sensitive data using AES-256-GCM with salt & pepper
        Returns format: salt:iv:authTag:encrypted (matching Node.js pattern)
        """
        try:
            # Per-key salt for unique encryption even with same data
            salt = os.urandom(16)  # 128-bit salt per encryption
            
            # Pepper from environment (global secret)
            pepper = os.environ.get('ENCRYPTION_PEPPER', 'default_pepper_change_me')
            
            # Derive key using salt + pepper + base key
            base_key = self._get_or_create_encryption_key()
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt + pepper.encode('utf-8'),
                iterations=100000,
                backend=default_backend()
            )
            derived_key = kdf.derive(base_key)
            
            # Generate random IV for each encryption
            iv = os.urandom(12)  # 96-bit IV for GCM mode
            
            # Create cipher with derived key
            cipher = Cipher(algorithms.AES(derived_key), modes.GCM(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            
            # Encrypt the data
            ciphertext = encryptor.update(text.encode('utf-8')) + encryptor.finalize()
            
            # Format: salt:iv:authTag:encrypted (hex encoded)
            encrypted_data = f"{salt.hex()}:{iv.hex()}:{encryptor.tag.hex()}:{ciphertext.hex()}"
            
            if context:
                self._log_security_event('data_encrypted', {
                    'context': context, 
                    'data_length': len(text),
                    'user_id': user_id,
                    'salt_length': len(salt)
                })
                
            return encrypted_data
            
        except Exception as e:
            self._log_security_event('encryption_error', {'error': str(e), 'context': context, 'user_id': user_id})
            raise SecurityError(f"Encryption failed: {str(e)}")
    
    def decrypt_sensitive_data(self, encrypted_text: str, context: str = None, user_id: str = None) -> str:
        """
        Decrypt sensitive data using AES-256-GCM with salt & pepper
        Expects format: salt:iv:authTag:encrypted (hex encoded)
        """
        try:
            parts = encrypted_text.split(':')
            
            # Handle both old (3 parts) and new (4 parts) formats for backward compatibility
            if len(parts) == 3:
                # Old format: iv:authTag:encrypted
                iv_hex, auth_tag_hex, ciphertext_hex = parts
                key = self._get_or_create_encryption_key()
            elif len(parts) == 4:
                # New format: salt:iv:authTag:encrypted
                salt_hex, iv_hex, auth_tag_hex, ciphertext_hex = parts
                
                # Recreate derived key using salt + pepper
                salt = bytes.fromhex(salt_hex)
                pepper = os.environ.get('ENCRYPTION_PEPPER', 'default_pepper_change_me')
                base_key = self._get_or_create_encryption_key()
                
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt + pepper.encode('utf-8'),
                    iterations=100000,
                    backend=default_backend()
                )
                key = kdf.derive(base_key)
            else:
                raise SecurityError("Invalid encrypted data format")
                
            # Convert from hex
            iv = bytes.fromhex(iv_hex)
            auth_tag = bytes.fromhex(auth_tag_hex)
            ciphertext = bytes.fromhex(ciphertext_hex)
            
            # Create cipher
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv, auth_tag), backend=default_backend())
            decryptor = cipher.decryptor()
            
            # Decrypt the data
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            if context:
                self._log_security_event('data_decrypted', {'context': context, 'user_id': user_id})
                
            return plaintext.decode('utf-8')
            
        except Exception as e:
            self._log_security_event('decryption_error', {'error': str(e), 'context': context, 'user_id': user_id})
            raise SecurityError(f"Decryption failed: {str(e)}")
    
    def create_secure_session(self, user_id: str, permissions: list = None, role: str = 'user') -> dict:
        """
        Create secure session with access and refresh tokens
        Following Node.js JWT patterns
        """
        try:
            now = datetime.utcnow()
            session_id = secrets.token_urlsafe(32)
            
            # Access token (short-lived - 30 minutes)
            access_payload = {
                'user_id': user_id,
                'session_id': session_id,
                'permissions': permissions or [],
                'role': role,
                'type': 'access',
                'iat': now,
                'exp': now + timedelta(minutes=30)
            }
            
            # Refresh token (longer-lived - 7 days)
            refresh_payload = {
                'user_id': user_id,
                'session_id': session_id,
                'type': 'refresh',
                'iat': now,
                'exp': now + timedelta(days=7)
            }
            
            access_token = jwt.encode(access_payload, self.access_token_secret, algorithm='HS256')
            refresh_token = jwt.encode(refresh_payload, self.refresh_token_secret, algorithm='HS256')
            
            # Store session data
            session_data = {
                'user_id': user_id,
                'permissions': permissions or [],
                'role': role,
                'created_at': now.isoformat(),
                'last_activity': now.isoformat()
            }
            
            if self.redis_client:
                self.redis_client.setex(f"session:{session_id}", 1800, json.dumps(session_data))
            
            self._log_security_event('session_created', {
                'user_id': user_id,
                'session_id': session_id,
                'permissions': permissions,
                'role': role
            })
            
            return {
                'access_token': access_token,
                'refresh_token': refresh_token,
                'expires_in': 1800,
                'session_id': session_id
            }
            
        except Exception as e:
            self._log_security_event('session_creation_error', {'error': str(e), 'user_id': user_id})
            raise SecurityError(f"Session creation failed: {str(e)}")
    
    def authenticate_token(self, token: str, required_permission: str = None) -> dict:
        """
        Authenticate access token (similar to Node.js authenticateToken middleware)
        """
        try:
            payload = jwt.decode(token, self.access_token_secret, algorithms=['HS256'])
            
            if payload.get('type') != 'access':
                raise SecurityError("Invalid token type")
            
            session_id = payload.get('session_id')
            user_id = payload.get('user_id')
            
            # Check if session is still valid
            if self.redis_client:
                session_data = self.redis_client.get(f"session:{session_id}")
                if not session_data:
                    raise SecurityError("Session expired")
                
                # Update last activity
                session_info = json.loads(session_data)
                session_info['last_activity'] = datetime.utcnow().isoformat()
                self.redis_client.setex(f"session:{session_id}", 1800, json.dumps(session_info))
            
            # Check permissions if required
            if required_permission:
                permissions = payload.get('permissions', [])
                if required_permission not in permissions and payload.get('role') != 'admin':
                    self._log_security_event('authorization_failure', {
                        'user_id': user_id,
                        'required_permission': required_permission,
                        'user_permissions': permissions
                    })
                    raise SecurityError("Insufficient permissions")
            
            return payload
            
        except jwt.ExpiredSignatureError:
            self._log_security_event('token_expired', {'token_type': 'access'})
            raise SecurityError("Token expired")
        except jwt.InvalidTokenError as e:
            self._log_security_event('token_invalid', {'error': str(e)})
            raise SecurityError("Invalid token")
    
    def authorize_roles(self, allowed_roles: list, user_payload: dict) -> bool:
        """
        Authorize user roles (similar to Node.js authorizeRoles middleware)
        """
        user_role = user_payload.get('role', 'user')
        if user_role not in allowed_roles:
            self._log_security_event('role_authorization_failure', {
                'user_id': user_payload.get('user_id'),
                'user_role': user_role,
                'allowed_roles': allowed_roles
            })
            return False
        return True
    
    def refresh_session(self, refresh_token: str) -> dict:
        """
        Refresh session using refresh token
        """
        try:
            payload = jwt.decode(refresh_token, self.refresh_token_secret, algorithms=['HS256'])
            
            if payload.get('type') != 'refresh':
                raise SecurityError("Invalid token type")
            
            user_id = payload.get('user_id')
            session_id = payload.get('session_id')
            
            # Get stored session data
            if self.redis_client:
                session_data = self.redis_client.get(f"session:{session_id}")
                if not session_data:
                    raise SecurityError("Session not found")
                
                session_info = json.loads(session_data)
                permissions = session_info.get('permissions', [])
                role = session_info.get('role', 'user')
            else:
                permissions = []
                role = 'user'
            
            # Create new access token
            return self.create_secure_session(user_id, permissions, role)
            
        except jwt.ExpiredSignatureError:
            self._log_security_event('refresh_token_expired', {})
            raise SecurityError("Refresh token expired")
        except jwt.InvalidTokenError as e:
            self._log_security_event('refresh_token_invalid', {'error': str(e)})
            raise SecurityError("Invalid refresh token")
    
    def check_rate_limit(self, identifier: str, limit: int = 10, window: int = 300) -> bool:
        """
        Advanced rate limiting with sliding window
        """
        try:
            now = time.time()
            key = f"rate_limit:{identifier}"
            
            if self.redis_client:
                # Sliding window using sorted sets
                pipe = self.redis_client.pipeline()
                pipe.zremrangebyscore(key, 0, now - window)
                pipe.zcard(key)
                pipe.zadd(key, {str(now): now})
                pipe.expire(key, window)
                results = pipe.execute()
                
                current_count = results[1]
                
                if current_count >= limit:
                    self._log_security_event('rate_limit_exceeded', {
                        'identifier': identifier,
                        'current_count': current_count,
                        'limit': limit,
                        'window': window
                    })
                    return False
                
                return True
            else:
                # Simple in-memory fallback
                if not hasattr(self, '_rate_limits'):
                    self._rate_limits = {}
                
                if identifier not in self._rate_limits:
                    self._rate_limits[identifier] = []
                
                # Clean old entries
                self._rate_limits[identifier] = [
                    timestamp for timestamp in self._rate_limits[identifier]
                    if timestamp > now - window
                ]
                
                if len(self._rate_limits[identifier]) >= limit:
                    return False
                
                self._rate_limits[identifier].append(now)
                return True
                
        except Exception as e:
            logger.error(f"Rate limit check failed: {e}")
            return True  # Fail open for availability
    
    def invalidate_session(self, session_id: str):
        """Invalidate session and log event"""
        try:
            if self.redis_client:
                self.redis_client.delete(f"session:{session_id}")
            
            self._log_security_event('session_invalidated', {'session_id': session_id})
            
        except Exception as e:
            logger.error(f"Session invalidation failed: {e}")
    
    def _log_security_event(self, event_type: str, details: dict):
        """Log security events for audit trail with persistent storage"""
        try:
            event = {
                'timestamp': datetime.utcnow().isoformat(),
                'event_type': event_type,
                'details': details,
                'session_id': getattr(g, 'session_id', 'unknown')
            }
            
            # Store in memory for immediate access
            if not hasattr(self, '_security_log'):
                self._security_log = []
            
            self._security_log.append(event)
            
            # Keep only last 1000 events in memory to prevent bloat
            if len(self._security_log) > 1000:
                self._security_log = self._security_log[-1000:]
            
            # Persistent storage to file for audit compliance
            log_file = os.path.join(os.getcwd(), 'security_audit.log')
            with open(log_file, 'a', encoding='utf-8') as f:
                f.write(f"{json.dumps(event)}\n")
            
            # Send alerts for critical events
            if event_type in ['encryption_error', 'decryption_error', 'authentication_failure']:
                self._send_security_alert(event_type, details)
                
            logging.info(f"Security event: {event_type} - {details}")
            
        except Exception as e:
            logging.error(f"Failed to log security event: {e}")
    
    def _send_security_alert(self, event_type: str, details: dict):
        """Send security alerts via webhook/Slack for critical events"""
        try:
            webhook_url = os.environ.get('SECURITY_WEBHOOK_URL')
            if not webhook_url:
                return
                
            alert_payload = {
                'text': f'🚨 SECURITY ALERT: {event_type}',
                'attachments': [{
                    'color': 'danger',
                    'fields': [
                        {'title': 'Event Type', 'value': event_type, 'short': True},
                        {'title': 'Timestamp', 'value': datetime.utcnow().isoformat(), 'short': True},
                        {'title': 'Details', 'value': str(details), 'short': False}
                    ]
                }]
            }
            
            # Send webhook in background (non-blocking)
            import threading
            import requests
            
            def send_webhook():
                try:
                    requests.post(webhook_url, json=alert_payload, timeout=5)
                except:
                    pass  # Fail silently to not break app flow
            
            threading.Thread(target=send_webhook, daemon=True).start()
            
        except Exception as e:
            logging.warning(f"Failed to send security alert: {e}")
    
    def get_security_audit_log(self, limit: int = 100) -> list:
        """Get recent security events for audit"""
        if hasattr(self, '_security_log'):
            return self._security_log[-limit:]
        return []
    
    def cleanup_expired_sessions(self):
        """Clean up expired sessions"""
        try:
            if self.redis_client:
                # Redis handles expiration automatically
                pass
            
            self._log_security_event('session_cleanup', {'timestamp': datetime.utcnow().isoformat()})
            
        except Exception as e:
            logger.error(f"Session cleanup failed: {e}")

class SecurityError(Exception):
    """Custom security exception"""
    pass

# Global instance
security_manager = EnterpriseSecurityManager()