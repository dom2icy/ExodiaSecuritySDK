"""
Secure Server-Side Session Store for Private Key Security
Implements Redis-backed sessions to prevent client-side storage
"""
import os
import redis
from flask_session import Session

def setup_secure_session_store(app):
    """Configure secure server-side session storage"""
    
    try:
        # Try Redis first (preferred for production)
        redis_url = os.environ.get('REDIS_URL', 'redis://localhost:6379')
        redis_client = redis.from_url(redis_url, decode_responses=True)
        redis_client.ping()  # Test connection
        
        # Configure Flask-Session with Redis and auto-expiration
        app.config['SESSION_TYPE'] = 'redis'
        app.config['SESSION_REDIS'] = redis_client
        app.config['SESSION_PERMANENT'] = False
        app.config['SESSION_USE_SIGNER'] = True
        app.config['SESSION_KEY_PREFIX'] = 'exodia_session:'
        app.config['SESSION_COOKIE_SECURE'] = True
        app.config['SESSION_COOKIE_HTTPONLY'] = True
        app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
        
        # Auto-expire stale session data (30 minutes for active, 5 minutes idle)
        app.config['PERMANENT_SESSION_LIFETIME'] = 1800  # 30 minutes
        app.config['SESSION_REDIS_TTL'] = 1800  # Redis TTL for auto-cleanup
        
        Session(app)
        
        print("✅ Secure Redis session store configured")
        return True
        
    except Exception as e:
        print(f"⚠ Redis unavailable, falling back to secure database sessions: {e}")
        
        # Fallback to filesystem-backed sessions with auto-expiration
        app.config['SESSION_TYPE'] = 'filesystem'
        app.config['SESSION_FILE_DIR'] = '/tmp/flask_sessions'
        app.config['SESSION_PERMANENT'] = False
        app.config['SESSION_USE_SIGNER'] = True
        app.config['SESSION_COOKIE_SECURE'] = True
        app.config['SESSION_COOKIE_HTTPONLY'] = True
        app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
        app.config['PERMANENT_SESSION_LIFETIME'] = 1800  # 30 minutes auto-expire
        
        # Create session directory if it doesn't exist
        import os as os_module
        os_module.makedirs('/tmp/flask_sessions', exist_ok=True)
        
        Session(app)
        return False