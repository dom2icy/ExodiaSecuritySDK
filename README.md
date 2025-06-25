# Exodia Security SDK

Enterprise-grade security components for Python Flask applications with nation-state level protection.

## Core Security Features

### 🔐 Enterprise Security Manager
- **AES-256-GCM Encryption**: Per-key salts + global pepper for maximum security
- **JWT Authentication**: 30-minute access tokens with refresh token rotation
- **Session Management**: Auto-expiration (30 min active, 5 min idle)
- **Rate Limiting**: Sliding window algorithm with Redis backing
- **Audit Logging**: Persistent file-based logging with webhook alerts

### 🛡️ Authentication Middleware
- **Zero Trust Architecture**: All endpoints require explicit permission validation
- **Role-Based Access Control**: Granular permission system with audit trails
- **Token Validation**: Proper JWT signature verification and expiration checks
- **Session Tracking**: Redis-backed session storage with automatic cleanup

### 🌐 CSRF Protection
- **SPA Support**: X-CSRF-TOKEN header validation for single-page applications
- **Token Management**: Secure token generation and validation
- **Request Protection**: Automatic CSRF validation for state-changing operations

### 🔑 Cryptographic Utilities
- **Private Key Encryption**: Fernet-based encryption with PBKDF2 key derivation
- **Secure Key Management**: Zero plaintext logging policy
- **Salt Management**: Per-encryption salts with environment-based pepper

## Quick Start

### 1. Install Dependencies
```bash
pip install flask flask-session redis cryptography pyjwt
```

### 2. Environment Variables
```bash
# Required
export SESSION_SECRET="your-session-secret"
export ENCRYPTION_KEY="your-32-byte-encryption-key"
export ACCESS_TOKEN_SECRET="your-jwt-access-secret"
export REFRESH_TOKEN_SECRET="your-jwt-refresh-secret"

# Optional
export ENCRYPTION_PEPPER="your-global-pepper"
export REDIS_URL="redis://localhost:6379"
export SECURITY_WEBHOOK_URL="https://hooks.slack.com/your-webhook"
```

### 3. Basic Integration
```python
from flask import Flask
from security_manager import security_manager
from auth_routes import auth_bp, authenticate_token
from secure_session_store import setup_secure_session_store
from csrf_spa_middleware import csrf_protect_spa

app = Flask(__name__)
app.secret_key = os.environ.get('SESSION_SECRET')

# Setup secure session storage
setup_secure_session_store(app)

# Register authentication routes
app.register_blueprint(auth_bp)

# Protected endpoint example
@app.route('/api/protected', methods=['POST'])
@authenticate_token('read_permission')
@csrf_protect_spa
def protected_endpoint():
    return {'message': 'Access granted', 'user': request.user}
```

## Security Components

### Enterprise Security Manager
```python
from security_manager import security_manager

# Encrypt sensitive data
encrypted = security_manager.encrypt_sensitive_data(
    "sensitive_data", 
    context="user_private_key",
    user_id="user123"
)

# Create secure session
session = security_manager.create_secure_session(
    user_id="user123",
    permissions=['read', 'write'],
    role='user'
)

# Rate limiting
if security_manager.check_rate_limit("user123", limit=10, window=300):
    # Process request
    pass
```

### Authentication Decorators
```python
from auth_routes import authenticate_token, authorize_roles, sliding_window_rate_limiter

@app.route('/admin/users')
@authenticate_token('admin_access')
@authorize_roles('admin', 'superuser')
@sliding_window_rate_limiter(max_requests=5, window_ms=60000)
def admin_users():
    return {'users': get_users()}
```

### CSRF Protection
```python
from csrf_spa_middleware import csrf_protect_spa

@app.route('/api/update', methods=['POST'])
@csrf_protect_spa
def update_data():
    # Automatically validates X-CSRF-TOKEN header
    return {'status': 'updated'}
```

### Private Key Encryption
```python
from crypto_utils import encrypt_private_key, decrypt_private_key

# Encrypt private key
encrypted_key = encrypt_private_key("your_private_key")

# Decrypt when needed (never logs plaintext)
private_key = decrypt_private_key(encrypted_key)
```

## Security Architecture

### Encryption Layers
1. **Client-Side**: Web Crypto API AES-GCM encryption (if applicable)
2. **Transport**: HTTPS with certificate validation
3. **Server-Side**: AES-256-GCM with salt & pepper
4. **Storage**: Database encryption with versioning

### Authentication Flow
1. **Login**: JWT access/refresh token generation with permissions
2. **Validation**: Token signature verification and permission checks
3. **Authorization**: Role-based access control with audit logging
4. **Refresh**: Automatic token rotation with session tracking
5. **Logout**: Session invalidation and cleanup

### Audit Trail
- All security events logged with timestamps
- Failed authentication attempts tracked with rate limiting
- Encryption operations monitored for integrity
- Critical alerts sent via webhook for immediate response

## Production Deployment

### Security Checklist
- [ ] Set strong `SESSION_SECRET` (32+ random bytes)
- [ ] Configure `ENCRYPTION_KEY` (32 bytes, base64 encoded)
- [ ] Set unique JWT secrets for access/refresh tokens
- [ ] Enable Redis for session storage in production
- [ ] Configure security webhook for critical alerts
- [ ] Set `ENCRYPTION_PEPPER` for additional entropy
- [ ] Enable HTTPS with proper certificates
- [ ] Configure rate limiting based on traffic patterns

### Environment Security
```bash
# Generate secure keys
python -c "import secrets, base64; print(base64.b64encode(secrets.token_bytes(32)).decode())"

# Redis configuration
export REDIS_URL="redis://username:password@host:port/db"

# Webhook alerts
export SECURITY_WEBHOOK_URL="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
```

## API Endpoints

### Authentication
- `POST /auth/login` - User authentication with credentials
- `POST /auth/refresh` - Refresh access token using refresh token
- `POST /auth/logout` - Invalidate session and tokens
- `GET /auth/status` - Check authentication status
- `GET /auth/audit` - Security audit log (admin only)

### CSRF Protection
- `GET /api/csrf-token` - Get CSRF token for SPA frontend

## Error Handling

### Security Errors
```python
from security_manager import SecurityError

try:
    user = security_manager.authenticate_token(token)
except SecurityError as e:
    return jsonify({'error': str(e)}), 401
```

### Rate Limiting
```python
if not security_manager.check_rate_limit(identifier):
    return jsonify({
        'error': 'Rate limit exceeded',
        'retry_after': 300
    }), 429
```

## Monitoring & Alerts

### Security Events
- Authentication failures with IP tracking
- Encryption/decryption errors with context
- Rate limit violations with user identification
- Session anomalies and unauthorized access attempts
- Token tampering and signature validation failures

### Webhook Integration
Configure `SECURITY_WEBHOOK_URL` to receive real-time security alerts via Slack or other webhook services.

## License

Proprietary - Exodia Security SDK

## Support

For security vulnerabilities or questions: security@exodia.digital

---

**🔐 Nation-State Level Security | 🛡️ Zero Trust Architecture | 📊 Complete Audit Trail**