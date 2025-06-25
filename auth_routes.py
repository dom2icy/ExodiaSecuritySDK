"""
Authentication routes with proper Node.js-style middleware patterns
Implements proper environment validation and audit logging
"""
import os
import json
import logging
from functools import wraps
from datetime import datetime
from flask import Blueprint, request, jsonify, session
from security_manager import security_manager, SecurityError

# Configure logging
logger = logging.getLogger(__name__)

# Create authentication blueprint
auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

def validate_environment():
    """Validate required environment variables on startup"""
    required_vars = [
        'ACCESS_TOKEN_SECRET',
        'REFRESH_TOKEN_SECRET', 
        'ENCRYPTION_KEY'
    ]
    
    missing_vars = []
    for var in required_vars:
        if not os.environ.get(var):
            logger.error(f"Missing required environment variable: {var}")
            missing_vars.append(var)
    
    if missing_vars:
        logger.warning(f"Environment validation failed: Missing required environment variables: {', '.join(missing_vars)}")
        return False
    
    return True

def authenticate_token(required_permission=None):
    """
    Flask decorator matching Node.js authenticateToken middleware pattern
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                auth_header = request.headers.get('Authorization')
                if not auth_header or not auth_header.startswith('Bearer '):
                    return jsonify({'error': 'Missing or invalid authorization header'}), 401
                
                token = auth_header.split(' ')[1]
                user_payload = security_manager.authenticate_token(token, required_permission)
                
                # Store user info in request context
                request.user = user_payload
                
                return f(*args, **kwargs)
                
            except SecurityError as e:
                return jsonify({'error': str(e)}), 401
            except Exception as e:
                logger.error(f"Authentication error: {e}")
                return jsonify({'error': 'Authentication failed'}), 500
        
        return decorated_function
    return decorator

def authorize_roles(*allowed_roles):
    """
    Flask decorator matching Node.js authorizeRoles middleware pattern
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                if not hasattr(request, 'user'):
                    return jsonify({'error': 'Authentication required'}), 401
                
                if not security_manager.authorize_roles(list(allowed_roles), request.user):
                    return jsonify({'error': 'Insufficient permissions'}), 403
                
                return f(*args, **kwargs)
                
            except Exception as e:
                logger.error(f"Authorization error: {e}")
                return jsonify({'error': 'Authorization failed'}), 500
        
        return decorated_function
    return decorator

def sliding_window_rate_limiter(max_requests=10, window_ms=300000):
    """
    Flask decorator matching Node.js slidingWindowRateLimiter pattern
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                # Use IP address or user ID as identifier
                identifier = request.remote_addr
                if hasattr(request, 'user'):
                    identifier = f"user:{request.user.get('user_id', identifier)}"
                
                window_seconds = window_ms // 1000
                
                if not security_manager.check_rate_limit(identifier, max_requests, window_seconds):
                    return jsonify({
                        'error': 'Rate limit exceeded',
                        'retry_after': window_seconds
                    }), 429
                
                return f(*args, **kwargs)
                
            except Exception as e:
                logger.error(f"Rate limiting error: {e}")
                return f(*args, **kwargs)  # Fail open
        
        return decorated_function
    return decorator

def log_audit_event(user_id, action, details=''):
    """
    Audit logging matching Node.js logEvent pattern
    """
    try:
        security_manager._log_security_event('user_action', {
            'user_id': user_id,
            'action': action,
            'details': details,
            'ip_address': request.remote_addr,
            'user_agent': request.headers.get('User-Agent', ''),
            'timestamp': datetime.utcnow().isoformat()
        })
    except Exception as e:
        logger.error(f"Audit logging failed: {e}")

@auth_bp.route('/login', methods=['POST'])
@sliding_window_rate_limiter(max_requests=5, window_ms=300000)
def login():
    """
    Secure login endpoint with proper validation
    """
    try:
        data = request.get_json()
        
        if not data or not data.get('username') or not data.get('password'):
            return jsonify({'error': 'Username and password required'}), 400
        
        username = data['username']
        password = data['password']
        
        # TODO: Implement actual user authentication against database
        # For now, this is a placeholder that should be replaced with real auth
        if username == 'admin' and password == 'secure_password':
            user_id = 'admin_user'
            permissions = ['read', 'write', 'admin']
            role = 'admin'
        else:
            log_audit_event('unknown', 'failed_login', f'Username: {username}')
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Create secure session
        session_data = security_manager.create_secure_session(user_id, permissions, role)
        
        log_audit_event(user_id, 'successful_login', f'Username: {username}')
        
        return jsonify({
            'access_token': session_data['access_token'],
            'refresh_token': session_data['refresh_token'],
            'expires_in': session_data['expires_in'],
            'user': {
                'id': user_id,
                'username': username,
                'role': role,
                'permissions': permissions
            }
        })
        
    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify({'error': 'Login failed'}), 500

@auth_bp.route('/refresh', methods=['POST'])
@sliding_window_rate_limiter(max_requests=10, window_ms=300000)
def refresh_token():
    """
    Refresh access token using refresh token
    """
    try:
        data = request.get_json()
        
        if not data or not data.get('refresh_token'):
            return jsonify({'error': 'Refresh token required'}), 400
        
        refresh_token = data['refresh_token']
        
        # Refresh session
        session_data = security_manager.refresh_session(refresh_token)
        
        return jsonify({
            'access_token': session_data['access_token'],
            'refresh_token': session_data['refresh_token'],
            'expires_in': session_data['expires_in']
        })
        
    except SecurityError as e:
        return jsonify({'error': str(e)}), 401
    except Exception as e:
        logger.error(f"Token refresh error: {e}")
        return jsonify({'error': 'Token refresh failed'}), 500

@auth_bp.route('/logout', methods=['POST'])
@authenticate_token()
def logout():
    """
    Secure logout with session invalidation
    """
    try:
        user_id = request.user.get('user_id')
        session_id = request.user.get('session_id')
        
        # Invalidate session
        security_manager.invalidate_session(session_id)
        
        log_audit_event(user_id, 'logout', 'User logged out')
        
        return jsonify({'message': 'Logged out successfully'})
        
    except Exception as e:
        logger.error(f"Logout error: {e}")
        return jsonify({'error': 'Logout failed'}), 500

@auth_bp.route('/status', methods=['GET'])
@authenticate_token()
def auth_status():
    """
    Check authentication status
    """
    try:
        return jsonify({
            'authenticated': True,
            'user': {
                'id': request.user.get('user_id'),
                'role': request.user.get('role'),
                'permissions': request.user.get('permissions', [])
            },
            'session_id': request.user.get('session_id')
        })
        
    except Exception as e:
        logger.error(f"Auth status error: {e}")
        return jsonify({'error': 'Status check failed'}), 500

@auth_bp.route('/audit', methods=['GET'])
@authenticate_token()
@authorize_roles('admin')
def security_audit_log():
    """
    Get security audit log (admin only)
    """
    try:
        limit = request.args.get('limit', 100, type=int)
        limit = min(limit, 1000)  # Cap at 1000 events
        
        events = security_manager.get_security_audit_log(limit)
        
        return jsonify({
            'events': events,
            'count': len(events)
        })
        
    except Exception as e:
        logger.error(f"Audit log error: {e}")
        return jsonify({'error': 'Audit log retrieval failed'}), 500

# Validate environment on module import
validate_environment()