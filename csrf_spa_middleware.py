"""
CSRF Protection for SPA Frontend
Handles token-passing pattern for React/Vue/Angular applications
"""
from flask import request, jsonify, session
from functools import wraps
import secrets

def generate_csrf_token():
    """Generate a new CSRF token"""
    token = secrets.token_urlsafe(32)
    session['csrf_token'] = token
    return token

def get_csrf_token():
    """Get current CSRF token or generate new one"""
    if 'csrf_token' not in session:
        return generate_csrf_token()
    return session['csrf_token']

def csrf_protect_spa(f):
    """
    CSRF protection decorator for SPA endpoints
    Validates X-CSRF-TOKEN header
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method in ['POST', 'PUT', 'DELETE', 'PATCH']:
            # Get token from custom header (SPA pattern)
            token_from_header = request.headers.get('X-CSRF-TOKEN')
            token_from_session = session.get('csrf_token')
            
            if not token_from_header or not token_from_session:
                return jsonify({'error': 'CSRF token missing'}), 400
            
            if not secrets.compare_digest(token_from_header, token_from_session):
                return jsonify({'error': 'CSRF token invalid'}), 403
        
        return f(*args, **kwargs)
    
    return decorated_function

def csrf_token_endpoint():
    """Endpoint for SPA to fetch CSRF token"""
    token = get_csrf_token()
    return jsonify({'csrf_token': token})