"""
OAuth2 Authentication Module for CA Manager 6.0.0
Handles Google and Microsoft authentication flows
"""

import json
import secrets
from typing import Dict, Any, Optional
from flask import Flask, redirect, url_for, session, request, jsonify
from authlib.integrations.flask_client import OAuth
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token
import msal
import logging
from datetime import datetime, timedelta
from idp_config import IDPConfig

logger = logging.getLogger(__name__)

class IDPAuthManager:
    """Manages OAuth2 authentication for multiple IDPs"""
    
    def __init__(self, app: Flask = None):
        self.app = app
        self.oauth = None
        self.google_client = None
        self.microsoft_app = None
        
        if app:
            self.init_app(app)
    
    def init_app(self, app: Flask):
        """Initialize OAuth2 clients for the Flask app"""
        self.app = app
        
        if not IDPConfig.IDP_ENABLED:
            logger.info("IDP authentication is disabled")
            return
        
        # Validate configuration
        config_validation = IDPConfig.validate_config()
        if not config_validation['valid']:
            logger.error(f"IDP configuration errors: {config_validation['errors']}")
            return
        
        if config_validation['warnings']:
            for warning in config_validation['warnings']:
                logger.warning(warning)
        
        # Initialize OAuth
        self.oauth = OAuth(app)
        
        # Initialize Google OAuth2 if enabled
        if IDPConfig.GOOGLE_OAUTH_ENABLED:
            self._init_google_oauth()
        
        # Initialize Microsoft OAuth2 if enabled
        if IDPConfig.MICROSOFT_OAUTH_ENABLED:
            self._init_microsoft_oauth()
    
    def _init_google_oauth(self):
        """Initialize Google OAuth2 client"""
        try:
            self.google_client = self.oauth.register(
                name='google',
                client_id=IDPConfig.GOOGLE_CLIENT_ID,
                client_secret=IDPConfig.GOOGLE_CLIENT_SECRET,
                server_metadata_url=IDPConfig.GOOGLE_DISCOVERY_URL,
                client_kwargs={
                    'scope': 'openid email profile'
                }
            )
            logger.info("Google OAuth2 client initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize Google OAuth2: {str(e)}")
    
    def _init_microsoft_oauth(self):
        """Initialize Microsoft OAuth2 client using MSAL"""
        try:
            self.microsoft_app = msal.ConfidentialClientApplication(
                IDPConfig.MICROSOFT_CLIENT_ID,
                authority=IDPConfig.MICROSOFT_AUTHORITY,
                client_credential=IDPConfig.MICROSOFT_CLIENT_SECRET
            )
            logger.info("Microsoft OAuth2 client initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize Microsoft OAuth2: {str(e)}")
    
    def initiate_google_login(self):
        """Initiate Google OAuth2 login flow"""
        if not self.google_client:
            return jsonify({'error': 'Google OAuth not configured'}), 500
        
        # Generate and store state for CSRF protection
        state = secrets.token_urlsafe(32)
        session['oauth_state'] = state
        
        # Add hosted domain hint if configured
        kwargs = {}
        if IDPConfig.GOOGLE_HOSTED_DOMAIN:
            kwargs['hd'] = IDPConfig.GOOGLE_HOSTED_DOMAIN
        
        return self.google_client.authorize_redirect(
            redirect_uri=IDPConfig.get_google_redirect_uri(),
            state=state,
            **kwargs
        )
    
    def handle_google_callback(self):
        """Handle Google OAuth2 callback"""
        try:
            # Verify state for CSRF protection
            if request.args.get('state') != session.pop('oauth_state', None):
                return jsonify({'error': 'Invalid state parameter'}), 400
            
            # Get token from Google
            token = self.google_client.authorize_access_token()
            
            # Get user info from token
            user_info = token.get('userinfo')
            if not user_info:
                # Parse ID token if userinfo not directly available
                user_info = id_token.verify_oauth2_token(
                    token['id_token'],
                    google_requests.Request(),
                    IDPConfig.GOOGLE_CLIENT_ID
                )
            
            # Verify hosted domain if configured
            if IDPConfig.GOOGLE_HOSTED_DOMAIN:
                if user_info.get('hd') != IDPConfig.GOOGLE_HOSTED_DOMAIN:
                    return jsonify({'error': 'Invalid domain'}), 403
            
            # Create user session
            user_data = self._process_google_user(user_info)
            return user_data
            
        except Exception as e:
            logger.error(f"Google OAuth callback error: {str(e)}")
            return jsonify({'error': 'Authentication failed'}), 500
    
    def initiate_microsoft_login(self):
        """Initiate Microsoft OAuth2 login flow"""
        if not self.microsoft_app:
            return jsonify({'error': 'Microsoft OAuth not configured'}), 500
        
        # Generate and store state for CSRF protection
        state = secrets.token_urlsafe(32)
        session['oauth_state'] = state
        
        # Get authorization URL
        auth_url = self.microsoft_app.get_authorization_request_url(
            scopes=['User.Read', 'email', 'profile'],
            state=state,
            redirect_uri=IDPConfig.get_microsoft_redirect_uri()
        )
        
        return redirect(auth_url)
    
    def handle_microsoft_callback(self):
        """Handle Microsoft OAuth2 callback"""
        try:
            # Verify state for CSRF protection
            if request.args.get('state') != session.pop('oauth_state', None):
                return jsonify({'error': 'Invalid state parameter'}), 400
            
            # Get authorization code
            code = request.args.get('code')
            if not code:
                return jsonify({'error': 'No authorization code received'}), 400
            
            # Exchange code for token
            result = self.microsoft_app.acquire_token_by_authorization_code(
                code,
                scopes=['User.Read', 'email', 'profile'],
                redirect_uri=IDPConfig.get_microsoft_redirect_uri()
            )
            
            if 'error' in result:
                logger.error(f"Microsoft token error: {result.get('error_description')}")
                return jsonify({'error': 'Authentication failed'}), 500
            
            # Get user info using the access token
            if 'access_token' in result:
                # Call Microsoft Graph API to get user details
                import requests
                graph_response = requests.get(
                    'https://graph.microsoft.com/v1.0/me',
                    headers={'Authorization': f"Bearer {result['access_token']}"}
                )
                
                if graph_response.status_code == 200:
                    user_info = graph_response.json()
                    user_data = self._process_microsoft_user(user_info)
                    return user_data
                else:
                    logger.error(f"Failed to get user info from Microsoft Graph: {graph_response.text}")
                    return jsonify({'error': 'Failed to get user information'}), 500
            
        except Exception as e:
            logger.error(f"Microsoft OAuth callback error: {str(e)}")
            return jsonify({'error': 'Authentication failed'}), 500
    
    def _process_google_user(self, user_info: Dict[str, Any]) -> Dict[str, Any]:
        """Process Google user information"""
        return {
            'provider': 'google',
            'id': user_info.get('sub'),
            'email': user_info.get('email'),
            'name': user_info.get('name'),
            'given_name': user_info.get('given_name'),
            'family_name': user_info.get('family_name'),
            'picture': user_info.get('picture'),
            'email_verified': user_info.get('email_verified', False),
            'locale': user_info.get('locale'),
            'hosted_domain': user_info.get('hd'),
            'raw_attributes': user_info
        }
    
    def _process_microsoft_user(self, user_info: Dict[str, Any]) -> Dict[str, Any]:
        """Process Microsoft user information"""
        return {
            'provider': 'microsoft',
            'id': user_info.get('id'),
            'email': user_info.get('userPrincipalName') or user_info.get('mail'),
            'name': user_info.get('displayName'),
            'given_name': user_info.get('givenName'),
            'family_name': user_info.get('surname'),
            'job_title': user_info.get('jobTitle'),
            'department': user_info.get('department'),
            'office_location': user_info.get('officeLocation'),
            'mobile_phone': user_info.get('mobilePhone'),
            'business_phones': user_info.get('businessPhones', []),
            'raw_attributes': user_info
        }
    
    def create_idp_user_session(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create session for IDP authenticated user"""
        # Store user data in session
        session['idp_user'] = user_data
        session['idp_authenticated'] = True
        session['idp_auth_time'] = datetime.utcnow().isoformat()
        session['idp_session_expires'] = (
            datetime.utcnow() + timedelta(seconds=IDPConfig.IDP_SESSION_LIFETIME)
        ).isoformat()
        
        # Set session permanent for remember me functionality
        session.permanent = True
        
        return {
            'status': 'success',
            'user': user_data,
            'session_expires': session['idp_session_expires']
        }
    
    def get_current_idp_user(self) -> Optional[Dict[str, Any]]:
        """Get current IDP authenticated user from session"""
        if not session.get('idp_authenticated'):
            return None
        
        # Check session expiry
        expires = session.get('idp_session_expires')
        if expires:
            if datetime.fromisoformat(expires) < datetime.utcnow():
                self.logout_idp_user()
                return None
        
        return session.get('idp_user')
    
    def logout_idp_user(self):
        """Logout IDP user and clear session"""
        session.pop('idp_user', None)
        session.pop('idp_authenticated', None)
        session.pop('idp_auth_time', None)
        session.pop('idp_session_expires', None)
        
        return {'status': 'success', 'message': 'Logged out successfully'}
    
    def is_idp_authenticated(self) -> bool:
        """Check if user is authenticated via IDP"""
        return self.get_current_idp_user() is not None
    
    def require_idp_auth(self, f):
        """Decorator to require IDP authentication for routes"""
        from functools import wraps
        
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not self.is_idp_authenticated():
                if request.is_json:
                    return jsonify({'error': 'IDP authentication required'}), 401
                return redirect(url_for('idp_login'))
            return f(*args, **kwargs)
        
        return decorated_function