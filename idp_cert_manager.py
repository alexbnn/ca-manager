"""
Automated Certificate Management for IDP Users
CA Manager 6.0.0
"""

import os
import json
import logging
import tempfile
import base64
from typing import Dict, Any, Optional, Tuple
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
import psycopg2
from psycopg2.extras import RealDictCursor
from idp_config import IDPConfig
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication

logger = logging.getLogger(__name__)

class IDPCertManager:
    """Manages certificate generation and lifecycle for IDP users"""
    
    def __init__(self, db_connection=None, easyrsa_api_url=None):
        self.db_connection = db_connection
        self.easyrsa_api_url = easyrsa_api_url or os.getenv('TERMINAL_CONTAINER_URL', 'http://easyrsa-container:8080')
    
    def get_or_create_user_cert(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Get existing certificate or create new one for IDP user"""
        try:
            # Check if user already has a valid certificate
            existing_cert = self._get_existing_cert(user_data['email'])
            
            if existing_cert and not self._is_cert_expiring_soon(existing_cert):
                logger.info(f"Found existing valid certificate for {user_data['email']}")
                return {
                    'status': 'exists',
                    'certificate': existing_cert,
                    'message': 'Existing certificate is still valid'
                }
            
            # Generate new certificate if auto-generation is enabled
            if IDPConfig.IDP_CERT_AUTO_GENERATE:
                logger.info(f"Generating new certificate for {user_data['email']}")
                new_cert = self._generate_certificate(user_data)
                
                # Send certificate via email if enabled
                if IDPConfig.IDP_CERT_EMAIL_DELIVERY and new_cert.get('status') == 'success':
                    self._send_certificate_email(user_data, new_cert)
                
                return new_cert
            
            return {
                'status': 'manual',
                'message': 'Certificate must be manually requested'
            }
            
        except Exception as e:
            logger.error(f"Error managing certificate for {user_data.get('email')}: {str(e)}")
            return {
                'status': 'error',
                'message': f'Failed to manage certificate: {str(e)}'
            }
    
    def _get_existing_cert(self, email: str) -> Optional[Dict[str, Any]]:
        """Check if user has existing certificate in database"""
        if not self.db_connection:
            return None
        
        try:
            with self.db_connection.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute("""
                    SELECT 
                        ic.id,
                        ic.common_name,
                        ic.certificate_pem,
                        ic.serial_number,
                        ic.valid_from,
                        ic.valid_until,
                        ic.status,
                        ic.created_at
                    FROM idp_certificates ic
                    WHERE ic.email = %s 
                    AND ic.status = 'active'
                    ORDER BY ic.created_at DESC
                    LIMIT 1
                """, (email,))
                
                result = cursor.fetchone()
                return dict(result) if result else None
                
        except Exception as e:
            logger.error(f"Database error checking existing cert: {str(e)}")
            return None
    
    def _is_cert_expiring_soon(self, cert_data: Dict[str, Any]) -> bool:
        """Check if certificate is expiring within renewal window"""
        try:
            valid_until = cert_data.get('valid_until')
            if isinstance(valid_until, str):
                valid_until = datetime.fromisoformat(valid_until)
            
            renewal_window = timedelta(days=IDPConfig.IDP_SELF_SERVICE_RENEWAL_DAYS)
            return valid_until <= (datetime.utcnow() + renewal_window)
            
        except Exception as e:
            logger.error(f"Error checking certificate expiry: {str(e)}")
            return True  # Assume expiring if we can't check
    
    def _generate_certificate(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate new certificate for IDP user"""
        try:
            # Determine certificate template based on user attributes
            template = self._get_cert_template(user_data)
            
            # Prepare certificate request data
            cert_request = {
                'name': user_data['email'].replace('@', '_').replace('.', '_'),
                'common_name': user_data['email'],
                'email': user_data['email'],
                'organization': user_data.get('hosted_domain', '') or user_data.get('department', ''),
                'organizational_unit': user_data.get('department', 'IDP Users'),
                'cert_type': template['cert_type'],
                'validity_days': template['validity_days'],
                'key_size': template['key_size'],
                'san_email': user_data['email'],
                'idp_provider': user_data['provider'],
                'idp_user_id': user_data['id']
            }
            
            # Add user's full name if available
            if user_data.get('name'):
                cert_request['full_name'] = user_data['name']
            
            # Call EasyRSA API to generate certificate
            import requests
            response = requests.post(
                f"{self.easyrsa_api_url}/api/execute",
                json={
                    'operation': 'build-client-full',
                    'params': cert_request
                },
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                
                if result.get('status') == 'success':
                    # Store certificate in database
                    self._store_certificate(user_data, cert_request, result)
                    
                    # Generate PKCS12 bundle for easy import
                    pkcs12_bundle = self._create_pkcs12_bundle(result, user_data['email'])
                    result['pkcs12'] = pkcs12_bundle
                    
                    return {
                        'status': 'success',
                        'message': f'Certificate generated successfully for {user_data["email"]}',
                        'certificate': result,
                        'download_formats': ['pem', 'pkcs12', 'der']
                    }
                else:
                    return {
                        'status': 'error',
                        'message': result.get('message', 'Certificate generation failed')
                    }
            else:
                return {
                    'status': 'error',
                    'message': f'EasyRSA API error: {response.status_code}'
                }
                
        except Exception as e:
            logger.error(f"Certificate generation error: {str(e)}")
            return {
                'status': 'error',
                'message': f'Failed to generate certificate: {str(e)}'
            }
    
    def _get_cert_template(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Determine certificate template based on user attributes"""
        # Check for admin role
        if user_data.get('job_title') and 'admin' in user_data['job_title'].lower():
            return IDPConfig.IDP_CERT_TEMPLATE_MAPPING.get('admin')
        
        # Check for server/service accounts
        if user_data.get('email') and 'service' in user_data['email'].lower():
            return IDPConfig.IDP_CERT_TEMPLATE_MAPPING.get('server')
        
        # Default template
        return IDPConfig.IDP_CERT_TEMPLATE_MAPPING.get('default')
    
    def _store_certificate(self, user_data: Dict[str, Any], cert_request: Dict[str, Any], cert_result: Dict[str, Any]):
        """Store certificate information in database"""
        if not self.db_connection:
            return
        
        try:
            with self.db_connection.cursor() as cursor:
                cursor.execute("""
                    INSERT INTO idp_certificates (
                        email, common_name, idp_provider, idp_user_id,
                        certificate_pem, private_key_pem, serial_number,
                        valid_from, valid_until, status, metadata
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    user_data['email'],
                    cert_request['common_name'],
                    user_data['provider'],
                    user_data['id'],
                    cert_result.get('certificate_pem'),
                    cert_result.get('private_key_pem'),  # Should be encrypted
                    cert_result.get('serial_number'),
                    datetime.utcnow(),
                    datetime.utcnow() + timedelta(days=cert_request['validity_days']),
                    'active',
                    json.dumps({
                        'user_name': user_data.get('name'),
                        'department': user_data.get('department'),
                        'template': cert_request['cert_type']
                    })
                ))
                self.db_connection.commit()
                logger.info(f"Certificate stored in database for {user_data['email']}")
                
        except Exception as e:
            logger.error(f"Failed to store certificate in database: {str(e)}")
            self.db_connection.rollback()
    
    def _create_pkcs12_bundle(self, cert_result: Dict[str, Any], email: str) -> str:
        """Create PKCS12 bundle for certificate and key"""
        try:
            # Parse certificate and key from PEM
            cert_pem = cert_result.get('certificate_pem', '')
            key_pem = cert_result.get('private_key_pem', '')
            ca_pem = cert_result.get('ca_certificate_pem', '')
            
            cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
            key = serialization.load_pem_private_key(key_pem.encode(), password=None, backend=default_backend())
            ca_cert = x509.load_pem_x509_certificate(ca_pem.encode(), default_backend()) if ca_pem else None
            
            # Create PKCS12 bundle
            friendly_name = f"{email} Certificate"
            pkcs12_data = pkcs12.serialize_key_and_certificates(
                name=friendly_name.encode(),
                key=key,
                cert=cert,
                cas=[ca_cert] if ca_cert else None,
                encryption_algorithm=serialization.BestAvailableEncryption(b'')  # No password for now
            )
            
            # Return base64 encoded PKCS12
            return base64.b64encode(pkcs12_data).decode('utf-8')
            
        except Exception as e:
            logger.error(f"Failed to create PKCS12 bundle: {str(e)}")
            return ""
    
    def _send_certificate_email(self, user_data: Dict[str, Any], cert_data: Dict[str, Any]):
        """Send certificate to user via email"""
        try:
            # Get SMTP configuration
            smtp_host = os.getenv('SMTP_HOST', 'localhost')
            smtp_port = int(os.getenv('SMTP_PORT', '587'))
            smtp_user = os.getenv('SMTP_USER', '')
            smtp_password = os.getenv('SMTP_PASSWORD', '')
            smtp_from = os.getenv('SMTP_FROM', 'noreply@ca-manager.local')
            
            # Create email message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = IDPConfig.IDP_CERT_EMAIL_SUBJECT
            msg['From'] = smtp_from
            msg['To'] = user_data['email']
            
            # Create email body
            html_body = f"""
            <html>
            <body style="font-family: Arial, sans-serif; padding: 20px;">
                <h2 style="color: #5B059C;">Your PKI Certificate is Ready</h2>
                
                <p>Hello {user_data.get('name', user_data['email'])},</p>
                
                <p>Your digital certificate has been generated and is attached to this email.</p>
                
                <h3>Certificate Details:</h3>
                <ul>
                    <li><strong>Common Name:</strong> {user_data['email']}</li>
                    <li><strong>Valid From:</strong> {datetime.utcnow().strftime('%Y-%m-%d')}</li>
                    <li><strong>Valid Until:</strong> {(datetime.utcnow() + timedelta(days=IDPConfig.IDP_CERT_VALIDITY_DAYS)).strftime('%Y-%m-%d')}</li>
                    <li><strong>Key Size:</strong> {IDPConfig.IDP_CERT_KEY_SIZE} bits</li>
                </ul>
                
                <h3>Installation Instructions:</h3>
                <ol>
                    <li>Save the attached .p12 file to your computer</li>
                    <li>Double-click the file to import it</li>
                    <li>Follow your operating system's certificate import wizard</li>
                    <li>The certificate password is blank (just press Enter when prompted)</li>
                </ol>
                
                <p>You can also access your certificate anytime by logging into the 
                <a href="{IDPConfig.OAUTH_REDIRECT_URI_BASE}/portal">Certificate Portal</a>.</p>
                
                <p style="color: #666; font-size: 12px; margin-top: 30px;">
                This is an automated message. Please do not reply to this email.
                </p>
            </body>
            </html>
            """
            
            msg.attach(MIMEText(html_body, 'html'))
            
            # Attach PKCS12 certificate if available
            if cert_data.get('certificate', {}).get('pkcs12'):
                pkcs12_data = base64.b64decode(cert_data['certificate']['pkcs12'])
                
                attachment = MIMEApplication(pkcs12_data)
                attachment.add_header(
                    'Content-Disposition',
                    'attachment',
                    filename=f"{user_data['email'].replace('@', '_')}_certificate.p12"
                )
                msg.attach(attachment)
            
            # Send email
            with smtplib.SMTP(smtp_host, smtp_port) as server:
                if smtp_user and smtp_password:
                    server.starttls()
                    server.login(smtp_user, smtp_password)
                server.send_message(msg)
            
            logger.info(f"Certificate email sent to {user_data['email']}")
            
        except Exception as e:
            logger.error(f"Failed to send certificate email: {str(e)}")
    
    def renew_certificate(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Renew certificate for IDP user"""
        try:
            # Revoke old certificate first
            existing_cert = self._get_existing_cert(user_data['email'])
            if existing_cert:
                self._revoke_certificate(existing_cert['serial_number'])
            
            # Generate new certificate
            return self._generate_certificate(user_data)
            
        except Exception as e:
            logger.error(f"Certificate renewal error: {str(e)}")
            return {
                'status': 'error',
                'message': f'Failed to renew certificate: {str(e)}'
            }
    
    def _revoke_certificate(self, serial_number: str):
        """Revoke certificate by serial number"""
        try:
            import requests
            response = requests.post(
                f"{self.easyrsa_api_url}/api/execute",
                json={
                    'operation': 'revoke',
                    'params': {
                        'serial_number': serial_number,
                        'reason': 'superseded'
                    }
                },
                timeout=30
            )
            
            if response.status_code == 200:
                logger.info(f"Certificate {serial_number} revoked successfully")
            
        except Exception as e:
            logger.error(f"Failed to revoke certificate: {str(e)}")
    
    def get_user_certificates(self, email: str) -> list:
        """Get all certificates for a user"""
        if not self.db_connection:
            return []
        
        try:
            with self.db_connection.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute("""
                    SELECT 
                        id, common_name, serial_number,
                        valid_from, valid_until, status,
                        created_at, metadata
                    FROM idp_certificates
                    WHERE email = %s
                    ORDER BY created_at DESC
                """, (email,))
                
                results = cursor.fetchall()
                return [dict(row) for row in results]
                
        except Exception as e:
            logger.error(f"Error fetching user certificates: {str(e)}")
            return []