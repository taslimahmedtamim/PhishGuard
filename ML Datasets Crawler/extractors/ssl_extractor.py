import ssl
import socket
from urllib.parse import urlparse
from datetime import datetime, timezone
import requests
from typing import Dict, Any, Optional

class SSLExtractor:
    def __init__(self, logger, config):
        self.logger = logger
        self.config = config
    
    def extract_ssl_features(self, url: str) -> Optional[Dict[str, Any]]:
        """Extract SSL certificate features from a URL"""
        try:
            parsed_url = urlparse(url)
            
            if parsed_url.scheme != 'https':
                # Try to convert to https
                url = url.replace('http://', 'https://')
                parsed_url = urlparse(url)
            
            hostname = parsed_url.netloc or parsed_url.path
            port = parsed_url.port or 443
            
            if not hostname:
                return None
            
            # Remove port from hostname if present
            if ':' in hostname:
                hostname = hostname.split(':')[0]
            
            # Get SSL certificate
            cert_info = self._get_ssl_certificate(hostname, port)
            
            if not cert_info:
                return None
            
            # Extract features
            features = {
                'ssl_issuer': cert_info.get('issuer', 'Unknown'),
                'ssl_validity_days': cert_info.get('validity_days', -1),
                'ssl_key_length': cert_info.get('key_length', -1),
                'ssl_algorithm': cert_info.get('algorithm', 'Unknown'),
                'is_self_signed': cert_info.get('is_self_signed', 0),
                'ssl_common_name_match': cert_info.get('common_name_match', 0)
            }
            
            return features
            
        except Exception as e:
            self.logger.error(f"SSL extraction failed for {url}: {e}")
            return None
    
    def _get_ssl_certificate(self, hostname: str, port: int = 443) -> Optional[Dict[str, Any]]:
        """Get SSL certificate information"""
        try:
            # Create SSL context - FIXED VERSION
            context = ssl.create_default_context()
            context.check_hostname = True  # Keep hostname checking
            context.verify_mode = ssl.CERT_REQUIRED  # Require certificate validation
            
            # Connect and get certificate
            with socket.create_connection((hostname, port), timeout=self.config.SSL_TIMEOUT) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cert_binary = ssock.getpeercert(binary_form=True)
                    
                    if not cert or cert == {}:
                        return None
                    
                    # Parse certificate information
                    cert_info = self._parse_certificate(cert, cert_binary, hostname)
                    return cert_info
                    
        except Exception as e:
            self.logger.error(f"SSL certificate retrieval failed for {hostname}: {e}")
            return None
    
    def _parse_certificate(self, cert: dict, cert_binary: bytes, hostname: str) -> Dict[str, Any]:
        """Parse SSL certificate information"""
        try:
            # Get issuer
            issuer = dict(x[0] for x in cert.get('issuer', []))
            issuer_org = issuer.get('organizationName', 'Unknown')
            
            # Get subject
            subject = dict(x[0] for x in cert.get('subject', []))
            subject_org = subject.get('organizationName', 'Unknown')
            subject_cn = subject.get('commonName', 'Unknown')
            
            # Calculate validity period
            validity_days = self._calculate_validity_days(cert)
            
            # Get public key info
            key_length = self._get_key_length(cert_binary)
            
            # Get signature algorithm
            algorithm = cert.get('signatureAlgorithm', 'Unknown')
            
            # Check if self-signed
            is_self_signed = self._is_self_signed(cert)
            
            # Check common name match
            common_name_match = self._check_common_name_match(cert, hostname)
            
            return {
                'issuer': issuer_org,
                'validity_days': validity_days,
                'key_length': key_length,
                'algorithm': algorithm,
                'is_self_signed': is_self_signed,
                'common_name_match': common_name_match
            }
            
        except Exception as e:
            self.logger.error(f"Certificate parsing failed: {e}")
            return {}
    
    def _calculate_validity_days(self, cert: dict) -> int:
        """Calculate certificate validity period in days"""
        try:
            not_after = cert.get('notAfter')
            if not_after:
                expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                expiry_date = expiry_date.replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                
                validity_days = (expiry_date - now).days
                return validity_days
        except Exception as e:
            self.logger.error(f"Error calculating validity days: {e}")
        
        return -1
    
    def _get_key_length(self, cert_binary: bytes) -> int:
        """Extract public key length from certificate"""
        try:
            from cryptography import x509
            
            cert_obj = x509.load_der_x509_certificate(cert_binary)
            public_key = cert_obj.public_key()
            
            # Get key size based on key type
            if hasattr(public_key, 'key_size'):
                return public_key.key_size
        except Exception as e:
            self.logger.error(f"Error extracting key length: {e}")
        
        return -1
    
    def _is_self_signed(self, cert: dict) -> int:
        """Check if certificate is self-signed"""
        try:
            issuer = dict(x[0] for x in cert.get('issuer', []))
            subject = dict(x[0] for x in cert.get('subject', []))
            
            issuer_org = issuer.get('organizationName', '')
            subject_org = subject.get('organizationName', '')
            
            issuer_cn = issuer.get('commonName', '')
            subject_cn = subject.get('commonName', '')
            
            # Simple check: if issuer and subject organization are the same and not empty
            if (issuer_org == subject_org and issuer_cn == subject_cn and 
                issuer_org and issuer_org != 'Unknown'):
                return 1
            
        except Exception:
            pass
        
        return 0
    
    def _check_common_name_match(self, cert: dict, hostname: str) -> int:
        """Check if certificate common name matches hostname"""
        try:
            subject = dict(x[0] for x in cert.get('subject', []))
            common_name = subject.get('commonName', '')
            
            # Check direct match
            if common_name == hostname:
                return 1
            
            # Check wildcard match
            if common_name.startswith('*.'):
                wildcard_domain = common_name[2:]
                if hostname.endswith(wildcard_domain):
                    return 1
            
            # Check Subject Alternative Names
            san_list = cert.get('subjectAltName', [])
            for san_type, san_value in san_list:
                if san_type == 'DNS' and san_value == hostname:
                    return 1
            
        except Exception:
            pass
        
        return 0