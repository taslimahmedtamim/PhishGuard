import whois
import socket
import ssl
from urllib.parse import urlparse
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class HostFeatureExtractor:
    def __init__(self):
        pass

    def get_host_features(self, url):
        """
        Attempts to get WHOIS and SSL features for UI display.
        Returns a dictionary.
        """
        features = {
            'whois_available': False,
            'domain_age_days': None,
            'registration_period_days': None,
            'ssl_available': False,
            'cert_issuer': None,
            'cert_age_days': None
        }

        try:
            parsed = urlparse(url)
            hostname = parsed.hostname
            if not hostname:
                return features
        except Exception:
            return features

        # WHOIS lookup (with short timeout)
        try:
            domain = whois.whois(hostname)
            if domain and domain.creation_date:
                features['whois_available'] = True
                
                creation_date = domain.creation_date
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                    
                expiration_date = domain.expiration_date
                if isinstance(expiration_date, list):
                    expiration_date = expiration_date[0]
                
                if isinstance(creation_date, datetime):
                    try:
                        naive_creation = creation_date.replace(tzinfo=None)
                        age = (datetime.now() - naive_creation).days
                        features['domain_age_days'] = age
                    except Exception as e:
                        logger.debug(f"Age calculation failed: {e}")
                    
                if isinstance(expiration_date, datetime) and isinstance(creation_date, datetime):
                    try:
                        naive_expiration = expiration_date.replace(tzinfo=None)
                        naive_creation = creation_date.replace(tzinfo=None)
                        period = (naive_expiration - naive_creation).days
                        features['registration_period_days'] = period
                    except Exception as e:
                        logger.debug(f"Period calculation failed: {e}")
        except Exception as e:
            logger.debug(f"WHOIS lookup failed for {hostname}: {e}")

        # SSL Lookup
        if url.startswith('https'):
            features['ssl_available'] = True # HTTPs is used
            try:
                # Basic cert check
                context = ssl.create_default_context()
                with socket.create_connection((hostname, 443), timeout=3) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        
                        # Extract issuer
                        issuer_dict = dict(x[0] for x in cert.get('issuer', []))
                        if 'organizationName' in issuer_dict:
                            features['cert_issuer'] = issuer_dict['organizationName']
                        elif 'commonName' in issuer_dict:
                            features['cert_issuer'] = issuer_dict['commonName']
                            
                        # Extract cert age
                        not_before = cert.get('notBefore')
                        if not_before:
                            try:
                                not_before_date = datetime.strptime(not_before, '%b %d %H:%M:%S %Y %Z')
                                features['cert_age_days'] = (datetime.utcnow() - not_before_date).days
                            except Exception:
                                pass
            except Exception as e:
                logger.debug(f"SSL certificate check failed for {hostname}: {e}")
                features['ssl_available'] = False # Failed to verify

        return features
