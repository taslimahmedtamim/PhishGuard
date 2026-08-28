import whois
from datetime import datetime, timezone
import tldextract
from typing import Dict, Any, Optional

class WHOISExtractor:
    def __init__(self, logger, config):
        self.logger = logger
        self.config = config
    
    def extract_whois_features(self, url: str) -> Optional[Dict[str, Any]]:
        """Extract WHOIS features from a URL"""
        try:
            # Extract domain from URL
            extracted = tldextract.extract(url)
            domain = f"{extracted.domain}.{extracted.suffix}"
            
            if not domain or domain == '.':
                return None
            
            # Query WHOIS
            domain_info = whois.whois(domain)
            
            if not domain_info:
                return None
            
            # Calculate domain age
            domain_age_days = self._calculate_domain_age(domain_info.creation_date)
            
            # Extract features
            features = {
                'domain_age_days': domain_age_days,
                'registrar': str(domain_info.registrar) if domain_info.registrar else 'Unknown',
                'creation_date': str(domain_info.creation_date) if domain_info.creation_date else 'Unknown',
                'expiration_date': str(domain_info.expiration_date) if domain_info.expiration_date else 'Unknown',
                'country': str(domain_info.country) if domain_info.country else 'Unknown',
                'whois_privacy': self._check_privacy_protection(domain_info)
            }
            
            return features
            
        except Exception as e:
            self.logger.error(f"WHOIS extraction failed for {url}: {e}")
            return None
    
    def _calculate_domain_age(self, creation_date) -> int:
        """Calculate domain age in days"""
        try:
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            if creation_date:
                if isinstance(creation_date, str):
                    # Try to parse string date
                    creation_date = datetime.fromisoformat(creation_date.replace('Z', '+00:00'))
                
                now = datetime.now(timezone.utc)
                if creation_date.tzinfo is None:
                    creation_date = creation_date.replace(tzinfo=timezone.utc)
                
                age = (now - creation_date).days
                return max(0, age)  # Ensure non-negative
        except Exception as e:
            self.logger.error(f"Error calculating domain age: {e}")
        
        return -1  # Unknown age
    
    def _check_privacy_protection(self, domain_info) -> int:
        """Check if domain has privacy protection (1 = yes, 0 = no)"""
        try:
            privacy_indicators = [
                'privacy', 'private', 'protected', 'whoisguard', 'proxy',
                'domains by proxy', 'perfect privacy', 'contact privacy'
            ]
            
            # Check registrar
            registrar = str(domain_info.registrar).lower() if domain_info.registrar else ''
            
            # Check organization/name fields
            org_fields = [domain_info.org, domain_info.name]
            
            for field in org_fields:
                if field:
                    field_str = str(field).lower()
                    for indicator in privacy_indicators:
                        if indicator in field_str:
                            return 1
            
            # Check registrar for privacy services
            for indicator in privacy_indicators:
                if indicator in registrar:
                    return 1
            
            return 0
        except:
            return 0  # Default to no privacy protection