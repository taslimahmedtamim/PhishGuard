import requests
from bs4 import BeautifulSoup 
from urllib.parse import urlparse, urljoin, parse_qs
import re
import time
from typing import Dict, Any, Optional
import socket

class BehavioralExtractor:
    def __init__(self, logger, config):
        self.logger = logger
        self.config = config
        self.session = requests.Session()
        
        # Set up session
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
    
    def extract_behavioral_features(self, url: str) -> Optional[Dict[str, Any]]:
        """Extract behavioral features from a URL"""
        try:
            # First extract URL-based features
            url_features = self._extract_url_features(url)
            
            # Then extract page-based features
            page_features = self._extract_page_features(url)
            
            # Combine features
            features = {**url_features, **page_features}
            
            return features
            
        except Exception as e:
            self.logger.error(f"Behavioral extraction failed for {url}: {e}")
            return None
    
    def _extract_url_features(self, url: str) -> Dict[str, Any]:
        """Extract features from the URL itself"""
        try:
            parsed_url = urlparse(url)
            
            # Basic URL features
            url_length = len(url)
            num_dots = url.count('.')
            num_hyphens = url.count('-')
            num_underscores = url.count('_')
            num_digits = sum(c.isdigit() for c in url)
            
            # Query parameters
            query_params = parse_qs(parsed_url.query)
            num_params = len(query_params)
            
            # Check for IP address instead of domain
            has_ip_address = self._is_ip_address(parsed_url.netloc.split(':')[0])
            
            return {
                'url_length': url_length,
                'num_dots': num_dots,
                'num_hyphens': num_hyphens,
                'num_underscores': num_underscores,
                'num_digits': num_digits,
                'num_params': num_params,
                'has_ip_address': 1 if has_ip_address else 0
            }
            
        except Exception as e:
            self.logger.error(f"URL feature extraction failed: {e}")
            return {
                'url_length': -1, 'num_dots': -1, 'num_hyphens': -1,
                'num_underscores': -1, 'num_digits': -1, 'num_params': -1,
                'has_ip_address': -1
            }
    
    def _extract_page_features(self, url: str) -> Dict[str, Any]:
        """Extract features from the webpage content"""
        try:
            # Track redirects
            response_history = []
            
            response = self.session.get(
                url,
                timeout=self.config.REQUEST_TIMEOUT,
                allow_redirects=True,
                stream=True
            )
            
            # Check response size
            content_length = response.headers.get('content-length')
            if content_length and int(content_length) > self.config.MAX_PAGE_SIZE:
                self.logger.warning(f"Page too large: {url}")
                return self._get_default_page_features()
            
            # Get content with size limit
            content = ''
            size = 0
            for chunk in response.iter_content(chunk_size=8192):
                size += len(chunk)
                if size > self.config.MAX_PAGE_SIZE:
                    break
                content += chunk.decode('utf-8', errors='ignore')
            
            # Parse HTML
            soup = BeautifulSoup(content, 'html.parser')
            
            # Extract features
            features = {
                'num_redirects': len(response.history),
                'final_url_different': 1 if response.url != url else 0,
                'has_iframe': 1 if soup.find('iframe') else 0,
                'num_iframes': len(soup.find_all('iframe')),
                'has_js_redirect': self._check_js_redirect(content),
                'num_external_links': self._count_external_links(soup, url),
                'num_forms': len(soup.find_all('form')),
                'has_password_field': self._has_password_field(soup),
                'page_title_length': len(soup.title.string) if soup.title and soup.title.string else 0,
                'num_images': len(soup.find_all('img')),
                'has_favicon': 1 if self._has_favicon(soup) else 0
            }
            
            return features
            
        except requests.RequestException as e:
            self.logger.error(f"Request failed for {url}: {e}")
            return self._get_default_page_features()
        except Exception as e:
            self.logger.error(f"Page feature extraction failed for {url}: {e}")
            return self._get_default_page_features()
    
    def _is_ip_address(self, hostname: str) -> bool:
        """Check if hostname is an IP address"""
        try:
            socket.inet_aton(hostname)
            return True
        except socket.error:
            return False
    
    def _check_js_redirect(self, content: str) -> int:
        """Check for JavaScript-based redirection"""
        js_redirect_patterns = [
            r'window\.location\s*=',
            r'location\.href\s*=',
            r'location\.replace\s*\(',
            r'window\.open\s*\(',
            r'document\.location\s*='
        ]
        
        for pattern in js_redirect_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return 1
        
        return 0
    
    def _count_external_links(self, soup: BeautifulSoup, url: str) -> int:
        """Count external links in the page"""
        try:
            parsed_base = urlparse(url)
            base_domain = parsed_base.netloc.lower()
            
            external_count = 0
            
            for link in soup.find_all('a', href=True):
                href = link['href']
                
                # Skip mailto, tel, javascript links
                if href.startswith(('mailto:', 'tel:', 'javascript:')):
                    continue
                
                # Convert relative URLs to absolute
                if href.startswith(('http://', 'https://')):
                    link_domain = urlparse(href).netloc.lower()
                    if link_domain and link_domain != base_domain:
                        external_count += 1
                elif href.startswith('//'):
                    link_domain = href.split('/')[2].lower()
                    if link_domain != base_domain:
                        external_count += 1
            
            return external_count
            
        except Exception as e:
            self.logger.error(f"Error counting external links: {e}")
            return -1
    
    def _has_password_field(self, soup: BeautifulSoup) -> int:
        """Check if page has password input fields"""
        password_inputs = soup.find_all('input', {'type': 'password'})
        return 1 if password_inputs else 0
    
    def _has_favicon(self, soup: BeautifulSoup) -> bool:
        """Check if page has a favicon"""
        # Check for favicon links
        favicon_links = soup.find_all('link', rel=lambda x: x and 'icon' in x.lower() if x else False)
        return len(favicon_links) > 0
    
    def _get_default_page_features(self) -> Dict[str, Any]:
        """Return default values for page features when extraction fails"""
        return {
            'num_redirects': -1,
            'final_url_different': -1,
            'has_iframe': -1,
            'num_iframes': -1,
            'has_js_redirect': -1,
            'num_external_links': -1,
            'num_forms': -1,
            'has_password_field': -1,
            'page_title_length': -1,
            'num_images': -1,
            'has_favicon': -1
        } 