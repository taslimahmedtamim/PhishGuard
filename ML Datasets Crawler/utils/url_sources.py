import requests
import csv
import io
from typing import List, Generator
import time
import random

class URLSource:
    def __init__(self, logger, config):
        self.logger = logger
        self.config = config
        self.session = requests.Session()
        # Set a more common user agent
        self.session.headers.update({
            'User-Agent': random.choice(config.USER_AGENTS)
        })
        
    def get_phishing_urls(self) -> Generator[str, None, None]:
        """Get phishing URLs from PhishTank and OpenPhish"""
        
        # PhishTank
        try:
            self.logger.info("Fetching PhishTank data...")
            response = self.session.get(
                'http://data.phishtank.com/data/online-valid.csv',
                timeout=30
            )
            
            if response.status_code == 200:
                csv_data = io.StringIO(response.text)
                reader = csv.DictReader(csv_data)
                count = 0
                for row in reader:
                    if 'url' in row and row['url']:
                        yield row['url']
                        count += 1
                        # Faster processing - smaller delay
                        time.sleep(0.05)
                        if count >= 10000:  # Limit to first 10k for faster processing
                            break
                            
                self.logger.info(f"Collected {count} URLs from PhishTank")
        except Exception as e:
            self.logger.error(f"Error fetching PhishTank: {e}")
        
        # OpenPhish
        try:
            self.logger.info("Fetching OpenPhish data...")
            response = self.session.get(
                'https://openphish.com/feed.txt',
                timeout=30
            )
            
            if response.status_code == 200:
                count = 0
                for line in response.text.strip().split('\n'):
                    if line.strip():
                        yield line.strip()
                        count += 1
                        time.sleep(0.05)  # Faster processing
                        if count >= 10000:  # Limit to first 10k
                            break
                            
                self.logger.info(f"Collected {count} URLs from OpenPhish")
        except Exception as e:
            self.logger.error(f"Error fetching OpenPhish: {e}")
    
    def get_legitimate_urls(self) -> Generator[str, None, None]:
        """Get legitimate URLs from multiple sources"""
        
        # First, try Tranco (but with smaller list for faster download)
        try:
            self.logger.info("Fetching Tranco top domains...")
            response = self.session.get(
                'https://tranco-list.eu/download/latest/10000',  # Smaller list
                timeout=60
            )
            
            if response.status_code == 200:
                count = 0
                for line in response.text.strip().split('\n'):
                    if ',' in line and count < 5000:  # Limit to 5000 from Tranco
                        rank, domain = line.strip().split(',', 1)
                        # Convert to full URL
                        yield f"https://{domain}"
                        count += 1
                        time.sleep(0.02)  # Faster processing
                        
                self.logger.info(f"Collected {count} URLs from Tranco")
        except Exception as e:
            self.logger.error(f"Error fetching Tranco: {e}")
        
        # Then use our expanded fallback list
        self.logger.info("Using fallback legitimate sites...")
        count = 0
        for site in self.config.LEGIT_FALLBACK_URLS:
            yield site
            count += 1
            time.sleep(0.02)  # Fast processing for known good sites
            
        self.logger.info(f"Provided {count} fallback legitimate URLs")
        
        # If we still need more, generate variations of popular domains
        self.logger.info("Generating additional legitimate URL variations...")
        base_domains = [
            "google.com", "microsoft.com", "amazon.com", "apple.com", "meta.com",
            "netflix.com", "github.com", "stackoverflow.com", "wikipedia.org", "reddit.com"
        ]
        
        subdomains = ["www", "support", "help", "docs", "blog", "news", "about", "careers"]
        
        for domain in base_domains:
            for subdomain in subdomains:
                yield f"https://{subdomain}.{domain}"
                time.sleep(0.01)
                
        # Generate country-specific variations
        country_codes = ["uk", "ca", "au", "de", "fr", "jp", "in", "br"]
        for domain in ["google.com", "amazon.com", "ebay.com"]:
            base_name = domain.split('.')[0]
            for cc in country_codes:
                if cc == "uk":
                    yield f"https://{base_name}.co.{cc}"
                else:
                    yield f"https://{base_name}.{cc}"
                time.sleep(0.01)