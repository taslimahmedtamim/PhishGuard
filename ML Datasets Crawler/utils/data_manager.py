import pandas as pd
import os
from typing import Dict, Any

class DataManager:
    def __init__(self, dataset_file: str, logger):
        self.dataset_file = dataset_file
        self.logger = logger
        self.df = self.load_existing_data()
        
        # Ensure data directory exists
        os.makedirs(os.path.dirname(dataset_file), exist_ok=True)
    
    def load_existing_data(self) -> pd.DataFrame:
        """Load existing dataset if it exists"""
        if os.path.exists(self.dataset_file):
            try:
                df = pd.read_csv(self.dataset_file)
                self.logger.info(f"Loaded existing dataset with {len(df)} rows")
                return df
            except Exception as e:
                self.logger.error(f"Error loading existing dataset: {e}")
        
        # Create new DataFrame with all columns
        columns = [
            'url', 'is_phishing',
            # WHOIS features
            'domain_age_days', 'registrar', 'creation_date', 'expiration_date', 
            'country', 'whois_privacy',
            # SSL features
            'ssl_issuer', 'ssl_validity_days', 'ssl_key_length', 'ssl_algorithm',
            'is_self_signed', 'ssl_common_name_match',
            # Behavioral features
            'url_length', 'num_dots', 'num_hyphens', 'num_underscores',
            'num_digits', 'num_params', 'has_ip_address', 'num_redirects',
            'final_url_different', 'has_iframe', 'num_iframes', 'has_js_redirect',
            'num_external_links', 'num_forms', 'has_password_field',
            'page_title_length', 'num_images', 'has_favicon'
        ]
        
        return pd.DataFrame(columns=columns)
    
    def add_row(self, data: Dict[str, Any]):
        """Add a new row to the dataset"""
        # Convert data to DataFrame row
        new_row = pd.DataFrame([data])
        self.df = pd.concat([self.df, new_row], ignore_index=True)
    
    def save_dataset(self):
        """Save the current dataset to CSV"""
        try:
            self.df.to_csv(self.dataset_file, index=False)
            self.logger.info(f"Saved dataset with {len(self.df)} rows")
        except Exception as e:
            self.logger.error(f"Error saving dataset: {e}")
    
    def get_counts(self) -> tuple:
        """Get current counts of phishing and legitimate sites"""
        if len(self.df) == 0:
            return 0, 0
        
        phishing_count = len(self.df[self.df['is_phishing'] == 1])
        legit_count = len(self.df[self.df['is_phishing'] == 0])
        return phishing_count, legit_count
    
    def is_url_processed(self, url: str) -> bool:
        """Check if URL has already been processed"""
        return url in self.df['url'].values if len(self.df) > 0 else False 