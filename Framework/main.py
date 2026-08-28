#!/usr/bin/python
"""
PhishGuard Framework - Phishing Website Detection System
========================================================

A comprehensive machine learning framework for detecting phishing websites using:
- WHOIS features
- SSL features  
- Behavioral features

The framework supports flexible model selection based on available features.
"""

import pandas as pd
import numpy as np
import pickle
import os
import warnings
import requests
import ssl
import socket
from urllib.parse import urlparse
from datetime import datetime, timedelta
import whois
import re
from bs4 import BeautifulSoup
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, classification_report, confusion_matrix
from sklearn.utils.class_weight import compute_class_weight
import xgboost as xgb
import shap
import matplotlib.pyplot as plt
import seaborn as sns

warnings.filterwarnings('ignore')

class FeatureExtractor:
    """Extracts WHOIS, SSL, and Behavioral features from a given URL."""
    
    def __init__(self, timeout=10):
        self.timeout = timeout
    
    def extract_whois_features(self, url):
        """Extract WHOIS-based features."""
        try:
            domain = urlparse(url).netloc
            if domain.startswith('www.'):
                domain = domain[4:]
            
            w = whois.whois(domain)
            features = {}
            
            # Domain age
            if w.creation_date:
                creation_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
                features['domain_age_days'] = (datetime.now() - creation_date).days
                features['creation_date'] = str(creation_date)
            else:
                features['domain_age_days'] = -1
                features['creation_date'] = 'Unknown'
            
            # Domain expiry
            if w.expiration_date:
                expiry_date = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
                features['domain_expiry_days'] = (expiry_date - datetime.now()).days
                features['expiration_date'] = str(expiry_date)
            else:
                features['domain_expiry_days'] = -1
                features['expiration_date'] = 'Unknown'
            
            # Registrar info
            features['registrar'] = str(w.registrar) if w.registrar else 'Unknown'
            features['has_registrar'] = 1 if w.registrar else 0
            features['has_nameservers'] = 1 if w.name_servers else 0
            features['nameserver_count'] = len(w.name_servers) if w.name_servers else 0
            
            # Country
            features['country'] = str(w.country) if hasattr(w, 'country') and w.country else 'Unknown'
            
            # Privacy protection
            features['whois_privacy'] = 1 if any(keyword in str(w).lower() for keyword in ['privacy', 'protected', 'redacted']) else 0
            
            return features
            
        except Exception as e:
            print(f"WHOIS extraction error for {url}: {e}")
            return {
                'domain_age_days': -1,
                'domain_expiry_days': -1,
                'registrar': 'Unknown',
                'creation_date': 'Unknown',
                'expiration_date': 'Unknown',
                'country': 'Unknown',
                'has_registrar': 0,
                'has_nameservers': 0,
                'nameserver_count': 0,
                'whois_privacy': 0
            }
    
    def extract_ssl_features(self, url):
        """Extract SSL certificate features."""
        try:
            parsed = urlparse(url)
            hostname = parsed.netloc
            if hostname.startswith('www.'):
                hostname = hostname[4:]
            
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
            
            features = {}
            
            # Certificate validity
            not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
            
            features['ssl_validity_days'] = (not_after - datetime.now()).days
            features['ssl_cert_age_days'] = (datetime.now() - not_before).days
            features['ssl_is_expired'] = 1 if datetime.now() > not_after else 0
            
            # Issuer information
            issuer = dict(x[0] for x in cert['issuer'])
            features['ssl_self_signed'] = 1 if issuer.get('organizationName', '') == cert.get('subject', [{}])[0].get('organizationName', '') else 0
            features['ssl_issuer'] = issuer.get('organizationName', 'Unknown')
            
            # Certificate authority (simplified)
            ca_names = ['Let\'s Encrypt', 'DigiCert', 'Comodo', 'GeoTrust', 'Symantec', 'GoDaddy', 'Google Trust Services', 'Sectigo']
            features['ssl_trusted_ca'] = 1 if any(ca in issuer.get('organizationName', '') for ca in ca_names) else 0
            
            # Subject alternative names
            features['ssl_san_count'] = len(cert.get('subjectAltName', []))
            
            # Common name match
            common_name = None
            for field in cert.get('subject', []):
                for key, value in field:
                    if key == 'commonName':
                        common_name = value
                        break
            
            features['ssl_common_name_match'] = 1 if common_name and (common_name == hostname or f"*.{hostname.split('.', 1)[1]}" == common_name) else 0
            
            # SSL key length and algorithm
            if cipher:
                features['ssl_key_length'] = cipher[2]  # Key length
                features['ssl_algorithm'] = cipher[0]    # Algorithm name
            else:
                features['ssl_key_length'] = 0
                features['ssl_algorithm'] = 'Unknown'
            
            return features
            
        except Exception as e:
            print(f"SSL extraction error for {url}: {e}")
            return {
                'ssl_validity_days': -1,
                'ssl_cert_age_days': -1,
                'ssl_is_expired': 1,
                'ssl_self_signed': 1,
                'ssl_trusted_ca': 0,
                'ssl_san_count': 0,
                'ssl_issuer': 'Unknown',
                'ssl_common_name_match': 0,
                'ssl_key_length': 0,
                'ssl_algorithm': 'Unknown'
            }
    
    def extract_behavioral_features(self, url):
        """Extract behavioral features from URL and webpage content."""
        try:
            features = {}
            parsed = urlparse(url)
            
            # URL-based features
            features['url_length'] = len(url)
            features['domain_length'] = len(parsed.netloc)
            features['path_length'] = len(parsed.path)
            features['has_ip_address'] = 1 if re.match(r'\d+\.\d+\.\d+\.\d+', parsed.netloc) else 0
            features['num_dots'] = url.count('.')
            features['num_hyphens'] = url.count('-')
            features['num_underscores'] = url.count('_')
            features['num_digits'] = sum(1 for char in url if char.isdigit())
            features['num_params'] = len(parsed.query.split('&')) if parsed.query else 0
            
            # Initialize redirect features
            features['num_redirects'] = 0
            features['final_url_different'] = 0
            
            # Try to fetch webpage content
            try:
                response = requests.get(url, timeout=self.timeout, allow_redirects=True)
                
                # Check redirects
                if response.history:
                    features['num_redirects'] = len(response.history)
                    features['final_url_different'] = 1 if response.url != url else 0
                
                soup = BeautifulSoup(response.content, 'html.parser')
                
                # Content-based features
                features['page_title_length'] = len(soup.title.string) if soup.title and soup.title.string else 0
                
                # Form features
                forms = soup.find_all('form')
                features['num_forms'] = len(forms)
                
                # Check for password fields
                password_fields = soup.find_all('input', {'type': 'password'})
                features['has_password_field'] = 1 if password_fields else 0
                
                # Iframe features
                iframes = soup.find_all('iframe')
                features['has_iframe'] = 1 if iframes else 0
                features['num_iframes'] = len(iframes)
                
                # External links
                links = soup.find_all('a', href=True)
                external_links = [link for link in links if urlparse(link['href']).netloc and urlparse(link['href']).netloc != parsed.netloc]
                features['num_external_links'] = len(external_links)
                
                # Images
                images = soup.find_all('img')
                features['num_images'] = len(images)
                
                # Favicon
                features['has_favicon'] = 1 if soup.find('link', rel='icon') or soup.find('link', rel='shortcut icon') else 0
                
                # JavaScript redirect
                scripts = soup.find_all('script')
                script_content = ' '.join([script.string for script in scripts if script.string])
                features['has_js_redirect'] = 1 if any(pattern in script_content.lower() for pattern in ['window.location', 'document.location', 'window.href', '.href']) else 0
                
            except Exception as e:
                print(f"Webpage fetch error for {url}: {e}")
                # If webpage fetch fails, set default values
                features.update({
                    'page_title_length': 0,
                    'num_forms': 0,
                    'has_password_field': 0,
                    'has_iframe': 0,
                    'num_iframes': 0,
                    'num_external_links': 0,
                    'num_images': 0,
                    'has_favicon': 0,
                    'has_js_redirect': 0,
                    'num_redirects': 0,
                    'final_url_different': 0
                })
            
            return features
            
        except Exception as e:
            print(f"Behavioral extraction error for {url}: {e}")
            return {
                'url_length': len(url),
                'domain_length': 0,
                'path_length': 0,
                'has_ip_address': 0,
                'num_dots': 0,
                'num_hyphens': 0,
                'num_underscores': 0,
                'num_digits': 0,
                'num_params': 0,
                'num_redirects': 0,
                'final_url_different': 0,
                'has_iframe': 0,
                'num_iframes': 0,
                'has_js_redirect': 0,
                'num_external_links': 0,
                'num_forms': 0,
                'has_password_field': 0,
                'page_title_length': 0,
                'num_images': 0,
                'has_favicon': 0
            }
    
    def extract_all_features(self, url):
        """Extract all features from a URL."""
        print(f"Extracting features for: {url}")
        
        whois_features = self.extract_whois_features(url)
        ssl_features = self.extract_ssl_features(url)
        behavioral_features = self.extract_behavioral_features(url)
        
        all_features = {**whois_features, **ssl_features, **behavioral_features}
        
        # Map features to match dataset columns
        mapped_features = {
            'url': url,
            'domain_age_days': whois_features.get('domain_age_days', -1),
            'registrar': whois_features.get('has_registrar', 0),
            'creation_date': whois_features.get('creation_date', 'Unknown'),
            'expiration_date': whois_features.get('expiration_date', 'Unknown'),
            'country': whois_features.get('country', 'Unknown'),
            'whois_privacy': whois_features.get('whois_privacy', 0),
            'ssl_issuer': ssl_features.get('ssl_trusted_ca', 0),
            'ssl_validity_days': ssl_features.get('ssl_validity_days', -1),
            'ssl_key_length': ssl_features.get('ssl_key_length', 0),
            'ssl_algorithm': ssl_features.get('ssl_algorithm', 'Unknown'),
            'is_self_signed': ssl_features.get('ssl_self_signed', 1),
            'ssl_common_name_match': ssl_features.get('ssl_common_name_match', 0),
            'url_length': behavioral_features.get('url_length', 0),
            'num_dots': behavioral_features.get('num_dots', 0),
            'num_hyphens': behavioral_features.get('num_hyphens', 0),
            'num_underscores': behavioral_features.get('num_underscores', 0),
            'num_digits': behavioral_features.get('digit_count', 0),
            'num_params': behavioral_features.get('num_params', 0),
            'has_ip_address': behavioral_features.get('has_ip_address', 0),
            'num_redirects': behavioral_features.get('num_redirects', 0),
            'final_url_different': behavioral_features.get('final_url_different', 0),
            'has_iframe': 1 if behavioral_features.get('iframe_count', 0) > 0 else 0,
            'num_iframes': behavioral_features.get('iframe_count', 0),
            'has_js_redirect': behavioral_features.get('has_js_redirect', 0),
            'num_external_links': behavioral_features.get('external_links', 0),
            'num_forms': behavioral_features.get('form_count', 0),
            'has_password_field': behavioral_features.get('has_password_field', 0),
            'page_title_length': behavioral_features.get('page_title_length', 0),
            'num_images': behavioral_features.get('num_images', 0),
            'has_favicon': behavioral_features.get('has_favicon', 0)
        }
        
        # Determine which feature groups are available (not all -1 or 0)
        available_groups = []
        if any(mapped_features.get(k, -1) > 0 for k in ['domain_age_days', 'registrar', 'whois_privacy']):
            available_groups.append('whois')
        if any(mapped_features.get(k, -1) > 0 for k in ['ssl_validity_days', 'ssl_key_length', 'ssl_common_name_match']):
            available_groups.append('ssl')
        if any(mapped_features.get(k, 0) > 0 for k in ['url_length', 'num_dots', 'num_forms', 'has_favicon']):
            available_groups.append('behavioral')
        
        return mapped_features, available_groups


class PhishGuardFramework:
    """Main PhishGuard Framework for phishing website detection."""
    
    def __init__(self, models_dir='phishguard_models'):
        self.models_dir = models_dir
        self.models = {}
        self.scalers = {}
        self.feature_columns = {}
        self.feature_extractor = FeatureExtractor()
        
        # Define model configurations
        self.model_configs = {
            'whois': {'features': 'whois', 'name': 'WHOIS Only'},
            'ssl': {'features': 'ssl', 'name': 'SSL Only'},
            'behavioral': {'features': 'behavioral', 'name': 'Behavioral Only'},
            'whois_ssl': {'features': 'whois+ssl', 'name': 'WHOIS + SSL'},
            'whois_behavioral': {'features': 'whois+behavioral', 'name': 'WHOIS + Behavioral'},
            'ssl_behavioral': {'features': 'ssl+behavioral', 'name': 'SSL + Behavioral'},
            'combined': {'features': 'whois+ssl+behavioral', 'name': 'Combined (All Features)'}
        }
        
        # Create models directory
        os.makedirs(self.models_dir, exist_ok=True)
    
    def generate_synthetic_dataset(self, n_samples=1031):
        """Generate a synthetic dataset for demonstration purposes."""
        print(f"Generating synthetic dataset with {n_samples} samples...")
        
        np.random.seed(42)
        
        # Class distribution (849 phishing, 182 legitimate)
        n_phishing = int(0.823 * n_samples)  # ~823
        n_legitimate = n_samples - n_phishing
        
        labels = [1] * n_phishing + [0] * n_legitimate
        np.random.shuffle(labels)
        
        data = []
        
        for i, label in enumerate(labels):
            if label == 1:  # Phishing
                # Phishing websites tend to have suspicious characteristics
                features = {
                    # WHOIS features (phishing sites often have newer domains)
                    'domain_age_days': np.random.exponential(30) if np.random.random() > 0.3 else np.random.uniform(0, 365),
                    'domain_expiry_days': np.random.uniform(-10, 365),
                    'has_registrar': np.random.choice([0, 1], p=[0.2, 0.8]),
                    'has_nameservers': np.random.choice([0, 1], p=[0.1, 0.9]),
                    'nameserver_count': np.random.poisson(2),
                    'whois_privacy': np.random.choice([0, 1], p=[0.3, 0.7]),
                    
                    # SSL features (phishing sites often have poor SSL)
                    'ssl_validity_days': np.random.uniform(-10, 90),
                    'ssl_cert_age_days': np.random.uniform(0, 100),
                    'ssl_is_expired': np.random.choice([0, 1], p=[0.7, 0.3]),
                    'ssl_self_signed': np.random.choice([0, 1], p=[0.4, 0.6]),
                    'ssl_trusted_ca': np.random.choice([0, 1], p=[0.6, 0.4]),
                    'ssl_san_count': np.random.poisson(1),
                    
                    # Behavioral features (phishing sites are often suspicious)
                    'url_length': np.random.normal(80, 30),
                    'domain_length': np.random.normal(25, 10),
                    'path_length': np.random.normal(30, 15),
                    'has_ip_address': np.random.choice([0, 1], p=[0.8, 0.2]),
                    'subdomain_count': np.random.poisson(3),
                    'suspicious_keywords': np.random.poisson(2),
                    'special_char_count': np.random.poisson(15),
                    'digit_count': np.random.poisson(8),
                    'page_title_length': np.random.normal(40, 20),
                    'form_count': np.random.poisson(2),
                    'input_count': np.random.poisson(5),
                    'iframe_count': np.random.poisson(1),
                    'external_links': np.random.poisson(3),
                    'internal_links': np.random.poisson(8),
                    'has_favicon': np.random.choice([0, 1], p=[0.4, 0.6]),
                    'script_count': np.random.poisson(3),
                    'suspicious_words': np.random.poisson(2)
                }
            else:  # Legitimate
                # Legitimate websites have more trustworthy characteristics
                features = {
                    # WHOIS features (legitimate sites often older)
                    'domain_age_days': np.random.uniform(365, 3650),
                    'domain_expiry_days': np.random.uniform(30, 730),
                    'has_registrar': np.random.choice([0, 1], p=[0.05, 0.95]),
                    'has_nameservers': np.random.choice([0, 1], p=[0.02, 0.98]),
                    'nameserver_count': np.random.poisson(3),
                    'whois_privacy': np.random.choice([0, 1], p=[0.6, 0.4]),
                    
                    # SSL features (legitimate sites have better SSL)
                    'ssl_validity_days': np.random.uniform(30, 365),
                    'ssl_cert_age_days': np.random.uniform(30, 365),
                    'ssl_is_expired': np.random.choice([0, 1], p=[0.95, 0.05]),
                    'ssl_self_signed': np.random.choice([0, 1], p=[0.9, 0.1]),
                    'ssl_trusted_ca': np.random.choice([0, 1], p=[0.2, 0.8]),
                    'ssl_san_count': np.random.poisson(2),
                    
                    # Behavioral features (legitimate sites less suspicious)
                    'url_length': np.random.normal(45, 15),
                    'domain_length': np.random.normal(15, 8),
                    'path_length': np.random.normal(20, 10),
                    'has_ip_address': np.random.choice([0, 1], p=[0.98, 0.02]),
                    'subdomain_count': np.random.poisson(1),
                    'suspicious_keywords': np.random.poisson(0.5),
                    'special_char_count': np.random.poisson(8),
                    'digit_count': np.random.poisson(4),
                    'page_title_length': np.random.normal(60, 25),
                    'form_count': np.random.poisson(1),
                    'input_count': np.random.poisson(3),
                    'iframe_count': np.random.poisson(0.5),
                    'external_links': np.random.poisson(5),
                    'internal_links': np.random.poisson(12),
                    'has_favicon': np.random.choice([0, 1], p=[0.1, 0.9]),
                    'script_count': np.random.poisson(5),
                    'suspicious_words': np.random.poisson(0.3)
                }
            
            # Ensure non-negative values
            for key in features:
                features[key] = max(0, features[key])
            
            features['label'] = label
            data.append(features)
        
        df = pd.DataFrame(data)
        print(f"Dataset generated: {len(df)} samples")
        print(f"Class distribution: {df['label'].value_counts().to_dict()}")
        return df
    
    def get_feature_groups(self, df):
        """Separate features into groups based on the dataset columns."""
        # WHOIS features
        whois_features = ['domain_age_days', 'registrar', 'creation_date', 'expiration_date', 'country', 'whois_privacy']
        
        # SSL features
        ssl_features = ['ssl_issuer', 'ssl_validity_days', 'ssl_key_length', 'ssl_algorithm', 'is_self_signed', 'ssl_common_name_match']
        
        # Behavioral features
        behavioral_features = ['url_length', 'num_dots', 'num_hyphens', 'num_underscores', 'num_digits', 'num_params', 
                              'has_ip_address', 'num_redirects', 'final_url_different', 'has_iframe', 'num_iframes', 
                              'has_js_redirect', 'num_external_links', 'num_forms', 'has_password_field', 
                              'page_title_length', 'num_images', 'has_favicon']
        
        # Filter to only include columns that exist in the dataframe
        whois_features = [col for col in whois_features if col in df.columns]
        ssl_features = [col for col in ssl_features if col in df.columns]
        behavioral_features = [col for col in behavioral_features if col in df.columns]
        
        return whois_features, ssl_features, behavioral_features
    
    def prepare_feature_sets(self, df):
        """Prepare different feature combinations."""
        whois_features, ssl_features, behavioral_features = self.get_feature_groups(df)
        
        feature_sets = {
            'whois': whois_features,
            'ssl': ssl_features,
            'behavioral': behavioral_features,
            'whois_ssl': whois_features + ssl_features,
            'whois_behavioral': whois_features + behavioral_features,
            'ssl_behavioral': ssl_features + behavioral_features,
            'combined': whois_features + ssl_features + behavioral_features
        }
        
        return feature_sets
    
    def train_models(self, df):
        """Train all 7 models with different feature combinations."""
        print("\n=== TRAINING PHASE ===")
        
        # Prepare feature sets
        feature_sets = self.prepare_feature_sets(df)
        
        # Make a copy to avoid modifying the original dataframe
        df_processed = df.copy()
        
        # Handle string values in the dataset
        for col in df_processed.columns:
            if df_processed[col].dtype == 'object':
                print(f"Processing column: {col}")
                
                # Replace 'Unknown' with NaN
                df_processed[col] = df_processed[col].replace('Unknown', np.nan)
                
                # Try to convert to datetime and extract days if possible
                if 'date' in col.lower():
                    try:
                        df_processed[col] = pd.to_datetime(df_processed[col], errors='coerce')
                        # Calculate days from a reference date
                        df_processed[col] = (df_processed[col] - pd.Timestamp('1970-01-01')).dt.total_seconds() / (24*60*60)
                    except Exception as e:
                        print(f"Error converting {col} to datetime: {e}")
                        # If conversion fails, drop the column
                        df_processed = df_processed.drop(col, axis=1)
                # For categorical columns, use one-hot encoding
                elif col not in ['url', 'is_phishing']:
                    print(f"One-hot encoding column: {col}")
                    # Convert to string first to handle any non-string objects
                    df_processed[col] = df_processed[col].astype(str)
                    # Create dummies and drop the original column
                    dummies = pd.get_dummies(df_processed[col], prefix=col, dummy_na=True)
                    df_processed = pd.concat([df_processed.drop(col, axis=1), dummies], axis=1)
        
        # Split data
        X = df_processed.drop(['url', 'is_phishing'], axis=1, errors='ignore')
        y = df_processed['is_phishing']
        
        # Fill NaN values with median for numeric columns and drop object columns
        numeric_cols = X.select_dtypes(include=['number']).columns
        for col in numeric_cols:
            X[col] = X[col].fillna(X[col].median())
            
        # Drop any remaining object columns
        X = X.select_dtypes(include=['number'])
        
        print(f"Final feature columns: {X.columns.tolist()}")
        print(f"Number of features: {len(X.columns)}")
        
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
        
        print(f"Training set: {len(X_train)} samples")
        print(f"Test set: {len(X_test)} samples")
        print(f"Class distribution in training: {y_train.value_counts().to_dict()}")
        
        # Calculate class weights for imbalanced data
        class_weights = compute_class_weight('balanced', classes=np.unique(y_train), y=y_train)
        class_weight_dict = {0: class_weights[0], 1: class_weights[1]}
        print(f"Class weights: {class_weight_dict}")
        
        results = {}
        
        # Train each model
        for model_name, features in feature_sets.items():
            print(f"\nTraining {self.model_configs[model_name]['name']} model...")
            print(f"Features used: {len(features)} features")
            
            # Filter features to only include those in the processed dataframe
            valid_features = [f for f in features if f in X.columns]
            print(f"Valid features: {len(valid_features)} of {len(features)}")
            
            # Prepare data for this model
            X_train_subset = X_train[valid_features]
            X_test_subset = X_test[valid_features]
            
            # Scale features
            scaler = StandardScaler()
            X_train_scaled = scaler.fit_transform(X_train_subset)
            X_test_scaled = scaler.transform(X_test_subset)
            
            # Train both Random Forest and XGBoost models
            # 1. Random Forest
            rf_model = RandomForestClassifier(
                n_estimators=100,
                max_depth=6,
                class_weight=class_weight_dict,
                random_state=42
            )
            
            rf_model.fit(X_train_scaled, y_train)
            
            # 2. XGBoost
            xgb_model = xgb.XGBClassifier(
                n_estimators=100,
                max_depth=6,
                learning_rate=0.1,
                scale_pos_weight=class_weight_dict[1]/class_weight_dict[0],
                random_state=42,
                eval_metric='logloss'
            )
            
            xgb_model.fit(X_train_scaled, y_train)
            
            # Use Random Forest as the primary model
            model = rf_model
            
            # Also evaluate Random Forest
            rf_pred = rf_model.predict(X_test_scaled)
            rf_pred_proba = rf_model.predict_proba(X_test_scaled)[:, 1]
            
            # Calculate RF metrics
            rf_metrics = {
                'accuracy': accuracy_score(y_test, rf_pred),
                'precision': precision_score(y_test, rf_pred),
                'recall': recall_score(y_test, rf_pred),
                'f1': f1_score(y_test, rf_pred),
                'auc': roc_auc_score(y_test, rf_pred_proba)
            }
            
            # Store RF results
            results[f"{model_name}_rf"] = rf_metrics
            print(f"Random Forest - Accuracy: {rf_metrics['accuracy']:.4f}, F1: {rf_metrics['f1']:.4f}, AUC: {rf_metrics['auc']:.4f}")
            
            # Make predictions
            y_pred = model.predict(X_test_scaled)
            y_pred_proba = model.predict_proba(X_test_scaled)[:, 1]
            
            # Calculate metrics
            metrics = {
                'accuracy': accuracy_score(y_test, y_pred),
                'precision': precision_score(y_test, y_pred),
                'recall': recall_score(y_test, y_pred),
                'f1': f1_score(y_test, y_pred),
                'auc': roc_auc_score(y_test, y_pred_proba)
            }
            
            results[model_name] = metrics
            
            # Save model and scaler
            self.models[model_name] = model
            self.scalers[model_name] = scaler
            self.feature_columns[model_name] = valid_features  # Save the actual features used
            
            # Save to disk
            with open(f"{self.models_dir}/{model_name}_xgb_model.pkl", 'wb') as f:
                pickle.dump(xgb_model, f)
            with open(f"{self.models_dir}/{model_name}_rf_model.pkl", 'wb') as f:
                pickle.dump(rf_model, f)
            with open(f"{self.models_dir}/{model_name}_scaler.pkl", 'wb') as f:
                pickle.dump(scaler, f)
            with open(f"{self.models_dir}/{model_name}_features.pkl", 'wb') as f:
                pickle.dump(valid_features, f)  # Save the actual features used
            
            print(f"Accuracy: {metrics['accuracy']:.4f}, F1: {metrics['f1']:.4f}, AUC: {metrics['auc']:.4f}")
        
        # Save results
        with open(f"{self.models_dir}/training_results.pkl", 'wb') as f:
            pickle.dump(results, f)
        
        return results
    
    def load_models(self):
        """Load pre-trained models from disk."""
        print("Loading pre-trained models...")
        
        for model_name in self.model_configs.keys():
            try:
                with open(f"{self.models_dir}/{model_name}_model.pkl", 'rb') as f:
                    self.models[model_name] = pickle.load(f)
                with open(f"{self.models_dir}/{model_name}_scaler.pkl", 'rb') as f:
                    self.scalers[model_name] = pickle.load(f)
                with open(f"{self.models_dir}/{model_name}_features.pkl", 'rb') as f:
                    self.feature_columns[model_name] = pickle.load(f)
                print(f"✓ Loaded {self.model_configs[model_name]['name']} model")
            except FileNotFoundError:
                print(f"✗ {self.model_configs[model_name]['name']} model not found")
    
    def select_best_model(self, available_groups):
        """Select the best model based on available feature groups."""
        # Priority order: combined > hybrid models > single models
        model_priority = [
            ('combined', ['whois', 'ssl', 'behavioral']),
            ('whois_ssl', ['whois', 'ssl']),
            ('whois_behavioral', ['whois', 'behavioral']),
            ('ssl_behavioral', ['ssl', 'behavioral']),
            ('whois', ['whois']),
            ('ssl', ['ssl']),
            ('behavioral', ['behavioral'])
        ]
        
        for model_name, required_groups in model_priority:
            if all(group in available_groups for group in required_groups):
                return model_name
        
        # Fallback to behavioral if available (most basic features)
        if 'behavioral' in available_groups:
            return 'behavioral'
        
        return None
    
    def predict_url(self, url):
        """Predict if a URL is phishing or legitimate."""
        print(f"\n=== PREDICTION FOR: {url} ===")
        
        # Extract features
        try:
            features, available_groups = self.feature_extractor.extract_all_features(url)
        except Exception as e:
            return {
                'error': f"Feature extraction failed: {str(e)}",
                'url': url
            }
        
        print(f"Available feature groups: {available_groups}")
        
        if not available_groups:
            return {
                'error': "No features could be extracted",
                'url': url
            }
        
        # Select appropriate model
        selected_model = self.select_best_model(available_groups)
        if not selected_model or selected_model not in self.models:
            return {
                'error': f"No suitable model found for available features: {available_groups}",
                'url': url
            }
        
        print(f"Using model: {self.model_configs[selected_model]['name']}")
        
        # Prepare features for prediction
        model_features = self.feature_columns[selected_model]
        feature_vector = []
        
        # Process features before prediction
        processed_features = {}
        for key, value in features.items():
            # Handle date fields
            if key in ['creation_date', 'expiration_date'] and isinstance(value, str):
                try:
                    if value != 'Unknown':
                        # Convert to datetime and then to days since epoch
                        dt = pd.to_datetime(value)
                        processed_features[key] = (dt - pd.Timestamp('1970-01-01')).total_seconds() / (24*60*60)
                    else:
                        processed_features[key] = -1  # Default for unknown dates
                except Exception as e:
                    print(f"Error converting date {key}: {e}")
                    processed_features[key] = -1
            # Handle string values that should be numeric
            elif key in ['country', 'registrar', 'ssl_issuer', 'ssl_algorithm'] and isinstance(value, str):
                # For string values that should be categorical, use a numeric placeholder
                processed_features[key] = -1  # Use -1 as a placeholder for categorical strings
            else:
                processed_features[key] = value
        
        # Build feature vector using processed features
        print(f"Model expects {len(model_features)} features: {model_features}")
        
        # Create a dictionary to track which features we've processed
        feature_dict = {}
        for feature in model_features:
            if feature in processed_features:
                feature_dict[feature] = processed_features[feature]
            else:
                feature_dict[feature] = 0  # Default value for missing features
        
        # Ensure we only use the exact features the model expects
        feature_vector = [feature_dict[feature] for feature in model_features]
        
        try:
            # Scale features
            feature_array = np.array(feature_vector).reshape(1, -1)
            scaled_features = self.scalers[selected_model].transform(feature_array)
        except Exception as e:
            print(f"❌ An error occurred: {e}")
            return {
                'error': f"Prediction failed: {str(e)}",
                'url': url
            }
        
        # Make prediction
        model = self.models[selected_model]
        prediction = model.predict(scaled_features)[0]
        probability = model.predict_proba(scaled_features)[0]
        
        # Get feature importance for explainability
        feature_importance = dict(zip(model_features, model.feature_importances_))
        top_features = sorted(feature_importance.items(), key=lambda x: x[1], reverse=True)[:5]
        
        result = {
            'url': url,
            'prediction': 'Phishing' if prediction == 1 else 'Legitimate',
            'confidence': float(max(probability)),
            'probability_phishing': float(probability[1]),
            'probability_legitimate': float(probability[0]),
            'model_used': self.model_configs[selected_model]['name'],
            'available_features': available_groups,
            'top_contributing_features': [{'feature': feat, 'importance': float(imp)} for feat, imp in top_features],
            'extracted_features': features
        }
        
        return result
    
    def evaluate_models(self):
        """Load and display evaluation results."""
        try:
            with open(f"{self.models_dir}/training_results.pkl", 'rb') as f:
                results = pickle.load(f)
            
            print("\n=== MODEL EVALUATION RESULTS ===")
            print(f"{'Model':<25} {'Accuracy':<10} {'Precision':<10} {'Recall':<10} {'F1-Score':<10} {'AUC':<10}")
            print("-" * 75)
            
            # Track best models by algorithm type
            best_rf = {'accuracy': 0, 'model': None}
            best_xgb = {'accuracy': 0, 'model': None}
            
            for model_name, metrics in results.items():
                # Check if it's a Random Forest model
                if model_name.endswith('_rf'):
                    base_model_name = model_name[:-3]  # Remove _rf suffix
                    if base_model_name in self.model_configs:
                        model_display_name = f"{self.model_configs[base_model_name]['name']} (RF)"
                    else:
                        model_display_name = f"{model_name} (RF)"
                    
                    # Track best RF model
                    if metrics['accuracy'] > best_rf['accuracy']:
                        best_rf['accuracy'] = metrics['accuracy']
                        best_rf['model'] = model_display_name
                else:
                    # Regular XGBoost model
                    if model_name in self.model_configs:
                        model_display_name = f"{self.model_configs[model_name]['name']} (XGB)"
                    else:
                        model_display_name = f"{model_name} (XGB)"
                    
                    # Track best XGBoost model
                    if metrics['accuracy'] > best_xgb['accuracy']:
                        best_xgb['accuracy'] = metrics['accuracy']
                        best_xgb['model'] = model_display_name
                
                print(f"{model_display_name:<25} {metrics['accuracy']:<10.4f} {metrics['precision']:<10.4f} {metrics['recall']:<10.4f} {metrics['f1']:<10.4f} {metrics['auc']:<10.4f}")
            
            # Display best models
            print("\n=== BEST MODEL PERFORMANCE ===")
            print(f"Best Random Forest Model: {best_rf['model']} with accuracy {best_rf['accuracy']:.4f}")
            print(f"Best XGBoost Model: {best_xgb['model']} with accuracy {best_xgb['accuracy']:.4f}")
            
            return results
            
        except FileNotFoundError:
            print("No evaluation results found. Please train models first.")
            return None


def main():
    """Main function to demonstrate the PhishGuard Framework."""
    print("🛡️  PhishGuard Framework - Phishing Website Detection System")
    print("=" * 60)
    
    # Initialize framework
    framework = PhishGuardFramework()
    
    # Force retrain models to ensure feature consistency
    print("Loading dataset and training models...")
    
    # Load dataset from CSV
    dataset_path = "../Datasets/dataset.csv"
    print(f"Loading dataset from {dataset_path}...")
    df = pd.read_csv(dataset_path)
    print(f"Dataset loaded: {len(df)} samples")
    print(f"Class distribution: {df['is_phishing'].value_counts().to_dict()}")
    
    # Train models
    results = framework.train_models(df)
    
    print("\n✅ Training completed successfully!")
    
    # Evaluate models
    framework.evaluate_models()
    
    # Example predictions
    test_urls = [
        "https://www.google.com",
        "https://github.com",
        "https://secure-bank-update-verify123.com/login",
        "https://paypal-security-alert.com/verify-account",
        "https://amazon.com"
    ]
    
    print("\n=== EXAMPLE PREDICTIONS ===")
    for url in test_urls:
        try:
            result = framework.predict_url(url)
            if 'error' in result:
                print(f"\n❌ Error for {url}: {result['error']}")
            else:
                print(f"\n🔍 URL: {result['url']}")
                print(f"   Prediction: {result['prediction']} ({result['confidence']:.2%} confidence)")
                print(f"   Model Used: {result['model_used']}")
                print(f"   Available Features: {', '.join(result['available_features'])}")
                print(f"   Top Contributing Features:")
                for feat_info in result['top_contributing_features'][:3]:
                    print(f"     - {feat_info['feature']}: {feat_info['importance']:.3f}")
        except Exception as e:
            print(f"\n❌ Prediction failed for {url}: {str(e)}")
    
    print("\n" + "=" * 60)
    print("🎯 PhishGuard Framework Demo Complete!")
    print("\nFramework Capabilities:")
    print("✅ 7 different ML models trained on various feature combinations")
    print("✅ Automatic feature extraction from URLs (WHOIS, SSL, Behavioral)")
    print("✅ Intelligent model selection based on available features")
    print("✅ Robust handling of missing data")
    print("✅ Explainable predictions with feature importance")
    print("✅ High accuracy phishing detection")
    
    # Interactive mode
    print("\n" + "=" * 60)
    print("🚀 INTERACTIVE MODE")
    print("Enter URLs to test (or 'quit' to exit):")
    
    while True:
        try:
            user_url = input("\nEnter URL: ").strip()
            if user_url.lower() in ['quit', 'exit', 'q']:
                break
            
            if not user_url.startswith(('http://', 'https://')):
                user_url = 'https://' + user_url
            
            result = framework.predict_url(user_url)
            
            if 'error' in result:
                print(f"❌ Error: {result['error']}")
            else:
                print(f"\n🔍 Analysis Results:")
                print(f"   URL: {result['url']}")
                print(f"   🎯 Prediction: {result['prediction']}")
                print(f"   📊 Confidence: {result['confidence']:.2%}")
                print(f"   🤖 Model Used: {result['model_used']}")
                print(f"   📋 Features Available: {', '.join(result['available_features'])}")
                print(f"   🏆 Top Contributing Features:")
                for i, feat_info in enumerate(result['top_contributing_features'][:3], 1):
                    print(f"      {i}. {feat_info['feature']}: {feat_info['importance']:.3f}")
                
                if result['prediction'] == 'Phishing':
                    print("   ⚠️  WARNING: This website appears to be PHISHING!")
                else:
                    print("   ✅ This website appears to be LEGITIMATE.")
        
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"❌ An error occurred: {str(e)}")
    
    print("\nThank you for using PhishGuard Framework! 🛡️")


class PhishGuardAPI:
    """Simple API wrapper for PhishGuard Framework."""
    
    def __init__(self):
        self.framework = PhishGuardFramework()
        self.framework.load_models()
    
    def analyze_url(self, url):
        """Analyze a single URL and return results."""
        return self.framework.predict_url(url)
    
    def batch_analyze(self, urls):
        """Analyze multiple URLs."""
        results = []
        for url in urls:
            result = self.analyze_url(url)
            results.append(result)
        return results
    
    def get_model_info(self):
        """Get information about available models."""
        return {
            'available_models': list(self.framework.model_configs.keys()),
            'model_descriptions': {k: v['name'] for k, v in self.framework.model_configs.items()},
            'models_loaded': list(self.framework.models.keys())
        }


# Additional utility functions
def create_phishing_report(results):
    """Create a detailed report from prediction results."""
    if isinstance(results, dict):
        results = [results]
    
    report = {
        'timestamp': datetime.now().isoformat(),
        'total_urls_analyzed': len(results),
        'phishing_detected': sum(1 for r in results if r.get('prediction') == 'Phishing'),
        'legitimate_detected': sum(1 for r in results if r.get('prediction') == 'Legitimate'),
        'errors': sum(1 for r in results if 'error' in r),
        'detailed_results': results
    }
    
    return report


def export_results_to_csv(results, filename='phishguard_results.csv'):
    """Export prediction results to CSV file."""
    if isinstance(results, dict):
        results = [results]
    
    # Prepare data for CSV
    csv_data = []
    for result in results:
        if 'error' not in result:
            csv_row = {
                'url': result['url'],
                'prediction': result['prediction'],
                'confidence': result['confidence'],
                'probability_phishing': result['probability_phishing'],
                'model_used': result['model_used'],
                'available_features': ','.join(result['available_features']),
                'top_feature_1': result['top_contributing_features'][0]['feature'] if result['top_contributing_features'] else '',
                'top_feature_1_importance': result['top_contributing_features'][0]['importance'] if result['top_contributing_features'] else 0
            }
            csv_data.append(csv_row)
    
    # Save to CSV
    df = pd.DataFrame(csv_data)
    df.to_csv(filename, index=False)
    print(f"Results exported to {filename}")


# Example usage for batch processing
def batch_url_analysis(url_file='urls.txt'):
    """Analyze URLs from a file."""
    try:
        with open(url_file, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
        
        framework = PhishGuardFramework()
        framework.load_models()
        
        results = []
        print(f"Analyzing {len(urls)} URLs from {url_file}...")
        
        for i, url in enumerate(urls, 1):
            print(f"Processing {i}/{len(urls)}: {url}")
            result = framework.predict_url(url)
            results.append(result)
        
        # Generate report
        report = create_phishing_report(results)
        
        print(f"\n📊 BATCH ANALYSIS REPORT:")
        print(f"   Total URLs: {report['total_urls_analyzed']}")
        print(f"   Phishing: {report['phishing_detected']}")
        print(f"   Legitimate: {report['legitimate_detected']}")
        print(f"   Errors: {report['errors']}")
        
        # Export results
        export_results_to_csv(results)
        
        return results
        
    except FileNotFoundError:
        print(f"File {url_file} not found.")
        return None


if __name__ == "__main__":
    main() 