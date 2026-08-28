import time
import random
from datetime import datetime
import os
import sys

# Add the project root to the Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from config import Config
from utils.logger import CrawlerLogger
from utils.url_sources import URLSource
from utils.data_manager import DataManager
from extractors.whois_extractor import WHOISExtractor
from extractors.ssl_extractor import SSLExtractor
from extractors.behavioral_extractor import BehavioralExtractor

class PhishGuardCrawler:
    def __init__(self):
        self.config = Config()
        self.logger = CrawlerLogger(self.config.ERROR_LOG_FILE)
        self.data_manager = DataManager(self.config.DATASET_FILE, self.logger)
        
        # Initialize extractors
        self.whois_extractor = WHOISExtractor(self.logger, self.config)
        self.ssl_extractor = SSLExtractor(self.logger, self.config)
        self.behavioral_extractor = BehavioralExtractor(self.logger, self.config)
        
        # Initialize URL source
        self.url_source = URLSource(self.logger, self.config)
        
        # Statistics
        self.processed_count = 0
        self.failed_count = 0
        self.start_time = datetime.now()
        
    def run(self):
        """Main crawler execution"""
        self.logger.info("Starting PhishGuard Crawler...")
        self.logger.info(f"Target: {self.config.TARGET_PHISHING_COUNT} phishing + {self.config.TARGET_LEGIT_COUNT} legitimate URLs")
        
        # Get initial counts
        phishing_count, legit_count = self.data_manager.get_counts()
        self.logger.info(f"Current dataset: {phishing_count} phishing, {legit_count} legitimate")
        
        try:
            # Process URLs until we reach target counts
            while True:
                phishing_count, legit_count = self.data_manager.get_counts()
                
                # Check if we've reached our targets
                if (phishing_count >= self.config.TARGET_PHISHING_COUNT and 
                    legit_count >= self.config.TARGET_LEGIT_COUNT):
                    self.logger.info("Target counts reached!")
                    break
                
                # Decide what type of URLs to collect based on current counts
                if phishing_count < self.config.TARGET_PHISHING_COUNT:
                    self._process_phishing_urls()
                
                if legit_count < self.config.TARGET_LEGIT_COUNT:
                    self._process_legitimate_urls()
                
                # Save progress periodically
                self.data_manager.save_dataset()
                self._print_progress()
                
                # Small delay between batches
                time.sleep(1)
                
        except KeyboardInterrupt:
            self.logger.info("Crawler stopped by user")
        except Exception as e:
            self.logger.error(f"Crawler crashed: {e}")
        finally:
            # Final save
            self.data_manager.save_dataset()
            self._print_final_stats()
    
    def _process_phishing_urls(self):
        """Process phishing URLs"""
        self.logger.info("Processing phishing URLs...")
        
        url_count = 0
        for url in self.url_source.get_phishing_urls():
            # Check if we've reached the limit
            phishing_count, _ = self.data_manager.get_counts()
            if phishing_count >= self.config.TARGET_PHISHING_COUNT:
                break
            
            # Skip if already processed
            if self.data_manager.is_url_processed(url):
                continue
            
            # Process the URL
            success = self._process_single_url(url, is_phishing=True)
            
            url_count += 1
            
            # Take a break after processing some URLs
            if url_count >= 50:  # Process in batches
                break
            
            # Rate limiting
            time.sleep(1 / self.config.HTTP_RATE_LIMIT)
    
    def _process_legitimate_urls(self):
        """Process legitimate URLs"""
        self.logger.info("Processing legitimate URLs...")
        
        url_count = 0
        for url in self.url_source.get_legitimate_urls():
            # Check if we've reached the limit
            _, legit_count = self.data_manager.get_counts()
            if legit_count >= self.config.TARGET_LEGIT_COUNT:
                break
            
            # Skip if already processed
            if self.data_manager.is_url_processed(url):
                continue
            
            # Process the URL
            success = self._process_single_url(url, is_phishing=False)
            
            url_count += 1
            
            # Take a break after processing some URLs
            if url_count >= 50:  # Process in batches
                break
            
            # Rate limiting
            time.sleep(1 / self.config.HTTP_RATE_LIMIT)
    
    def _process_single_url(self, url: str, is_phishing: bool) -> bool:
        """Process a single URL and extract all features"""
        try:
            self.logger.info(f"Processing: {url}")
            
            # Initialize feature dict
            features = {'url': url, 'is_phishing': 1 if is_phishing else 0}
            
            # Extract WHOIS features
            self.logger.info(f"Extracting WHOIS features for: {url}")
            whois_features = self.whois_extractor.extract_whois_features(url)
            
            if not whois_features:
                self.logger.warning(f"WHOIS extraction failed for: {url}")
                self.failed_count += 1
                return False
            
            features.update(whois_features)
            
            # Rate limiting for WHOIS
            time.sleep(1 / self.config.WHOIS_RATE_LIMIT)
            
            # Extract SSL features
            self.logger.info(f"Extracting SSL features for: {url}")
            ssl_features = self.ssl_extractor.extract_ssl_features(url)
            
            if not ssl_features:
                self.logger.warning(f"SSL extraction failed for: {url}")
                self.failed_count += 1
                return False
            
            features.update(ssl_features)
            
            # Extract behavioral features
            self.logger.info(f"Extracting behavioral features for: {url}")
            behavioral_features = self.behavioral_extractor.extract_behavioral_features(url)
            
            if not behavioral_features:
                self.logger.warning(f"Behavioral extraction failed for: {url}")
                self.failed_count += 1
                return False
            
            features.update(behavioral_features)
            
            # Add to dataset
            self.data_manager.add_row(features)
            self.processed_count += 1
            
            self.logger.info(f"Successfully processed: {url}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to process {url}: {e}")
            self.failed_count += 1
            return False
    
    def _print_progress(self):
        """Print current progress"""
        phishing_count, legit_count = self.data_manager.get_counts()
        total_processed = phishing_count + legit_count
        total_target = self.config.TARGET_PHISHING_COUNT + self.config.TARGET_LEGIT_COUNT
        
        elapsed_time = datetime.now() - self.start_time
        
        self.logger.info("="*50)
        self.logger.info(f"PROGRESS UPDATE")
        self.logger.info(f"Phishing: {phishing_count}/{self.config.TARGET_PHISHING_COUNT}")
        self.logger.info(f"Legitimate: {legit_count}/{self.config.TARGET_LEGIT_COUNT}")
        self.logger.info(f"Total: {total_processed}/{total_target} ({total_processed/total_target*100:.1f}%)")
        self.logger.info(f"Failed: {self.failed_count}")
        self.logger.info(f"Runtime: {elapsed_time}")
        self.logger.info("="*50)
    
    def _print_final_stats(self):
        """Print final statistics"""
        phishing_count, legit_count = self.data_manager.get_counts()
        total_time = datetime.now() - self.start_time
        
        self.logger.info("="*50)
        self.logger.info("FINAL STATISTICS")
        self.logger.info(f"Successfully collected:")
        self.logger.info(f"  - Phishing URLs: {phishing_count}")
        self.logger.info(f"  - Legitimate URLs: {legit_count}")
        self.logger.info(f"  - Total: {phishing_count + legit_count}")
        self.logger.info(f"Failed extractions: {self.failed_count}")
        self.logger.info(f"Total runtime: {total_time}")
        self.logger.info(f"Dataset saved to: {self.config.DATASET_FILE}")
        self.logger.info("="*50)

def main():
    """Main entry point"""
    try:
        crawler = PhishGuardCrawler()
        crawler.run()
    except Exception as e:
        print(f"Crawler failed to start: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main()) 