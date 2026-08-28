import logging
import os
from datetime import datetime

class CrawlerLogger:
    def __init__(self, log_file):
        self.log_file = log_file
        self.setup_logger()
    
    def setup_logger(self):
        # Ensure log directory exists
        log_dir = os.path.dirname(self.log_file)
        if log_dir:  # Only create directory if log_dir is not empty
            os.makedirs(log_dir, exist_ok=True)
        
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def info(self, message):
        self.logger.info(message)
    
    def error(self, message):
        self.logger.error(message)
    
    def warning(self, message):
        self.logger.warning(message) 