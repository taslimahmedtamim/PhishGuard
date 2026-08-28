import os

class Config:
    # Target counts
    TARGET_PHISHING_COUNT = 5000
    TARGET_LEGIT_COUNT = 5000
    
    # OPTIMIZED: Reduced timeouts for faster processing
    REQUEST_TIMEOUT = 8     # Reduced from 10
    MAX_RETRIES = 2         # Reduced from 3
    RETRY_DELAY = 1         # Reduced from 2
    
    # OPTIMIZED: Increased rate limiting for faster collection
    WHOIS_RATE_LIMIT = 1.0  # Increased from 0.5 (1 req/sec instead of 1 req/2sec)
    HTTP_RATE_LIMIT = 4.0   # Increased from 2.0 (4 req/sec instead of 2)
    
    # File paths
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    DATA_DIR = os.path.join(BASE_DIR, 'data')
    DATASET_FILE = os.path.join(DATA_DIR, 'dataset.csv')
    ERROR_LOG_FILE = os.path.join(DATA_DIR, 'crawler_errors.log')
    
    # URL Sources
    PHISHING_SOURCES = [
        'http://data.phishtank.com/data/online-valid.csv',
        'https://openphish.com/feed.txt'
    ]
    
    # OPTIMIZED: Multiple legitimate sources for better collection
    LEGIT_SOURCES = [
        'https://tranco-list.eu/download/latest/10000',  # Reduced to top 10k for faster download
        # We'll add manual fallback sites below
    ]
    
    # EXPANDED: More user agents for better success rate
    USER_AGENTS = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/118.0.2088.46',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15'
    ]
    
    # OPTIMIZED: Feature extraction settings
    MAX_PAGE_SIZE = 2 * 1024 * 1024  # Reduced from 5MB to 2MB for faster processing
    SSL_TIMEOUT = 8                   # Increased from 5 to 8 (more time for SSL handshake)
    WHOIS_TIMEOUT = 8                 # Reduced from 10 to 8
    
    # NEW: Batch processing settings
    BATCH_SIZE = 20                   # Process URLs in smaller batches
    PROGRESS_SAVE_INTERVAL = 10       # Save progress every 10 successful entries
    
    # NEW: Enhanced legitimate URL list
    LEGIT_FALLBACK_URLS = [
        # Technology companies
        "https://google.com", "https://microsoft.com", "https://apple.com", "https://amazon.com",
        "https://meta.com", "https://netflix.com", "https://adobe.com", "https://oracle.com",
        "https://salesforce.com", "https://ibm.com", "https://intel.com", "https://nvidia.com",
        
        # Social media and communication
        "https://twitter.com", "https://linkedin.com", "https://instagram.com", "https://whatsapp.com",
        "https://telegram.org", "https://discord.com", "https://zoom.us", "https://slack.com",
        
        # E-commerce and services
        "https://ebay.com", "https://paypal.com", "https://stripe.com", "https://shopify.com",
        "https://walmart.com", "https://target.com", "https://bestbuy.com", "https://aliexpress.com",
        
        # Media and entertainment
        "https://youtube.com", "https://spotify.com", "https://twitch.tv", "https://reddit.com",
        "https://wikipedia.org", "https://wikimedia.org", "https://archive.org", "https://medium.com",
        
        # Development and tools
        "https://github.com", "https://gitlab.com", "https://stackoverflow.com", "https://npmjs.com",
        "https://pypi.org", "https://docker.com", "https://kubernetes.io", "https://jenkins.io",
        
        # Cloud services
        "https://aws.amazon.com", "https://cloud.google.com", "https://azure.microsoft.com",
        "https://digitalocean.com", "https://heroku.com", "https://cloudflare.com",
        
        # Education and research
        "https://coursera.org", "https://edx.org", "https://khanacademy.org", "https://mit.edu",
        "https://stanford.edu", "https://harvard.edu", "https://arxiv.org", "https://scholar.google.com",
        
        # News and media
        "https://cnn.com", "https://bbc.com", "https://reuters.com", "https://bloomberg.com",
        "https://techcrunch.com", "https://wired.com", "https://theverge.com", "https://ycombinator.com",
        
        # Financial services
        "https://chase.com", "https://wellsfargo.com", "https://bankofamerica.com", "https://citi.com",
        "https://goldmansachs.com", "https://jpmorgan.com", "https://schwab.com", "https://fidelity.com",
        
        # Government and organizations
        "https://usa.gov", "https://gov.uk", "https://europa.eu", "https://un.org",
        "https://who.int", "https://worldbank.org", "https://imf.org", "https://oecd.org",
        
        # Travel and maps
        "https://booking.com", "https://expedia.com", "https://airbnb.com", "https://uber.com",
        "https://maps.google.com", "https://openstreetmap.org", "https://tripadvisor.com",
        
        # Health and fitness
        "https://webmd.com", "https://mayoclinic.org", "https://nih.gov", "https://fitbit.com",
        "https://myfitnesspal.com", "https://strava.com",
        
        # Productivity and office
        "https://office.com", "https://notion.so", "https://trello.com", "https://asana.com",
        "https://monday.com", "https://dropbox.com", "https://box.com", "https://onedrive.live.com",
        
        # Gaming
        "https://steam.com", "https://epicgames.com", "https://ea.com", "https://ubisoft.com",
        "https://blizzard.com", "https://riotgames.com", "https://minecraft.net",
        
        # Security and privacy
        "https://mozilla.org", "https://torproject.org", "https://signal.org", "https://protonmail.com",
        "https://nordvpn.com", "https://1password.com", "https://bitwarden.com",
        
        # Open source and foundations
        "https://apache.org", "https://python.org", "https://nodejs.org", "https://jquery.com",
        "https://react.dev", "https://vuejs.org", "https://angular.io", "https://tensorflow.org",
    ]