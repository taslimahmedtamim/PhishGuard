# PhishGuard Crawler

A comprehensive web crawler for collecting phishing and legitimate website data with WHOIS, SSL, and behavioral features.

## Features

- **Multi-layered feature extraction:**
  - WHOIS features (domain age, registrar, privacy protection, etc.)
  - SSL certificate features (issuer, validity, key length, etc.)
  - Behavioral features (URL structure, page content, redirects, etc.)

- **Robust data collection:**
  - Automatic retry mechanisms
  - Rate limiting to avoid being blocked
  - Error logging and recovery
  - Checkpoint saving for crash recovery

- **Balanced dataset creation:**
  - Automatically collects equal numbers of phishing and legitimate sites
  - Continues until target counts are reached
  - Skips sites with missing features

## Installation

1. **Clone or download the project:**
```bash
mkdir phishguard_crawler
cd phishguard_crawler
# Copy all files to this directory 