import re
import math
from urllib.parse import urlparse

class LexicalFeatureExtractor:
    def __init__(self):
        self.feature_names = [
            'url_length',
            'hostname_length',
            'path_length',
            'query_length',
            'fragment_length',
            'num_dots',
            'num_hyphens',
            'num_slashes',
            'num_at_symbols',
            'num_digits',
            'num_special_chars',
            'num_subdomains',
            'entropy',
            'contains_ip',
            'contains_https'
        ]
        self.ip_pattern = re.compile(
            r'(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])'
        )

    def extract_features(self, url):
        """
        Extracts 15 lexical features from a given URL.
        Returns a dictionary of features.
        """
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        try:
            parsed = urlparse(url)
            hostname = parsed.hostname or ''
        except:
            parsed = None
            hostname = ''

        features = {}
        
        # Length features
        features['url_length'] = len(url)
        features['hostname_length'] = len(hostname)
        features['path_length'] = len(parsed.path) if parsed else 0
        features['query_length'] = len(parsed.query) if parsed else 0
        features['fragment_length'] = len(parsed.fragment) if parsed else 0

        # Character counts
        features['num_dots'] = url.count('.')
        features['num_hyphens'] = url.count('-')
        features['num_slashes'] = url.count('/')
        features['num_at_symbols'] = url.count('@')
        features['num_digits'] = sum(c.isdigit() for c in url)
        
        special_chars = set(['!', '#', '$', '%', '&', '*', '+', ',', ';', '=', '?', '_', '~'])
        features['num_special_chars'] = sum(1 for c in url if c in special_chars)

        # Domain specific
        features['num_subdomains'] = max(0, hostname.count('.') - 1) if not self.ip_pattern.search(hostname) else 0
        features['contains_ip'] = 1 if self.ip_pattern.search(hostname) else 0
        features['contains_https'] = 1 if url.startswith('https://') else 0

        # Entropy
        features['entropy'] = self._calculate_entropy(url)

        return features

    def get_feature_array(self, url):
        """
        Returns the features as a list in the exact order of feature_names.
        """
        feats = self.extract_features(url)
        return [feats[name] for name in self.feature_names]

    def _calculate_entropy(self, text):
        if not text:
            return 0
        entropy = 0
        for x in set(text):
            p_x = float(text.count(x)) / len(text)
            entropy -= p_x * math.log(p_x, 2)
        return entropy

if __name__ == '__main__':
    extractor = LexicalFeatureExtractor()
    test_urls = [
        "https://github.com/taslimahmedtamim/phishguard",
        "http://192.168.1.1/login.php?user=admin&pass=123"
    ]
    for url in test_urls:
        print(f"Features for {url}:")
        print(extractor.extract_features(url))
        print()
