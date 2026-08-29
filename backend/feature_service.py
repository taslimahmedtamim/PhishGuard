from feature_extraction import LexicalFeatureExtractor
from host_features import HostFeatureExtractor

class FeatureService:
    def __init__(self):
        self.lexical_extractor = LexicalFeatureExtractor()
        self.host_extractor = HostFeatureExtractor()
        
    def extract(self, url):
        """
        Extract features for the given URL.
        Returns (lexical_features, host_features, available_groups).
        """
        lexical_features = self.lexical_extractor.extract_features(url)
        host_features = self.host_extractor.get_host_features(url)
        
        return lexical_features, host_features, ['lexical', 'host']
