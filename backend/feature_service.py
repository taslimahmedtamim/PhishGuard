from feature_extraction import LexicalFeatureExtractor

class FeatureService:
    def __init__(self):
        self.extractor = LexicalFeatureExtractor()
        
    def extract(self, url):
        """
        Extract features for the given URL using the new LexicalFeatureExtractor.
        """
        features = self.extractor.extract_features(url)
        # We only have lexical features now, so we just return them and 'lexical' as available group
        return features, ['lexical']
