import os
import joblib
import numpy as np

class ModelService:
    def __init__(self):
        models_dir = r'd:\phishguard\Trae\models'
        
        self.model_name = 'vondataset_models'
        
        # Load the model, scaler, and features list
        xgb_model_path = os.path.join(models_dir, "xgboost.pkl")
        rf_model_path = os.path.join(models_dir, "random_forest.pkl")
        scaler_path = os.path.join(models_dir, "scaler.pkl")
        features_path = os.path.join(models_dir, "feature_names.pkl")
        
        if not os.path.exists(xgb_model_path) or not os.path.exists(rf_model_path):
            raise Exception(f"Model files not found in {models_dir}")
            
        self.xgb_model = joblib.load(xgb_model_path)
        self.rf_model = joblib.load(rf_model_path)
        self.scaler = joblib.load(scaler_path)
        self.feature_columns = joblib.load(features_path)
            
        self.is_loaded = True

    def process_features(self, features):
        """Build vector based strictly on expected order"""
        feature_vector = []
        for feature in self.feature_columns:
            val = features.get(feature, 0) # default to 0 if missing
            feature_vector.append(val)
            
        return np.array(feature_vector).reshape(1, -1)

    def predict(self, features):
        """Scale features and return prediction and confidence."""
        try:
            vector = self.process_features(features)
            scaled_features = self.scaler.transform(vector)
            
            xgb_prediction = self.xgb_model.predict(scaled_features)[0]
            xgb_probability = self.xgb_model.predict_proba(scaled_features)[0]
            xgb_is_phishing = bool(xgb_prediction == 1)
            xgb_confidence = float(max(xgb_probability))
            
            rf_prediction = self.rf_model.predict(scaled_features)[0]
            rf_probability = self.rf_model.predict_proba(scaled_features)[0]
            rf_is_phishing = bool(rf_prediction == 1)
            rf_confidence = float(max(rf_probability))
            
            return {
                "prediction": "phishing" if rf_is_phishing else "legitimate",
                "is_phishing": rf_is_phishing,
                "xgb_is_phishing": xgb_is_phishing,
                "xgb_confidence": xgb_confidence,
                "rf_is_phishing": rf_is_phishing,
                "rf_confidence": rf_confidence,
                "model_used": self.model_name
            }
        except Exception as e:
            return {
                "error": str(e)
            }
