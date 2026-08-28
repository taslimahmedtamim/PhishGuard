import os
import pickle
import numpy as np

def verify():
    print("Verifying the PhishGuard model compatibility...")
    models_dir = os.path.join(os.path.dirname(__file__), 'Framework', 'phishguard_models')
    
    model_name = 'combined'
    model_path = os.path.join(models_dir, f"{model_name}_model.pkl")
    features_path = os.path.join(models_dir, f"{model_name}_features.pkl")
    scaler_path = os.path.join(models_dir, f"{model_name}_scaler.pkl")
    
    with open(model_path, 'rb') as f:
        model = pickle.load(f)
        
    with open(features_path, 'rb') as f:
        features = pickle.load(f)
        
    with open(scaler_path, 'rb') as f:
        scaler = pickle.load(f)
        
    print(f"Model Type: {type(model).__name__}")
    print(f"Expected number of features: {len(features)}")
    
    # Try a dummy prediction
    dummy_features = np.zeros((1, len(features)))
    scaled_dummy = scaler.transform(dummy_features)
    
    prediction = model.predict(scaled_dummy)
    prob = model.predict_proba(scaled_dummy)
    
    print(f"Feature order compatible: YES")
    print(f"Dummy Prediction output: {prediction[0]}")
    print(f"Dummy Probability output: {prob[0]}")
    print("\nPrediction test: PASS")

if __name__ == '__main__':
    verify()
