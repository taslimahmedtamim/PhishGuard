import os
import dill
import time
import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier
import sys

# Add backend directory to path to import feature_extraction
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'backend'))
from feature_extraction import LexicalFeatureExtractor

def decode_url(arr, int_to_char):
    return ''.join([int_to_char.get(i, '') for i in arr if i != 0])

def process_split(x_data, y_data, int_to_char, extractor, split_name):
    print(f"Processing {split_name} split ({len(x_data)} samples)...")
    
    start_time = time.time()
    features_list = []
    
    # Process in batches to print progress
    batch_size = 100000
    for i in range(0, len(x_data), batch_size):
        end = min(i + batch_size, len(x_data))
        batch = x_data[i:end]
        
        batch_features = []
        for row in batch:
            url = decode_url(row, int_to_char)
            batch_features.append(extractor.get_feature_array(url))
            
        features_list.extend(batch_features)
        print(f"  Processed {end}/{len(x_data)} samples...")
        
    print(f"Finished {split_name} processing in {time.time() - start_time:.2f} seconds.")
    return np.array(features_list), np.array(y_data)

def main():
    print("Loading dataset...")
    with open(r'd:\phishguard\Trae\Datasets\vonDataset20180426.dill', 'rb') as f:
        obj = dill.load(f)

    char_to_int = obj['char_to_int']
    int_to_char = {v: k for k, v in char_to_int.items()}
    int_to_char[0] = '' # padding

    extractor = LexicalFeatureExtractor()

    # Process training and validation data (we will train on both combined for better performance, or just train)
    # The paper uses 80/20. The dill has train/val/test. Let's use train for training, val for early stopping or just train on train+val.
    # Let's just use train_x.
    X_train, y_train = process_split(obj['train_x'], obj['train_y'], int_to_char, extractor, "Train")
    
    # We will use test_x for final evaluation in evaluate_model.py. 
    # But wait, we need to save the test features so we don't have to extract them again.
    X_test, y_test = process_split(obj['test_x'], obj['test_y'], int_to_char, extractor, "Test")

    # Scaling
    print("Scaling features...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Make models dir
    os.makedirs(r'd:\phishguard\Trae\models', exist_ok=True)
    
    # Save test sets for evaluation script
    joblib.dump((X_test_scaled, y_test), r'd:\phishguard\Trae\models\test_data.pkl')

    # Train Random Forest
    print("Training Random Forest...")
    rf_start = time.time()
    rf = RandomForestClassifier(n_estimators=100, max_depth=25, n_jobs=-1, random_state=42)
    rf.fit(X_train_scaled, y_train)
    print(f"Random Forest trained in {time.time() - rf_start:.2f} seconds.")
    joblib.dump(rf, r'd:\phishguard\Trae\models\random_forest.pkl')

    # Train XGBoost
    print("Training XGBoost...")
    xgb_start = time.time()
    xgb = XGBClassifier(n_estimators=100, max_depth=10, n_jobs=-1, random_state=42, use_label_encoder=False, eval_metric='logloss')
    xgb.fit(X_train_scaled, y_train)
    print(f"XGBoost trained in {time.time() - xgb_start:.2f} seconds.")
    joblib.dump(xgb, r'd:\phishguard\Trae\models\xgboost.pkl')

    # Save Scaler and features config
    joblib.dump(scaler, r'd:\phishguard\Trae\models\scaler.pkl')
    joblib.dump(extractor.feature_names, r'd:\phishguard\Trae\models\feature_names.pkl')
    
    print("Training complete! Models saved to d:\\phishguard\\Trae\\models\\")

if __name__ == '__main__':
    main()
