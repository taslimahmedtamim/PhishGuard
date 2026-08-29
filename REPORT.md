# PhishGuard Audit & Discrepancy Report

This report outlines key findings and discrepancies discovered during the audit of the PhishGuard system.

## 1. Primary Model Implementation
The original research paper and project documentation frequently reference a **Random Forest** model with extremely high accuracy (99.13%).
However, upon auditing `Framework/main.py`, the code trains both a Random Forest and an XGBoost model, but explicitly selects and saves the **XGBoost** model to the `.pkl` files (e.g., `combined_model.pkl`):
```python
# main.py lines 612-613
# Use XGBoost as the primary model
model = xgb_model
```
Because this local backend relies on the output of the training script (`_model.pkl`, `_scaler.pkl`, `_features.pkl`), the API utilizes the **XGBoost** model by default. This ensures complete compatibility with the saved feature scalers and feature orders.

## 2. Dataset Size
The research paper claims experiments on approximately **1.5M URLs**. 
The local dataset provided in `Datasets/dataset.csv` contains approximately **860 URLs** (678 phishing, 182 legitimate). 
This explains why real-world performance or exact replications of the paper's ROC curves might differ when training locally with this limited dataset. 

## 3. Real-Time Feature Extraction Constraints
Some features described in the research paper rely on exhaustive WHOIS or SSL analysis which can take significant time or may fail due to rate-limiting in a real-world real-time setting. 
To ensure the backend doesn't hang indefinitely, the system extracts **WHOIS and SSL information solely as supplementary security context for the user interface**. These features are **not** fed into the Machine Learning model. The ML model relies exclusively on 15 instantaneous Lexical features to guarantee sub-second prediction latency.
