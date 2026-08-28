# PhishGuard: A Multi-Feature Machine Learning Framework for Phishing URL Detection

---

## Agenda

1. Introduction & Problem Statement
2. Related Work
3. Methodology
4. Results & Evaluation
5. Discussion
6. Conclusion & Future Work

---

## Introduction

### Problem Statement

- Phishing attacks remain one of the most prevalent cybersecurity threats
- Phishing attempts increased by 220% during COVID-19 pandemic
- Traditional detection methods have limitations:
  - Blacklists cannot detect new phishing sites
  - Heuristic methods struggle with evolving techniques
  - Single-feature ML approaches are vulnerable to evasion

---

## Our Solution: PhishGuard Framework

- Multi-feature machine learning approach combining:
  - WHOIS information
  - SSL certificate data
  - Behavioral characteristics

- Key advantages:
  - Comprehensive detection system
  - Ensemble learning techniques
  - Graceful degradation when features are unavailable
  - Explainable predictions

---

## Related Work

### Existing Approaches

- **Blacklist-based:** Google Safe Browsing, PhishTank
  - Limited to known threats

- **Heuristic-based:** Rule systems for URL/content analysis
  - High false positive rates

- **Machine learning-based:**
  - Sahingoz et al. (2019): NLP + URL features (97.98% accuracy)
  - Jain and Gupta (2018): HTML/JS features (98.4% accuracy)
  - Marchal et al. (2017): URL lexical features (97.7% accuracy)

---

## Methodology

![Methodology Diagram](visualizations/methodology_diagram.png)

---

## Dataset

- 1,031 URLs (legitimate and phishing)
- Sources:
  - Legitimate: Alexa top-ranked websites
  - Phishing: PhishTank and OpenPhish repositories
- Diverse categories: banking, e-commerce, social media, cloud services

---

## Feature Extraction

### WHOIS Features
- Domain age
- Expiration date
- Last update date
- Registrar information
- Country of registration
- Privacy protection status

### SSL Certificate Features
- Certificate validity period
- Issuer information
- Certificate algorithm
- Self-signed status
- Certificate age

### Behavioral Features
- URL length
- Number of subdomains
- Special characters
- IP address presence
- Domain popularity
- Suspicious TLDs
- Suspicious keywords
- Redirect count

---

## Feature Processing

1. **Handling categorical variables**
   - One-hot encoding for registrar, country, SSL issuer, algorithm

2. **Date processing**
   - Convert to numeric values (days from reference date)

3. **Missing value imputation**
   - Fill with appropriate defaults

4. **Feature scaling**
   - StandardScaler for numerical features

---

## Model Training

### Algorithms
- Random Forest
- XGBoost

### Feature Set Combinations
- WHOIS only
- SSL only
- Behavioral only
- WHOIS + SSL
- WHOIS + Behavioral
- SSL + Behavioral
- Combined (all features)

### Validation
- Stratified 5-fold cross-validation
- Class weights for imbalance handling

---

## Results: Random Forest Models

![Random Forest Model Comparison](visualizations/model_comparison_random_forest.png)

---

## Results: XGBoost Models

![XGBoost Model Comparison](visualizations/model_comparison_xgboost.png)

---

## Results: Best Models Comparison

![Best Models Comparison](visualizations/model_comparison_best_models.png)

---

## ROC Curve Analysis

![ROC Curves](visualizations/roc_curves.png)

---

## Precision-Recall Analysis

![Precision-Recall Curve](visualizations/precision_recall_curve.png)

---

## Confusion Matrix

![Confusion Matrix](visualizations/confusion_matrix.png)

---

## Feature Importance

![Feature Importance](visualizations/feature_importance.png)

---

## Key Findings

- Combined features model (Random Forest): **99.52% accuracy**
- WHOIS + Behavioral (XGBoost): **98.55% accuracy**
- Behavioral features alone: **97.10% (RF) / 98.07% (XGB)**
- Domain age, URL length, and SSL validity period are most important features
- Multi-feature approach provides resilience when certain features are unavailable

---

## Conclusion

- PhishGuard combines WHOIS, SSL, and behavioral features for robust phishing detection
- Best model achieves 99.52% accuracy
- Modular design allows graceful degradation
- Feature importance analysis provides insights into phishing characteristics
- Future work will focus on content analysis, adversarial resilience, and real-time performance

---

## Thank You!

### Questions?