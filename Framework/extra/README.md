# PhishGuard Framework

## Overview

PhishGuard is a comprehensive machine learning framework for detecting phishing URLs by leveraging multiple feature sets: WHOIS information, SSL certificate data, and behavioral characteristics. The framework combines these diverse feature sets to create a robust detection system that achieves high accuracy while maintaining resilience against evasion techniques.

## Repository Structure

- `main.py`: Core implementation of the PhishGuard framework
- `final_dataset.csv`: Dataset containing legitimate and phishing URLs with extracted features
- `phishguard_models/`: Directory containing trained models, scalers, and feature lists
- `visualizations/`: Directory containing performance visualizations and diagrams
- `visualize_results.py`: Script for generating visualizations from model results
- `PhishGuard_Paper.md`: Academic paper describing the framework in Markdown format
- `PhishGuard_Paper.tex`: Academic paper in LaTeX format
- `PhishGuard_Presentation.md`: Presentation slides in Markdown format

## Features

The PhishGuard framework extracts and utilizes three categories of features:

### WHOIS Features
- Domain age (registration date)
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
- Number of special characters
- Presence of IP address
- Domain popularity
- Presence of suspicious TLDs
- Presence of suspicious keywords
- Redirect count

## Models

The framework trains and evaluates two machine learning algorithms:

1. **Random Forest**: An ensemble learning method that constructs multiple decision trees during training and outputs the class that is the mode of the classes of the individual trees.
2. **XGBoost**: A gradient boosting framework that uses a more regularized model formalization to control over-fitting.

For each algorithm, models are trained using different feature set combinations:
- WHOIS features only
- SSL features only
- Behavioral features only
- WHOIS + SSL features
- WHOIS + Behavioral features
- SSL + Behavioral features
- Combined (all features)

## Performance

Our experimental results demonstrate that the Random Forest model utilizing all features achieved the highest accuracy (99.52%), followed by the WHOIS + Behavioral combination (97.10%). Among XGBoost models, the WHOIS + Behavioral combination performed best with 98.55% accuracy.

## Visualizations

The `visualizations/` directory contains the following performance visualizations:

- `model_comparison_random_forest.png`: Performance metrics for Random Forest models across different feature sets
- `model_comparison_xgboost.png`: Performance metrics for XGBoost models across different feature sets
- `model_comparison_best_models.png`: Comparison of best-performing models from each algorithm
- `roc_curves.png`: ROC curves for different models
- `precision_recall_curve.png`: Precision-recall curves for handling class imbalance
- `confusion_matrix.png`: Confusion matrix for the best-performing model
- `feature_importance.png`: Feature importance analysis for the best model
- `methodology_diagram.png`: Overall architecture of the PhishGuard framework

## Usage

### Running the Framework

```bash
python main.py
```

This will:
1. Load the dataset from `final_dataset.csv`
2. Extract and process features
3. Train models on different feature set combinations
4. Evaluate model performance
5. Save trained models to the `phishguard_models/` directory
6. Test the framework on example URLs

### Generating Visualizations

```bash
python visualize_results.py
```

This will generate all visualizations and save them to the `visualizations/` directory.

### Predicting on New URLs

To use the trained models for prediction on new URLs, you can use the `predict_url` function in `main.py`:

```python
from main import PhishGuardFramework

framework = PhishGuardFramework()
framework.load_models()
result = framework.predict_url("https://example.com")
print(f"Prediction: {result['prediction']}")
print(f"Confidence: {result['confidence']:.2f}%")
print(f"Model used: {result['model_used']}")
```

## Requirements

- Python 3.7+
- pandas
- numpy
- scikit-learn
- xgboost
- matplotlib
- seaborn
- whois
- python-dateutil
- requests
- cryptography

## Citation

If you use PhishGuard in your research, please cite our paper:

```
@article{phishguard2023,
  title={PhishGuard: A Multi-Feature Machine Learning Framework for Phishing URL Detection},
  author={Author, A.},
  journal={Journal of Cybersecurity},
  year={2023},
  volume={1},
  number={1},
  pages={1-10}
}
```

## License

MIT