import os
import joblib
import json
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix

def evaluate(model, X_test, y_test, model_name):
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    auc = roc_auc_score(y_test, y_proba)

    cm = confusion_matrix(y_test, y_pred)
    
    return {
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
        "f1": f1,
        "auc": auc
    }, cm

def plot_confusion_matrix(cm, model_name, path):
    plt.figure(figsize=(6, 5))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=['Legitimate', 'Phishing'], yticklabels=['Legitimate', 'Phishing'])
    plt.title(f'Confusion Matrix - {model_name}')
    plt.ylabel('True Label')
    plt.xlabel('Predicted Label')
    plt.tight_layout()
    plt.savefig(path)
    plt.close()

def plot_feature_importance(model, feature_names, model_name, path):
    importances = model.feature_importances_
    indices = importances.argsort()[::-1]
    sorted_features = [feature_names[i] for i in indices]
    sorted_importances = importances[indices]

    plt.figure(figsize=(10, 6))
    sns.barplot(x=sorted_importances, y=sorted_features, palette='viridis')
    plt.title(f'Feature Importances - {model_name}')
    plt.xlabel('Importance')
    plt.ylabel('Feature')
    plt.tight_layout()
    plt.savefig(path)
    plt.close()

def main():
    print("Loading test data...")
    X_test, y_test = joblib.load(r'd:\phishguard\Trae\models\test_data.pkl')
    feature_names = joblib.load(r'd:\phishguard\Trae\models\feature_names.pkl')
    
    rf = joblib.load(r'd:\phishguard\Trae\models\random_forest.pkl')
    xgb = joblib.load(r'd:\phishguard\Trae\models\xgboost.pkl')

    os.makedirs(r'd:\phishguard\Trae\results', exist_ok=True)

    print("Evaluating Random Forest...")
    rf_metrics, rf_cm = evaluate(rf, X_test, y_test, "Random Forest")
    plot_confusion_matrix(rf_cm, "Random Forest", r'd:\phishguard\Trae\results\rf_confusion_matrix.png')
    plot_feature_importance(rf, feature_names, "Random Forest", r'd:\phishguard\Trae\results\rf_feature_importance.png')

    print("Evaluating XGBoost...")
    xgb_metrics, xgb_cm = evaluate(xgb, X_test, y_test, "XGBoost")
    plot_confusion_matrix(xgb_cm, "XGBoost", r'd:\phishguard\Trae\results\xgb_confusion_matrix.png')
    plot_feature_importance(xgb, feature_names, "XGBoost", r'd:\phishguard\Trae\results\xgb_feature_importance.png')

    results = {
        "Random Forest": rf_metrics,
        "XGBoost": xgb_metrics
    }
    
    with open(r'd:\phishguard\Trae\results\metrics.json', 'w') as f:
        json.dump(results, f, indent=4)

    print("\n" + "="*45)
    print(f"{'Metric':<15} | {'Random Forest':<12} | {'XGBoost':<12}")
    print("-" * 45)
    for metric in ['accuracy', 'precision', 'recall', 'f1', 'auc']:
        print(f"{metric.capitalize():<15} | {rf_metrics[metric]:<12.4f} | {xgb_metrics[metric]:<12.4f}")
    print("="*45 + "\n")
    print("Evaluation complete. Results saved to d:\\phishguard\\Trae\\results\\")

if __name__ == '__main__':
    main()
