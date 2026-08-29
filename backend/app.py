from flask import Flask, request, jsonify
from flask_cors import CORS
import logging
from feature_service import FeatureService
from model_service import ModelService
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app) # Enable CORS for Chrome Extension

try:
    feature_service = FeatureService()
    model_service = ModelService()
    logger.info("Successfully loaded FeatureService and ModelService.")
except Exception as e:
    logger.error(f"Failed to initialize services: {e}")
    feature_service = None
    model_service = None

def is_valid_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        "status": "ok",
        "model_loaded": model_service.is_loaded if model_service else False,
        "services_initialized": feature_service is not None and model_service is not None
    }), 200

@app.route('/predict', methods=['POST'])
def predict():
    if not feature_service or not model_service:
        return jsonify({"error": "Backend services not fully initialized"}), 500
        
    data = request.json
    if not data or 'url' not in data:
        return jsonify({"error": "No URL provided"}), 400
        
    url = data['url'].strip()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
        
    if not is_valid_url(url):
        return jsonify({"error": "Invalid URL format"}), 400
        
    logger.info(f"Analyzing URL: {url}")
    
    try:
        # Extract features
        lexical_features, host_features, available_groups = feature_service.extract(url)
        
        if not available_groups:
            logger.warning(f"Could not extract features for URL: {url}")
            return jsonify({
                "url": url,
                "prediction": "legitimate",
                "is_phishing": False,
                "risk_score": 0.50,
                "risk_level": "UNKNOWN",
                "message": "Analysis incomplete or failed; defaulting to safe",
                "error": "Feature extraction failed"
            }), 200
            
        # Predict using ONLY the lexical features as expected by the model
        result = model_service.predict(lexical_features)
        
        if "error" in result:
            logger.error(f"Prediction error for {url}: {result['error']}")
            return jsonify({"error": "Prediction failed", "details": result['error']}), 500
            
        # Determine risk level and message (Primarily relying on Random Forest)
        is_phishing = result.get("rf_is_phishing", False)
        risk_score = result.get("rf_confidence", 0.0)
        
        if is_phishing:
            risk_level = "HIGH"
            message = "Potential phishing website detected"
        else:
            if risk_score > 0.8: # If not phishing but high confidence of safe
                risk_level = "LOW"
                message = "Website appears safe based on analysis"
            else:
                risk_level = "MEDIUM"
                message = "Website has some suspicious characteristics"
                
        # Merge all features for the UI
        all_features = {**lexical_features, **host_features}
            
        response = {
            "url": url,
            "prediction": "phishing" if is_phishing else "legitimate",
            "is_phishing": is_phishing,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "message": message,
            "features": all_features,
            "available_groups": available_groups
        }
        
        logger.info(f"Result for {url}: {risk_level} Risk ({risk_score:.2f})")
        return jsonify(response), 200
        
    except Exception as e:
        import traceback
        error_trace = traceback.format_exc()
        logger.exception(f"Unexpected error analyzing {url}")
        return jsonify({"error": f"Internal server error: {str(e)}", "trace": error_trace}), 500

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000)
