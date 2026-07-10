"""
ML Model Loader for Phishing Detection Backend
Loads the trained model (.pkl) exported from Colab Notebook 1.

Usage:
    Place model_training_ml.pkl and feature_config.json in backend/models/
    Then this module auto-loads and provides predict_phishing_probability()
"""

import os
import re
import json
import numpy as np
from urllib.parse import urlparse

try:
    import joblib
    HAS_JOBLIB = True
except ImportError:
    HAS_JOBLIB = False
    print("Warning: joblib not installed. ML model will not load. Run: pip install joblib")

# --- Model Loading ---
MODEL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'models')
MODEL_PATH = os.path.join(MODEL_DIR, 'model_training_ml.pkl')
CONFIG_PATH = os.path.join(MODEL_DIR, 'model_feature_config.json')

_model = None
_scaler = None
_feature_columns = None
_model_loaded = False


def _load_model():
    """Load the ML model and scaler from disk."""
    global _model, _scaler, _feature_columns, _model_loaded
    
    if not HAS_JOBLIB:
        print("[ML] joblib not available — ML scoring disabled")
        return False
    
    if not os.path.exists(MODEL_PATH):
        print(f"[ML] Model file not found: {MODEL_PATH}")
        print(f"[ML] Run Notebook 1 in Colab and place model_training_ml.pkl in backend/models/")
        return False
    
    try:
        model_data = joblib.load(MODEL_PATH)
        _model = model_data['model']
        _scaler = model_data.get('scaler')
        _feature_columns = model_data.get('feature_columns', [])
        _model_loaded = True
        
        model_name = model_data.get('model_name', 'unknown')
        test_f1 = model_data.get('test_f1', 'N/A')
        print(f"[ML] Model loaded: {model_name} (F1={test_f1})")
        print(f"[ML] Features: {len(_feature_columns)} columns")
        return True
    except Exception as e:
        print(f"[ML] Error loading model: {e}")
        return False


def extract_url_features(url):
    """
    Extract numerical features from a URL string.
    Returns a dict of feature_name -> value.
    """
    features = {}
    
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        path = parsed.path or ""
        query = parsed.query or ""
        full_url = url
    except:
        return features
    
    # Basic URL length features
    features['url_length'] = len(full_url)
    features['length_url'] = len(full_url)
    features['length_hostname'] = len(hostname)
    
    # Character counts
    features['n_dots'] = full_url.count('.')
    features['nb_dots'] = full_url.count('.')
    features['n_hyphens'] = full_url.count('-')
    features['nb_hyphens'] = full_url.count('-')
    features['n_underline'] = full_url.count('_')
    features['n_slash'] = full_url.count('/')
    features['nb_slash'] = full_url.count('/')
    features['n_questionmark'] = full_url.count('?')
    features['nb_qm'] = full_url.count('?')
    features['n_equal'] = full_url.count('=')
    features['nb_eq'] = full_url.count('=')
    features['n_at'] = full_url.count('@')
    features['nb_at'] = full_url.count('@')
    features['n_and'] = full_url.count('&')
    features['nb_and'] = full_url.count('&')
    features['n_exclamation'] = full_url.count('!')
    features['n_space'] = full_url.count(' ')
    features['nb_space'] = full_url.count(' ')
    features['n_tilde'] = full_url.count('~')
    features['n_comma'] = full_url.count(',')
    features['n_plus'] = full_url.count('+')
    features['n_star'] = full_url.count('*')
    features['n_dollar'] = full_url.count('$')
    features['n_percent'] = full_url.count('%')
    features['nb_percent'] = full_url.count('%')
    
    # Digit ratio
    digit_count = sum(c.isdigit() for c in full_url)
    features['ratio_digits_url'] = digit_count / max(len(full_url), 1)
    features['ratio_digits_host'] = sum(c.isdigit() for c in hostname) / max(len(hostname), 1)
    
    # Protocol
    features['https_token'] = 1 if parsed.scheme == 'https' else 0
    
    # IP check
    features['ip'] = 1 if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname) else 0
    features['ip_in_url'] = features['ip']
    
    # Subdomains
    features['nb_subdomains'] = hostname.count('.') - 1 if hostname.count('.') > 0 else 0
    
    # Redirections
    features['n_redirection'] = full_url.count('//')  - 1  # minus the protocol
    features['nb_redirection'] = max(0, features['n_redirection'])
    
    # Shortening service check
    shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly']
    features['shortening_service'] = 1 if any(s in hostname for s in shorteners) else 0
    
    # Path extension
    features['path_extension'] = 1 if re.search(r'\.\w{2,4}$', path) else 0
    
    # Prefix-suffix (dash in domain)
    features['prefix_suffix'] = 1 if '-' in hostname else 0
    
    # TLD in subdomain
    tlds = ['.com', '.net', '.org', '.edu', '.gov', '.co']
    subdomain = '.'.join(hostname.split('.')[:-2]) if hostname.count('.') >= 2 else ''
    features['tld_in_subdomain'] = 1 if any(tld.replace('.','') in subdomain for tld in tlds) else 0
    
    # Number of www
    features['nb_www'] = full_url.lower().count('www')
    
    return features


def predict_phishing_probability(url):
    """
    Predict the phishing probability for a URL using the trained ML model.
    Returns a float between 0.0 (safe) and 1.0 (phishing).
    """
    global _model_loaded
    
    # Lazy load model on first call
    if not _model_loaded:
        _load_model()
    
    if _model is None:
        return 0.0  # No model available, return 0 (no ML contribution)
    
    try:
        # Extract features
        url_features = extract_url_features(url)
        
        # Build feature vector in the order the model expects
        feature_vector = []
        for col in _feature_columns:
            feature_vector.append(float(url_features.get(col, 0.0)))
        
        X = np.array(feature_vector).reshape(1, -1)
        
        # Scale if scaler exists
        if _scaler is not None:
            X = _scaler.transform(X)
        
        # Predict probability
        prob = _model.predict_proba(X)[0][1]
        return float(prob)
        
    except Exception as e:
        print(f"[ML] Prediction error: {e}")
        return 0.0


def is_model_loaded():
    """Check if the ML model is loaded and ready."""
    global _model_loaded
    if not _model_loaded:
        _load_model()
    return _model_loaded
