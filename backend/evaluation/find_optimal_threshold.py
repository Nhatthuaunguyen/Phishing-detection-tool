import os
import sys
import pandas as pd
import numpy as np
from sklearn.metrics import roc_curve, precision_recall_curve, f1_score
from tqdm import tqdm
from urllib.parse import urlparse

# Ensure backend directory is in path for imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import app
import ml_model
import scoring

# Mock network calls to speed up evaluation
app.check_domain_age = lambda hostname: -1
app.check_ssl_certificate = lambda hostname: (True, "Valid SSL Certificate")
app.check_threat_intelligence = lambda url, hostname: (False, "")

def evaluate_thresholds(dataset_path, num_samples=1000):
    print(f"Loading dataset from {dataset_path}...")
    df = pd.read_csv(dataset_path)
    
    # Clean URLs
    df['url'] = df['url'].apply(lambda x: str(x).strip())
    
    if 'status' in df.columns:
        df['label'] = df['status'].apply(lambda x: 1 if str(x).lower() == 'phishing' else 0)
    
    # Sample dataset to speed up
    df = df.sample(n=min(num_samples, len(df)), random_state=42)
    
    y_true = df['label'].tolist()
    
    weights = scoring.get_weights()
    rules_weight = weights.get('rules_weight', 1.0)
    ml_weight = weights.get('ml_weight', 0.3)
    
    fast_scores = []
    
    print("Calculating fast path scores...")
    for index, row in tqdm(df.iterrows(), total=len(df)):
        url = row['url']
        
        # 1. Rules Breakdown (Layer 1, 2, 3)
        # Network calls are mocked
        _, _, rules_breakdown = app.calculate_rules_score(url)
        
        # 2. ML Prediction (Layer 4)
        ml_prob = ml_model.predict_phishing_probability(url)
        
        # 3. Fast Path
        fast_final = scoring.calculate_final_score(rules_breakdown, ml_prob, llm_result=None)
        fast_score = fast_final['score_breakdown']['heuristic_score'] + \
                     fast_final['score_breakdown']['reputation_score'] + \
                     fast_final['score_breakdown']['domain_score'] + \
                     fast_final['score_breakdown']['ml_score']
                     
        fast_scores.append(fast_score)
        
    y_scores = np.array(fast_scores)
    y_true = np.array(y_true)
    
    print(f"\n--- Results on {len(df)} samples ---")
    print("\n--- Threshold Analysis (0 to 100) ---")
    print(f"{'Threshold':<10} | {'Precision':<10} | {'Recall':<10} | {'F1-Score':<10}")
    print("-" * 50)
    
    best_t = 0
    best_p = 0
    best_r = 0
    best_f1 = 0
    
    for t in range(0, 101):
        y_pred = (y_scores >= t).astype(int)
        
        tp = np.sum((y_pred == 1) & (y_true == 1))
        fp = np.sum((y_pred == 1) & (y_true == 0))
        fn = np.sum((y_pred == 0) & (y_true == 1))
        
        p = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        r = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * p * r / (p + r) if (p + r) > 0 else 0.0
        
        print(f"{t:<10.2f} | {p:<10.4f} | {r:<10.4f} | {f1:<10.4f}")
        
        if f1 > best_f1:
            best_f1 = f1
            best_t = t
            best_p = p
            best_r = r
            
    print("-" * 50)
    print(f"Optimal Integer Threshold (Max F1): {best_t:.2f}")
    print(f"Max F1 Score: {best_f1:.4f}")
    print(f"Precision at optimal: {best_p:.4f}")
    print(f"Recall at optimal: {best_r:.4f}")
    
    # Analyze distribution for gray zone
    safe_scores = y_scores[y_true == 0]
    phishing_scores = y_scores[y_true == 1]
    
    print("\nScore Distribution:")
    print(f"Safe URLs - Mean: {np.mean(safe_scores):.2f}, 90th percentile: {np.percentile(safe_scores, 90):.2f}")
    print(f"Phishing URLs - Mean: {np.mean(phishing_scores):.2f}, 10th percentile: {np.percentile(phishing_scores, 10):.2f}")
    
    # Propose Gray Zone
    lower_bound = np.percentile(safe_scores, 90)
    upper_bound = np.percentile(phishing_scores, 10)
    
    print(f"\nProposed Thresholds for LLM Routing (Gray Zone):")
    print(f"- Fast Accept (Safe) < {lower_bound:.2f}")
    print(f"- LLM Trigger Zone: {lower_bound:.2f} to {upper_bound:.2f}")
    print(f"- Fast Reject (Phishing) >= {upper_bound:.2f}")
    
    # If lower_bound > upper_bound, flip them or adjust
    if lower_bound > upper_bound:
        print("Note: The distributions overlap significantly. Using percentiles for LLM zone.")
        print(f"Suggested LLM Trigger Zone: {min(lower_bound, upper_bound):.2f} to {max(lower_bound, upper_bound):.2f}")

if __name__ == '__main__':
    dataset_path = os.path.join(os.path.dirname(__file__), '..', '..', 'colab_notebooks', 'phishing_dataset', 'dataset_phishing.csv')
    evaluate_thresholds(dataset_path, num_samples=2000)
