import os
import sys
import pandas as pd
import numpy as np
from tqdm import tqdm
import time

# Ensure backend directory is in path for imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import app
from ml_model import predict_phishing_probability
from scoring import get_weights, get_threshold, calculate_final_score

# Mock network calls to prevent 11,000+ API requests from taking 6 hours or hitting rate limits
app.check_domain_age = lambda hostname: -1
app.check_ssl_certificate = lambda hostname: (True, "Valid SSL Certificate")
app.check_threat_intelligence = lambda url, hostname: (False, "")

def evaluate_fast_path(dataset_path):
    print(f"Loading dataset from {dataset_path}...")
    try:
        df = pd.read_csv(dataset_path)
    except FileNotFoundError:
        print(f"Error: Dataset {dataset_path} not found.")
        sys.exit(1)
        
    # Clean URLs
    df['url'] = df['url'].apply(lambda x: str(x).strip())
    
    if 'status' in df.columns:
        df['label'] = df['status'].apply(lambda x: 1 if str(x).lower() == 'phishing' else 0)
    
    y_true = df['label'].tolist()
    
    weights = get_weights()
    rules_weight = weights.get('rules_weight', 1.0)
    threshold = get_threshold()
    
    layer1_preds = []
    layer2_preds = []
    layer3_preds = []
    layer4_preds = []
    fast_path_preds = []
    
    print(f"Evaluating Fast Path on {len(df)} URLs...")
    for index, row in tqdm(df.iterrows(), total=len(df)):
        url = row['url']
        
        # 1. Rules Breakdown (Layer 1, 2, 3)
        _, _, rules_breakdown = app.calculate_rules_score(url)
        
        heuristic_score = sum(item.get('score_added', 0) for item in rules_breakdown if item.get('layer') == 'Heuristic') * rules_weight
        reputation_score = sum(item.get('score_added', 0) for item in rules_breakdown if item.get('layer') == 'Reputation') * rules_weight
        domain_score = sum(item.get('score_added', 0) for item in rules_breakdown if item.get('layer') == 'Domain / SSL') * rules_weight
        
        layer1_preds.append(1 if heuristic_score >= threshold else 0)
        layer2_preds.append(1 if reputation_score > 0 else 0) 
        layer3_preds.append(1 if domain_score >= threshold else 0)
        
        # 2. ML Prediction (Layer 4)
        ml_prob = predict_phishing_probability(url)
        layer4_preds.append(1 if ml_prob >= 0.5 else 0)
        
        # 3. Fast Path Final Score
        fast_final = calculate_final_score(rules_breakdown, ml_prob, llm_result=None)
        fast_decision = fast_final['final_decision']
        fast_path_preds.append(1 if fast_decision in ['unsafe', 'critical'] else 0)
        
    setups = [
        ('Layer 1 (Heuristic)', layer1_preds),
        ('Layer 2 (Reputation)', layer2_preds),
        ('Layer 3 (Domain/SSL)', layer3_preds),
        ('Layer 4 (ML)', layer4_preds),
        ('Fast Path Score', fast_path_preds)
    ]
    
    results = []
    
    for setup_name, y_pred in setups:
        tp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 1)
        fp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 1)
        tn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 0)
        fn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 0)
        
        acc = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * (prec * rec) / (prec + rec) if (prec + rec) > 0 else 0
        
        results.append({
            'Setup': setup_name,
            'Accuracy': f"{acc:.4f}",
            'Precision': f"{prec:.4f}",
            'Recall': f"{rec:.4f}",
            'F1-score': f"{f1:.4f}",
            'TP': tp,
            'FP': fp,
            'TN': tn,
            'FN': fn
        })
        
    results_df = pd.DataFrame(results)
    
    print("\n================ FINAL RESULTS ================")
    print(results_df.to_string(index=False))
    print("===============================================")
    
    output_dir = os.path.join(os.path.dirname(__file__), '..', 'models', 'evaluation result')
    os.makedirs(output_dir, exist_ok=True)
    csv_path = os.path.join(output_dir, 'fast_path_full_evaluation.csv')
    results_df.to_csv(csv_path, index=False)
    print(f"Results saved to {csv_path}")

if __name__ == '__main__':
    dataset_path = os.path.join(os.path.dirname(__file__), '..', '..', 'colab_notebooks', 'phishing_dataset', 'dataset_phishing.csv')
    evaluate_fast_path(dataset_path)
