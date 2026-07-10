import os
import sys
import pandas as pd
import numpy as np
from tqdm import tqdm
import time

# Đảm bảo import được các module từ backend
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import app
from ml_model import predict_phishing_probability
from llm_analyzer import analyze_url_with_llm, is_llm_available
from scoring import get_weights, get_threshold, calculate_final_score

# MOCK network calls (Tắt WHOIS và SSL check thực tế) 
# Điều này rất quan trọng để tránh script chạy mất 20 tiếng do phải chờ phản hồi từ mạng
app.check_domain_age = lambda hostname: -1
app.check_ssl_certificate = lambda hostname: (True, "Valid SSL Certificate")
app.check_threat_intelligence = lambda url, hostname: (False, "")

def evaluate_full_deep_path(dataset_path, output_dir):
    print(f"Loading dataset from {dataset_path}...")
    try:
        df = pd.read_csv(dataset_path)
    except FileNotFoundError:
        print(f"Error: Dataset {dataset_path} not found.")
        sys.exit(1)
        
    df['url'] = df['url'].apply(lambda x: str(x).strip())
    if 'status' in df.columns:
        df['label'] = df['status'].apply(lambda x: 1 if str(x).lower() == 'phishing' else 0)
    
    os.makedirs(output_dir, exist_ok=True)
    checkpoint_file = os.path.join(output_dir, 'deep_path_checkpoint.csv')
    
    # ---------------------------------------------------------
    # RESUME LOGIC (Tính năng chạy tiếp nếu bị lỗi)
    # ---------------------------------------------------------
    processed_urls = set()
    if os.path.exists(checkpoint_file):
        print(f"Found existing checkpoint. Resuming from {checkpoint_file}...")
        try:
            checkpoint_df = pd.read_csv(checkpoint_file)
            processed_urls = set(checkpoint_df['url'].tolist())
            results = checkpoint_df.to_dict('records')
            print(f"Already processed {len(processed_urls)} URLs. {len(df) - len(processed_urls)} remaining.")
        except Exception as e:
            print(f"Error reading checkpoint: {e}. Starting fresh.")
            results = []
    else:
        results = []
        
    weights = get_weights()
    rules_weight = weights.get('rules_weight', 1.0)
    threshold = get_threshold()
    
    print(f"Evaluating Full Deep Path (LLM enabled)...")
    
    # Lặp qua toàn bộ dữ liệu
    for index, row in tqdm(df.iterrows(), total=len(df)):
        url = row['url']
        label = row['label']
        
        # Bỏ qua nếu URL đã được xử lý từ lần chạy trước
        if url in processed_urls:
            continue
            
        # 1. LAYER 1, 2, 3 (Rules Breakdown)
        _, _, rules_breakdown = app.calculate_rules_score(url)
        heuristic_score = sum(item.get('score_added', 0) for item in rules_breakdown if item.get('layer') == 'Heuristic') * rules_weight
        reputation_score = sum(item.get('score_added', 0) for item in rules_breakdown if item.get('layer') == 'Reputation') * rules_weight
        domain_score = sum(item.get('score_added', 0) for item in rules_breakdown if item.get('layer') == 'Domain / SSL') * rules_weight
        
        layer1_pred = 1 if heuristic_score >= threshold else 0
        layer2_pred = 1 if reputation_score > 0 else 0
        layer3_pred = 1 if domain_score >= threshold else 0
        
        # 2. LAYER 4 (ML)
        ml_prob = predict_phishing_probability(url)
        layer4_pred = 1 if ml_prob >= 0.5 else 0
        
        # 3. FAST PATH TÍNH ĐIỂM
        fast_final = calculate_final_score(rules_breakdown, ml_prob, llm_result=None)
        fast_score = fast_final['final_risk_score']
        fast_decision = fast_final['final_decision']
        fast_path_pred = 1 if fast_decision in ['unsafe', 'critical'] else 0
        
        # 4. LAYER 5 & FULL PATH (LLM)
        llm_result = None
        layer5_pred = 0
        full_path_pred = fast_path_pred # Mặc định là điểm fast path nếu không kích hoạt LLM
        
        if is_llm_available():
            # LUÔN LUÔN gọi LLM để lấy layer5 standalone score (Tốn thời gian nhất ở đây)
            time.sleep(2.5) # Sleep 2.5s để tránh Rate Limit (Quá 15 requests / phút)
            
            try:
                llm_result = analyze_url_with_llm(url, ml_prob=ml_prob, fast_score=fast_score)
                if llm_result and llm_result.get('verdict'):
                    llm_verdict = llm_result['verdict'].get('llm_verdict', 'safe')
                    layer5_pred = 1 if llm_verdict == 'unsafe' else 0
            except Exception as e:
                print(f"\nLLM Error for {url}: {e}")
                layer5_pred = 0
                
            # Chỉ cung cấp LLM result cho Deep Path nếu nó nằm trong Gray Zone (18 -> 51.90)
            llm_for_full_path = llm_result if (18 < fast_score <= 51.90) else None
            deep_final = calculate_final_score(rules_breakdown, ml_prob, llm_result=llm_for_full_path)
            full_path_pred = 1 if deep_final['final_decision'] in ['unsafe', 'critical'] else 0
            
        # ---------------------------------------------------------
        # Lưu kết quả theo từng URL để làm checkpoint
        # ---------------------------------------------------------
        result_row = {
            'url': url,
            'y_true': label,
            'Layer 1 (Heuristic)': layer1_pred,
            'Layer 2 (Reputation)': layer2_pred,
            'Layer 3 (Domain/SSL)': layer3_pred,
            'Layer 4 (ML)': layer4_pred,
            'Layer 5 (LLM Standalone)': layer5_pred,
            'Fast Path Score': fast_path_pred,
            'Full Path Score': full_path_pred
        }
        results.append(result_row)
        processed_urls.add(url)
        
        # Ghi đè file checkpoint mỗi 10 url (để giảm hao mòn ổ cứng nhưng vẫn backup tốt)
        if len(results) % 10 == 0:
            pd.DataFrame(results).to_csv(checkpoint_file, index=False)
            
    # Lưu file cuối cùng khi chạy xong 100%
    final_df = pd.DataFrame(results)
    final_df.to_csv(checkpoint_file, index=False)
    
    # ---------------------------------------------------------
    # TÍNH TOÁN METRICS TỪ FILE CHECKPOINT
    # ---------------------------------------------------------
    print("\nCalculating Final Metrics...")
    metrics_results = []
    setups = ['Layer 1 (Heuristic)', 'Layer 2 (Reputation)', 'Layer 3 (Domain/SSL)', 
              'Layer 4 (ML)', 'Layer 5 (LLM Standalone)', 'Fast Path Score', 'Full Path Score']
              
    y_true_all = final_df['y_true'].tolist()
    
    for setup_name in setups:
        y_pred = final_df[setup_name].tolist()
        
        tp = sum(1 for yt, yp in zip(y_true_all, y_pred) if yt == 1 and yp == 1)
        fp = sum(1 for yt, yp in zip(y_true_all, y_pred) if yt == 0 and yp == 1)
        tn = sum(1 for yt, yp in zip(y_true_all, y_pred) if yt == 0 and yp == 0)
        fn = sum(1 for yt, yp in zip(y_true_all, y_pred) if yt == 1 and yp == 0)
        
        acc = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * (prec * rec) / (prec + rec) if (prec + rec) > 0 else 0
        
        metrics_results.append({
            'Setup': setup_name,
            'Accuracy': f"{acc:.4f}",
            'Precision': f"{prec:.4f}",
            'Recall': f"{rec:.4f}",
            'F1-score': f"{f1:.4f}",
            'TP': tp, 'FP': fp, 'TN': tn, 'FN': fn
        })
        
    metrics_df = pd.DataFrame(metrics_results)
    print("\n================ FINAL DEEP PATH RESULTS ================")
    print(metrics_df.to_string(index=False))
    
    csv_path = os.path.join(output_dir, 'deep_path_full_evaluation.csv')
    metrics_df.to_csv(csv_path, index=False)
    print(f"\nFinal metrics saved to {csv_path}")

if __name__ == '__main__':
    dataset_path = os.path.join(os.path.dirname(__file__), '..', '..', 'colab_notebooks', 'phishing_dataset', 'dataset_phishing.csv')
    output_dir = os.path.join(os.path.dirname(__file__), '..', 'models', 'evaluation result')
    evaluate_full_deep_path(dataset_path, output_dir)
