import os
import sys
import pandas as pd
from tqdm import tqdm
import time

# Ensure backend directory is in path for imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from app import calculate_rules_score
from ml_model import predict_phishing_probability
from llm_analyzer import analyze_url_with_llm, is_llm_available
from scoring import calculate_final_score


def run_2_phase_evaluation(dataset_path, output_dir):
    if not is_llm_available():
        print("Error: LLM API is not available. Please set GEMINI_API_KEYS environment variable.")
        sys.exit(1)

    print(f"Loading Case Study dataset from {dataset_path}...")
    try:
        df = pd.read_csv(dataset_path)
    except FileNotFoundError:
        print(f"Error: Dataset {dataset_path} not found.")
        sys.exit(1)

    if 'url' not in df.columns or 'label' not in df.columns:
        if 'url' in df.columns and 'status' in df.columns:
            df['label'] = df['status'].apply(lambda x: 1 if str(x).lower() == 'phishing' else 0)
        else:
            print("Error: Dataset must contain 'url' and 'label' (0=safe, 1=phishing).")
            sys.exit(1)

    results = []

    print("\nRunning 2-Phase Evaluation (Fast Path vs Deep Path)...")
    for _, row in tqdm(df.iterrows(), total=len(df)):
        url = str(row['url'])
        ground_truth = "Phishing" if row['label'] == 1 else "Safe"

        # --- PHASE 1: Fast Path (Heuristic + Reputation + Domain/SSL + ML) ---
        _, _, rules_breakdown = calculate_rules_score(url)
        ml_prob = predict_phishing_probability(url)

        fast_final = calculate_final_score(rules_breakdown, ml_prob, llm_result=None)
        fast_decision = fast_final['final_decision']
        fast_score = fast_final['final_risk_score']

        # --- PHASE 2: Deep Path (Only trigger LLM in boundary zone [17, 30)) ---
        llm_result = None

        if is_llm_available() and 17 <= fast_score < 30:
            print(f"\nAnalyzing (LLM boundary zone): {url}")
            # Artificial delay to avoid rate limits
            time.sleep(2)
            llm_result = analyze_url_with_llm(url, ml_prob=ml_prob, fast_score=fast_score)

        deep_final = calculate_final_score(rules_breakdown, ml_prob, llm_result=llm_result)

        deep_decision = deep_final['final_decision']
        deep_score = deep_final['final_risk_score']

        llm_finding = deep_final.get('llm_verdict', 'unknown')
        llm_reason = ""
        if deep_final.get('score_breakdown', {}).get('detailed_breakdown'):
            llm_reasons = [
                item['reason']
                for item in deep_final['score_breakdown']['detailed_breakdown']
                if item['layer'] == 'LLM'
            ]
            llm_reason = "; ".join(llm_reasons)

        improvement = "No Change"
        # If ground truth is phishing, and fast missed it (safe/suspicious), but deep caught it (unsafe/critical)
        if row['label'] == 1 and fast_decision in ['safe', 'suspicious'] and deep_decision in ['unsafe', 'critical']:
            improvement = "Yes (Caught Phishing)"
        # If ground truth is safe, and fast blocked it, but deep allowed it
        elif row['label'] == 0 and fast_decision in ['unsafe', 'critical'] and deep_decision in ['safe', 'suspicious']:
            improvement = "Yes (Fixed False Positive)"

        results.append({
            'URL': url,
            'Ground Truth': ground_truth,
            'Fast Path Score': fast_score,
            'Fast Path Decision': fast_decision,
            'LLM Finding (Verdict)': llm_finding,
            'LLM Reason': llm_reason,
            'Deep Path Score': deep_score,
            'Final Decision': deep_decision,
            'Improvement': improvement
        })

    results_df = pd.DataFrame(results)

    os.makedirs(output_dir, exist_ok=True)
    csv_path = os.path.join(output_dir, 'llm_comparison_results.csv')

    # Kiểm tra xem file đã tồn tại chưa để quyết định có ghi Header (dòng tiêu đề) hay không
    file_exists = os.path.exists(csv_path)

    # mode='a' (append) giúp ghi nối tiếp dữ liệu mới vào file cũ thay vì xóa đè
    results_df.to_csv(csv_path, mode='a', index=False, header=not file_exists)

    print(f"\nEvaluation Complete! Saved (Appended) to {csv_path}")
    print("\nSummary of Improvements:")
    print(results_df['Improvement'].value_counts())


if __name__ == '__main__':
    dataset_path = sys.argv[1] if len(sys.argv) > 1 else 'case_study_dataset_llm.csv'
    output_dir = os.path.join(os.path.dirname(__file__), '..', 'models', 'evaluation result')
    run_2_phase_evaluation(dataset_path, output_dir)

