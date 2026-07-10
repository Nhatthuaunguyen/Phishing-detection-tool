import json
import os

# Define config path
CONFIG_PATH = os.path.join(os.path.dirname(__file__), 'models', 'scoring_config_evaluation.json')

def load_scoring_config():
    """Loads configuration from scoring_config_evaluation.json."""
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading scoring config: {e}")
    # Fallback default configuration
    return {
        "global_threshold": 18,
        "weights": {
            "rules_weight": 1.0,
            "ml_weight": 0.3,
            "llm_weight": 1.0
        }
    }

def get_threshold():
    return load_scoring_config().get("global_threshold", 18)

def get_weights():
    return load_scoring_config().get("weights", {"rules_weight": 1.0, "ml_weight": 0.3, "llm_weight": 1.0})

def reload_config():
    return load_scoring_config()

def map_ml_risk_level(prob):
    """Maps ML probability to semantic risk level."""
    if prob <= 0.20: return "Low"
    elif prob <= 0.40: return "Mild"
    elif prob <= 0.60: return "Borderline"
    elif prob <= 0.80: return "High"
    return "Critical"

def calculate_final_score(rules_breakdown, ml_probability, llm_result=None):
    """
    Synthesizes the rules_breakdown, ML probability, and optional LLM analysis
    into a structured final risk score matching the Phase 0 architecture.
    """
    config = load_scoring_config()
    threshold = config.get("global_threshold", 18)
    weights = config.get("weights", {})
    rules_w = weights.get('rules_weight', 1.0)
    ml_w = weights.get('ml_weight', 0.3)
    
    # 1. Component Scoring
    heuristic_score = 0
    reputation_score = 0
    domain_score = 0
    
    detailed_breakdown = []
    
    # Process Rules Breakdown
    for rule in rules_breakdown:
        rule_score = rule.get('score_added', 0) * rules_w
        layer = rule.get('layer', 'Heuristic')
        if layer == 'Heuristic': heuristic_score += rule_score
        elif layer == 'Reputation': reputation_score += rule_score
        elif layer == 'Domain / SSL': domain_score += rule_score
        
        detailed_breakdown.append({
            'layer': layer,
            'rule_name': rule.get('rule_name', 'Unknown'),
            'matched': True,
            'score_added': round(rule_score, 2),
            'severity': rule.get('severity', 'Medium'),
            'reason': rule.get('reason', '')
        })

    # ML Scoring
    ml_risk_level = map_ml_risk_level(ml_probability)
    raw_ml_score = ml_probability * 100
    ml_score = raw_ml_score * ml_w
    
    detailed_breakdown.append({
        'layer': 'Machine Learning',
        'rule_name': f'ML Prediction ({int(raw_ml_score)}%)',
        'matched': True,
        'score_added': round(ml_score, 2),
        'severity': ml_risk_level,
        'reason': f'Machine learning model predicted probability of {ml_probability:.4f}'
    })

    # LLM Scoring
    llm_score = 0
    llm_triggered = False
    llm_verdict_str = "not_analyzed"
    
    if llm_result and llm_result.get('llm_status') == 'success':
        llm_triggered = True
        verdict = llm_result.get('verdict', {})
        llm_score = verdict.get('llm_risk_score', 0)
        llm_verdict_str = verdict.get('llm_verdict', 'safe')
        
        for signal in verdict.get('llm_detected_signals', []):
            detailed_breakdown.append({
                'layer': 'LLM',
                'rule_name': 'LLM Signal',
                'matched': True,
                'score_added': 0, # Usually synthesized in llm_risk_score
                'severity': 'High',
                'reason': signal
            })
            
        detailed_breakdown.append({
            'layer': 'LLM',
            'rule_name': 'LLM Deep Analysis',
            'matched': True,
            'score_added': round(llm_score, 2),
            'severity': 'Critical' if llm_score >= 40 else ('High' if llm_score >= 17 else 'Low'),
            'reason': verdict.get('llm_explanation', 'LLM analysis completed')
        })

    # 2. Total Risk Scores
    fast_total_score = heuristic_score + reputation_score + domain_score + ml_score
    
    final_risk_score = round(fast_total_score, 2)
    path_used = 'deep_path' if llm_triggered else 'fast_path'
    
    layers_used = ['Heuristic', 'Machine Learning']
    if reputation_score > 0: layers_used.append('Reputation')
    if domain_score > 0: layers_used.append('Domain / SSL')
    if llm_triggered: layers_used.append('LLM')

    # 3. Decision Zones
    final_decision = "safe"
    recommendation = "allow"
    user_explanation = "This website appears safe."
    
    LLM_LOWER_BOUND = 18
    LLM_UPPER_BOUND = 51.90
    FALLBACK_THRESHOLD = 18.65
    
    if final_risk_score > LLM_UPPER_BOUND or reputation_score > 0:
        final_decision = "unsafe"
        recommendation = "block immediately"
        user_explanation = "CRITICAL WARNING: This website is a known or highly suspected phishing threat. Do not provide any information."
    elif final_risk_score > LLM_LOWER_BOUND:
        if llm_triggered:
            if llm_verdict_str == 'safe':
                final_decision = "safe"
                recommendation = "allow / cleared by AI"
                user_explanation = "Website had suspicious elements, but deep AI analysis verified it is safe."
                final_risk_score = LLM_LOWER_BOUND - 0.01 # Lower the score visually so the app shows green
            else:
                final_decision = "unsafe"
                recommendation = "block / confirmed by AI"
                user_explanation = "Deep AI analysis confirmed this is a phishing website."
                final_risk_score = round(final_risk_score + llm_score, 2) # Boost the score
        else:
            if final_risk_score >= FALLBACK_THRESHOLD:
                final_decision = "unsafe"
                recommendation = "block"
                user_explanation = "WARNING: This website has indicators of phishing."
            else:
                final_decision = "safe"
                recommendation = "allow"
                user_explanation = "This website appears safe."
    else:
        final_decision = "safe"
        recommendation = "allow"
        user_explanation = "This website appears safe."

    # Top Reasons
    top_reasons = [item['reason'] for item in sorted(detailed_breakdown, key=lambda x: x['score_added'], reverse=True)[:5] if item['score_added'] > 0]

    return {
        'final_risk_score': final_risk_score,
        'final_decision': final_decision,
        'threshold_used': threshold,
        'path_used': path_used,
        'layers_used': layers_used,
        'score_breakdown': {
            'rules_score': round(heuristic_score + reputation_score + domain_score, 2),
            'heuristic_score': round(heuristic_score, 2),
            'reputation_score': round(reputation_score, 2),
            'domain_score': round(domain_score, 2),
            'ml_score': round(ml_score, 2),
            'llm_score': round(llm_score, 2),
            'detailed_breakdown': detailed_breakdown
        },
        'top_reasons': top_reasons,
        'user_explanation': user_explanation,
        'developer_details': f"ML Prob: {ml_probability:.4f}. Threshold cut: {threshold}.",
        'recommendation': recommendation,
        'llm_triggered': llm_triggered,
        'llm_verdict': llm_verdict_str,
        'llm_status': llm_result.get('llm_status', 'skipped') if llm_result else 'skipped',
        'is_unsafe': final_decision in ['unsafe', 'critical']
    }
