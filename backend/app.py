import warnings
warnings.filterwarnings("ignore")

import logging
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

from flask import Flask, request, jsonify
from flask_cors import CORS
import re
import os
import socket
import ssl
from datetime import datetime
from urllib.parse import urlparse
import whois
import requests

# --- NEW: Import ML, LLM, and Scoring modules ---
from ml_model import predict_phishing_probability, is_model_loaded
from llm_analyzer import analyze_url_with_llm, is_llm_available
from scoring import calculate_final_score, get_threshold, get_weights, reload_config

app = Flask(__name__)
CORS(app)

# --- CONFIGURATION ---
# Threshold is now loaded from scoring_config.json via scoring.py
# Fallback to 50 if config not available
THRESHOLD = get_threshold()

# Mock external blacklists for Threat Intelligence
LOCAL_BLACKLIST = ['phish-update-secure.com', 'fake-login-bank.net']

def is_valid_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

# --- LAYER 2: THREAT INTELLIGENCE ---
def check_threat_intelligence(url, hostname):
    """
    Checks the URL against blacklists. 
    In production, replace this with actual API calls to Google Safe Browsing or PhishTank.
    """
    # 1. Local/Hardcoded Blacklist Check
    if hostname in LOCAL_BLACKLIST:
        return True, "Domain found in local threat intelligence blacklist."
    
    # 2. External API Example (Placeholder)
    # try:
    #     response = requests.post("https://api.safebrowsing.google.com...", json={"url": url}, timeout=3)
    #     if response.json().get('matches'):
    #         return True, "Flagged by Google Safe Browsing."
    # except:
    #     pass

    return False, ""

# --- LAYER 3: DOMAIN AND SSL CHECKS ---
def check_domain_age(hostname):
    """Fetches WHOIS data to determine domain age. New domains are suspicious."""
    try:
        # Strip subdomains for WHOIS (e.g., www.example.com -> example.com)
        domain_parts = hostname.split('.')
        if len(domain_parts) > 2:
            base_domain = '.'.join(domain_parts[-2:])
        else:
            base_domain = hostname

        domain_info = whois.whois(base_domain)
        creation_date = domain_info.creation_date
        
        if type(creation_date) is list:
            creation_date = creation_date[0]
            
        if creation_date:
            age_days = (datetime.now() - creation_date).days
            return age_days
    except Exception as e:
        return -1 # Unable to fetch WHOIS (often true for malicious sites hiding data)
    return -1

def check_ssl_certificate(hostname):
    """Checks if the SSL certificate is valid and issued properly."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                # If we get here, a valid cert exists. We could check issuer/expiry here.
                return True, "Valid SSL Certificate"
    except Exception as e:
        return False, f"SSL Error or No valid certificate: {str(e)}"

# --- MAIN SCORING FUNCTION (LAYER 1: RULES) ---
def calculate_rules_score(url):
    """
    Calculate rule-based phishing score.
    Returns (score, reasons, breakdown) tuple.
    """
    score = 0
    reasons = []
    breakdown = []

    if not is_valid_url(url):
        return 0, [], []

    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    path = parsed.path.lower()

    # ========================================================
    # LAYER 1: ENHANCED RULE-BASED DETECTION (Lexical & Heuristic)
    # ========================================================

    # Rule 1.1: IP Address in Hostname
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname):
        score += 80
        reasons.append("Hostname looks like an IP address")
        breakdown.append({
            'rule_name': 'IP-based domain',
            'score_added': 80,
            'severity': 'Critical',
            'reason': 'Hostname looks like an IP address',
            'layer': 'Heuristic'
        })

    # Rule 1.2: Unusually Long URL
    if len(url) > 100:
        score += 20
        reasons.append(f"URL is unusually long ({len(url)} chars)")
        breakdown.append({
            'rule_name': 'Long URL',
            'score_added': 20,
            'severity': 'Low',
            'reason': f"URL length is {len(url)} characters",
            'layer': 'Heuristic'
        })

    # Rule 1.3: Suspicious Keywords
    suspicious_keywords = ['login', 'signin', 'auth', 'verify', 'verification', 'authorize', 'credential', 'identity','secure', 'security', 'protection', 'lock', 'account-update', 'webscr', 'admin', 'portal', 'client', 'server', 'support', 'config']
    if any(keyword in url.lower() for keyword in suspicious_keywords):
        score += 15
        reasons.append("Suspicious keyword found in URL")
        breakdown.append({
            'rule_name': 'Suspicious keyword',
            'score_added': 15,
            'severity': 'Medium',
            'reason': 'URL contains keywords often used in phishing',
            'layer': 'Heuristic'
        })

    # Rule 1.4: Protocol Check
    if parsed.scheme != 'https':
        score += 30
        reasons.append("Connection is not secure (HTTP only)")
        breakdown.append({
            'rule_name': 'Insecure Protocol',
            'score_added': 30,
            'severity': 'High',
            'reason': 'Connection is not secure (HTTP only)',
            'layer': 'Domain / SSL'
        })

    # Rule 1.5: Too Many Subdomains (e.g., login.verify.paypal.com.scam.net)
    if hostname.count('.') > 3:
        score += 25
        reasons.append("Excessive number of subdomains detected")
        breakdown.append({
            'rule_name': 'Too many subdomains',
            'score_added': 25,
            'severity': 'High',
            'reason': 'Excessive number of subdomains detected',
            'layer': 'Heuristic'
        })

    # Rule 1.6: Suspicious Path/File Extensions
    suspicious_extensions = ['.exe', '.zip', '.apk', '.rar']
    if any(path.endswith(ext) for ext in suspicious_extensions):
        score += 40
        reasons.append("URL points to a suspicious executable or archive file")
        breakdown.append({
            'rule_name': 'Suspicious file extension',
            'score_added': 40,
            'severity': 'High',
            'reason': 'URL points to a suspicious executable or archive file',
            'layer': 'Heuristic'
        })

    # Rule 1.7: Lexical/Homoglyph Simulation (Basic check for mixed character sets/dashes)
    if hostname.count('-') > 2:
        score += 15
        reasons.append("Multiple dashes in domain name (common in phishing)")
        breakdown.append({
            'rule_name': 'Multiple dashes in domain',
            'score_added': 15,
            'severity': 'Medium',
            'reason': 'Multiple dashes in domain name',
            'layer': 'Heuristic'
        })

    # ========================================================
    # LAYER 2: THREAT INTELLIGENCE (Blacklisting)
    # ========================================================
    is_blacklisted, blacklist_reason = check_threat_intelligence(url, hostname)
    if is_blacklisted:
        score += 100  # Immediate massive penalty
        reasons.append(f"BLACKLISTED: {blacklist_reason}")
        breakdown.append({
            'rule_name': 'Match Blacklist',
            'score_added': 100,
            'severity': 'Critical',
            'reason': blacklist_reason,
            'layer': 'Reputation'
        })

    # ========================================================
    # LAYER 3: DOMAIN AND SSL CHECKS
    # ========================================================
    # Domain Age Check
    domain_age_days = check_domain_age(hostname)
    if domain_age_days == -1:
        # Ẩn whois thì mình cũng chưa chắc nó có an toàn hay không nên cứ cho 10 điểm
        score += 8
        breakdown.append({'rule_name': 'Hidden WHOIS', 'score_added': 8, 'severity': 'Low', 'reason': 'WHOIS data is hidden or unavailable', 'layer': 'Domain / SSL'})
    elif domain_age_days < 30:
        score += 40
        reasons.append(f"Domain is very new (Registered {domain_age_days} days ago - High Risk)")
        breakdown.append({'rule_name': 'Very new domain', 'score_added': 40, 'severity': 'High', 'reason': f'Registered {domain_age_days} days ago', 'layer': 'Domain / SSL'})
    elif domain_age_days < 90:
        score += 20
        reasons.append(f"Domain is relatively new (Registered {domain_age_days} days ago - Medium Risk)")
        breakdown.append({'rule_name': 'New domain', 'score_added': 20, 'severity': 'Medium', 'reason': f'Registered {domain_age_days} days ago', 'layer': 'Domain / SSL'})
    elif domain_age_days < 180:
        score += 10
        reasons.append(f"Domain was registered recently ({domain_age_days} days ago - Low Risk)")
        breakdown.append({'rule_name': 'Recent domain', 'score_added': 10, 'severity': 'Low', 'reason': f'Registered {domain_age_days} days ago', 'layer': 'Domain / SSL'})

    # SSL Check (Only apply if scheme is HTTPS, HTTP is penalized above)
    if parsed.scheme == 'https':
        has_valid_ssl, ssl_msg = check_ssl_certificate(hostname)
        if not has_valid_ssl:
            score += 35
            reasons.append(f"SSL Certificate Anomaly: {ssl_msg}")
            breakdown.append({'rule_name': 'Invalid SSL', 'score_added': 35, 'severity': 'High', 'reason': ssl_msg, 'layer': 'Domain / SSL'})

    return score, reasons, breakdown


# ========================================================
# API ENDPOINTS
# ========================================================

@app.route('/', methods=['GET'])
def home():
    return jsonify({
        "status": "running",
        "message": "Enhanced Phishing Detection Backend with ML + LLM",
        "ml_model_loaded": is_model_loaded(),
        "llm_available": is_llm_available(),
        "threshold": get_threshold(),
        "endpoints": {
            "/analyze": "Fast analysis (Rules + ML) — real-time blocking",
            "/analyze-deep": "Deep analysis (Rules + ML + LLM Vision) — slower but more accurate",
            "/config": "View current scoring configuration"
        }
    })


@app.route('/analyze', methods=['POST'])
def analyze_url():
    """
    FAST analysis endpoint: Rules + ML only.
    Used for real-time URL blocking by both Chrome Extension and Mobile App.
    Response time: ~1-3 seconds
    """
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({"error": "No URL provided"}), 400

    url = data.get('url', '')
    print(f"\n[/analyze] Analyzing URL: {url}")

    # Layer 1: Rule-based scoring
    rules_score, reasons, rules_breakdown = calculate_rules_score(url)

    # Layer 2: ML model prediction
    ml_prob = predict_phishing_probability(url)
    if ml_prob > 0.5:
        reasons.append(f"ML Model detected phishing pattern ({int(ml_prob*100)}% confidence)")

    # Calculate fast path score without LLM first to check trigger conditions
    temp_final = calculate_final_score(
        rules_breakdown=rules_breakdown,
        ml_probability=ml_prob,
        llm_result=None
    )
    
    fast_risk_score = temp_final['final_risk_score']
    threshold = temp_final['threshold_used']
    
    # LLM Trigger Logic
    # Trigger LLM in the uncertain zone (18, 51.90]
    trigger_llm = False
    if is_llm_available():
        if 18 < fast_risk_score <= 51.90:
            trigger_llm = True


    llm_result = None
    if trigger_llm:
        print(f"  -> Triggering LLM Deep Analysis (Fast Score: {fast_risk_score})")
        llm_result = analyze_url_with_llm(url, ml_prob=ml_prob, fast_score=fast_risk_score)
        
        if llm_result and llm_result.get('llm_status') != 'success':
            print(f"  -> LLM Analysis Failed: {llm_result.get('reason', 'Unknown error')}. Falling back to Fast Path.")

        # Logging for Evaluation (Step 15)
        if llm_result:
            try:
                log_path = os.path.join(os.path.dirname(__file__), 'models', 'llm result', 'llm_eval_log.csv')
                os.makedirs(os.path.dirname(log_path), exist_ok=True)
                file_exists = os.path.exists(log_path)
                with open(log_path, 'a', encoding='utf-8') as f:
                    if not file_exists:
                        f.write("url,fast_path_score,llm_verdict,llm_risk_score,final_decision\n")
                    v = llm_result.get('verdict', {})
                    f.write(f"{url},{fast_risk_score},{v.get('llm_verdict', '')},{v.get('llm_risk_score', 0)},tbd\n")
            except Exception as e:
                print(f"  -> Failed to log LLM result: {e}")

    # Calculate final score using the scoring engine (with or without LLM)
    final = calculate_final_score(
        rules_breakdown=rules_breakdown,
        ml_probability=ml_prob,
        llm_result=llm_result
    )

    is_unsafe = final['is_unsafe']
    brkdwn = final['score_breakdown']
    fast_total = brkdwn['heuristic_score'] + brkdwn['reputation_score'] + brkdwn['domain_score'] + brkdwn['ml_score']

    if final.get('llm_triggered'):
        out = [
            f"PATH: DEEP PATH (Triggered because Fast Score {fast_total:.2f} is in gray zone (18 - 51.90])",
            f" FAST PATH SCORE: {fast_total:.2f}",
            f"     - Heuristic: {brkdwn['heuristic_score']}",
            f"     - Blacklist: {brkdwn['reputation_score']}",
            f"     - Domain/SSL: {brkdwn['domain_score']}",
            f"     - ML: {brkdwn['ml_score']} (prob={ml_prob:.4f})",
            f" LLM ANALYSIS",
            f"     - LLM Result: {final.get('llm_verdict', 'unknown').upper()}",
            f"     - LLM Score Added: {brkdwn['llm_score']}",
            f"-> Final score = {final['final_risk_score']:.2f}",
            f"-> final decision: {final['final_decision'].lower()}",
            f"-> status: {'unsafe' if is_unsafe else 'safe'}",
            f"Reason: {final['user_explanation']}"
        ]
    else:
        out = [
            f"PATH: FAST PATH",
            f" FAST PATH SCORE: {fast_total:.2f}",
            f"     - Heuristic: {brkdwn['heuristic_score']}",
            f"     - Blacklist: {brkdwn['reputation_score']}",
            f"     - Domain/SSL: {brkdwn['domain_score']}",
            f"     - ML: {brkdwn['ml_score']} (prob={ml_prob:.4f})",
            f"-> Final score = fast path score = {final['final_risk_score']:.2f}",
            f"-> final decision: {final['final_decision'].lower()}",
            f"-> status: {'unsafe' if is_unsafe else 'safe'}",
            f"Reason: {final['user_explanation']}"
        ]
    print("\n".join(out))
    print("-" * 30)

    # Return exactly the Phase 0 structured JSON + original URL
    response = final
    response["url"] = url
    
    if llm_result:
        response["llm_details"] = {
            "logo": llm_result.get('logo', {}),
            "content": llm_result.get('content', {}),
            "metadata": llm_result.get('metadata', {}),
            "cross_match": llm_result.get('cross_match', {}),
        }
    
    return jsonify(response)


@app.route('/analyze-deep', methods=['POST'])
def analyze_url_deep():
    """
    DEEP analysis endpoint: Rules + ML + LLM Vision.
    Provides full logo, content, and metadata analysis using Google Gemini.
    Response time: ~5-15 seconds (due to LLM API calls)
    """
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({"error": "No URL provided"}), 400

    url = data.get('url', '')
    print(f"\n[/analyze-deep] Deep analyzing URL: {url}")

    # Layer 1: Rule-based scoring
    rules_score, reasons, rules_breakdown = calculate_rules_score(url)

    # Layer 2: ML model prediction
    ml_prob = predict_phishing_probability(url)
    if ml_prob > 0.5:
        reasons.append(f"ML Model detected phishing pattern ({int(ml_prob*100)}% confidence)")

    # Layer 3: LLM analysis (logo, content, metadata, cross-matching)
    llm_result = None
    if is_llm_available():
        print("  -> Running Deep LLM analysis...")
        llm_result = analyze_url_with_llm(url, ml_prob=ml_prob, fast_score=0.0) # Using 0 as fast_score placeholder for manual deep
        
        # Add LLM-generated reasons handled entirely by calculate_final_score now
        if llm_result and llm_result.get('llm_status') != 'success':
            print(f"  -> LLM Analysis Failed: {llm_result.get('reason', 'Unknown error')}. Falling back to Fast Path.")

    else:
        print("  -> LLM not available, skipping deep analysis")

    # Calculate final score using all layers
    final = calculate_final_score(
        rules_breakdown=rules_breakdown,
        ml_probability=ml_prob,
        llm_result=llm_result
    )

    is_unsafe = final['is_unsafe']
    brkdwn = final['score_breakdown']
    fast_total = brkdwn['heuristic_score'] + brkdwn['reputation_score'] + brkdwn['domain_score'] + brkdwn['ml_score']

    if final.get('llm_triggered'):
        out = [
            f"PATH: DEEP PATH (Manual trigger)",
            f" FAST PATH SCORE: {fast_total:.2f}",
            f"     - Heuristic: {brkdwn['heuristic_score']}",
            f"     - Blacklist: {brkdwn['reputation_score']}",
            f"     - Domain/SSL: {brkdwn['domain_score']}",
            f"     - ML: {brkdwn['ml_score']} (prob={ml_prob:.4f})",
            f" LLM ANALYSIS",
            f"     - LLM Result: {final.get('llm_verdict', 'unknown').upper()}",
            f"     - LLM Score Added: {brkdwn['llm_score']}",
            f"-> Final score = {final['final_risk_score']:.2f}",
            f"-> final decision: {final['final_decision'].lower()}",
            f"-> status: {'unsafe' if is_unsafe else 'safe'}",
            f"Reason: {final['user_explanation']}"
        ]
    else:
        out = [
            f"PATH: FAST PATH",
            f" FAST PATH SCORE: {fast_total:.2f}",
            f"     - Heuristic: {brkdwn['heuristic_score']}",
            f"     - Blacklist: {brkdwn['reputation_score']}",
            f"     - Domain/SSL: {brkdwn['domain_score']}",
            f"     - ML: {brkdwn['ml_score']} (prob={ml_prob:.4f})",
            f"-> Final score = fast path score = {final['final_risk_score']:.2f}",
            f"-> final decision: {final['final_decision'].lower()}",
            f"-> status: {'unsafe' if is_unsafe else 'safe'}",
            f"Reason: {final['user_explanation']}"
        ]
    print("\n".join(out))
    print("-" * 30)

    # Return exactly the Phase 0 structured JSON + original URL
    response = final
    response["url"] = url
    
    if llm_result:
        response["llm_details"] = {
            "logo": llm_result.get('logo', {}),
            "content": llm_result.get('content', {}),
            "metadata": llm_result.get('metadata', {}),
            "cross_match": llm_result.get('cross_match', {}),
        }
        
    return jsonify(response)


@app.route('/config', methods=['GET'])
def get_config():
    """View the current scoring configuration."""
    return jsonify({
        "threshold": get_threshold(),
        "weights": get_weights(),
        "ml_model_loaded": is_model_loaded(),
        "llm_available": is_llm_available(),
    })


@app.route('/config/reload', methods=['POST'])
def reload_scoring_config():
    """Reload scoring configuration from disk without restarting the server."""
    global THRESHOLD
    config = reload_config()
    THRESHOLD = get_threshold()
    return jsonify({
        "message": "Configuration reloaded",
        "threshold": THRESHOLD,
        "weights": get_weights()
    })


import os
if __name__ == '__main__':
    print("  PHISHING DETECTION BACKEND")
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', debug=True, port=port)