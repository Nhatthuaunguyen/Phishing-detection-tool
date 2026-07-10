"""
LLM Analyzer for Phishing Detection Backend
Uses Google Gemini Vision & Text for logo, content, and metadata analysis.
Includes API Key Fallback Chain and exact output matching Phase 2.
"""

import os
import re
import json
import time
import requests
from io import BytesIO
from urllib.parse import urlparse

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False
    print("[LLM] Warning: beautifulsoup4 not installed.")

try:
    from PIL import Image
    HAS_PIL = True
except ImportError:
    HAS_PIL = False
    print("[LLM] Warning: Pillow not installed.")

try:
    import google.generativeai as genai
    HAS_GEMINI = True
except ImportError:
    HAS_GEMINI = False
    print("[LLM] Warning: google-generativeai not installed.")

# --- Configuration & Fallback Chain ---
# Dán API key của bạn vào đây. Key đầu tiên là Key chính. 
# Các key sau là dự phòng. Hệ thống tự động chuyển key khi hết quota.
API_KEYS = [
    "Enter your key here"
]

# Xóa các khoảng trắng thừa nếu có
API_KEYS = [k.strip() for k in API_KEYS if k.strip()]
current_key_idx = 0
LLM_ENABLED = HAS_GEMINI and len(API_KEYS) > 0

if LLM_ENABLED:
    genai.configure(api_key=API_KEYS[current_key_idx])
    print(f"[LLM] Gemini API configured. Loaded {len(API_KEYS)} keys.")
else:
    print("[LLM] API Keys not found. Set GEMINI_API_KEYS (comma separated).")

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Accept': 'text/html,application/xhtml+xml,*/*',
}

BRAND_DOMAINS = {
    'paypal': ['paypal.com', 'paypal.me'],
    'google': ['google.com', 'google.co', 'gmail.com', 'googleapis.com'],
    'facebook': ['facebook.com', 'fb.com', 'meta.com'],
    'instagram': ['instagram.com'],
    'apple': ['apple.com', 'icloud.com'],
    'microsoft': ['microsoft.com', 'live.com', 'outlook.com', 'office.com'],
    'amazon': ['amazon.com', 'amazon.co', 'aws.com'],
    'netflix': ['netflix.com'],
    'bank of america': ['bankofamerica.com', 'bofa.com'],
    'chase': ['chase.com', 'jpmorgan.com'],
    'wells fargo': ['wellsfargo.com'],
    'coinbase': ['coinbase.com'],
}

def rotate_api_key():
    global current_key_idx
    if len(API_KEYS) <= 1:
        return False
    current_key_idx = (current_key_idx + 1) % len(API_KEYS)
    genai.configure(api_key=API_KEYS[current_key_idx])
    # print(f"[LLM] API Key rate limited. Rotated to key index {current_key_idx}.")
    return True

# --- HTML Extractors ---

def fetch_page(url, timeout=10):
    try:
        response = requests.get(url, headers=HEADERS, timeout=timeout, verify=False, allow_redirects=True)
        response.raise_for_status()
        return response.text, response.url
    except:
        return None, url

def extract_logo_url(html, base_url):
    if not html or not HAS_BS4: return None
    soup = BeautifulSoup(html, 'lxml')
    parsed = urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    
    for link in soup.find_all('link', rel=True):
        if 'icon' in ' '.join(link.get('rel', [])).lower():
            href = link.get('href', '')
            if href:
                if href.startswith('//'): return f"{parsed.scheme}:{href}"
                elif href.startswith('/'): return base + href
                elif not href.startswith('http'): return base + '/' + href
                return href
    return f"{base}/favicon.ico"

def extract_metadata(html):
    if not html or not HAS_BS4: return {}
    soup = BeautifulSoup(html, 'lxml')
    metadata = {'title': '', 'description': '', 'keywords': '', 'og_title': '', 'og_site_name': ''}
    
    if soup.title: metadata['title'] = soup.title.string or ''
    
    for meta in soup.find_all('meta'):
        name = meta.get('name', '').lower()
        prop = meta.get('property', '').lower()
        content = meta.get('content', '')
        if name == 'description': metadata['description'] = content
        elif name == 'keywords': metadata['keywords'] = content
        elif prop == 'og:title': metadata['og_title'] = content
        elif prop == 'og:site_name': metadata['og_site_name'] = content
    return metadata

def extract_page_content(html):
    if not html or not HAS_BS4: return ""
    soup = BeautifulSoup(html, 'lxml')
    # Clean up JS, CSS, comments
    for tag in soup.find_all(['script', 'style', 'noscript', 'svg', 'nav', 'footer']):
        tag.decompose()
    
    parts = []
    for form in soup.find_all('form'):
        inputs = [i.get('type', 'text') + ':' + (i.get('name', '') or i.get('placeholder', '')) for i in form.find_all('input')]
        parts.append(f"Form(action={form.get('action', '?')}, inputs={inputs})")
    for h in soup.find_all(['h1', 'h2', 'h3'], limit=10):
        parts.append(f"{h.name}: {h.get_text(strip=True)}")
    
    parts.append("BODY: " + soup.get_text(separator=' ', strip=True)[:1500])
    return '\n'.join(parts)

# --- LLM Analyzer ---

class LLMAnalyzer:
    def __init__(self):
        if LLM_ENABLED:
            self.vision_model = genai.GenerativeModel('gemini-2.0-flash')
            self.text_model = genai.GenerativeModel('gemini-2.0-flash')
    
    def _execute_with_fallback(self, func, *args, **kwargs):
        """Wrapper to execute LLM calls with auto fallback on failure."""
        retries = len(API_KEYS) if len(API_KEYS) > 0 else 1
        last_err = None
        for _ in range(retries):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                last_err = str(e)
                # Rotate key for any error (invalid key, quota limits, etc.)
                if rotate_api_key():
                    if "429" in last_err or "quota" in last_err.lower() or "exhausted" in last_err.lower():
                        time.sleep(1) # wait briefly on quota issues
                    continue
                break
        raise Exception(f"LLM API Error after retries: {last_err}")

    def analyze_logo(self, logo_url):
        result = {'detected_logo_brand': 'unknown', 'logo_confidence': 0, 'logo_suspicious': False, 'logo_reason': '', 'error': None}
        if not logo_url: return result
        try:
            resp = requests.get(logo_url, headers=HEADERS, timeout=5, verify=False)
            if resp.status_code != 200 or len(resp.content) < 100:
                return result
            img = Image.open(BytesIO(resp.content))
            if img.format == 'ICO' or logo_url.endswith('.ico'): img = img.convert('RGBA')
            
            prompt = """Analyze this logo/favicon image. 
            Respond in EXACT JSON:
            {"detected_logo_brand": "CompanyName or unknown", "logo_suspicious": true/false, "logo_confidence": 0-100, "logo_reason": "Brief explanation"}"""
            
            def call_vision():
                resp = self.vision_model.generate_content([prompt, img])
                return resp.text.strip()
            
            text = self._execute_with_fallback(call_vision)
            json_match = re.search(r'\{[^}]+\}', text, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group())
                result.update(data)
        except Exception as e:
            result['error'] = str(e)
        return result

    def analyze_content(self, page_content, url):
        result = {'page_purpose': 'unknown', 'content_brand': 'unknown', 'sensitive_action_requested': False, 'content_suspicious_signals': [], 'error': None}
        if not page_content: return result
        try:
            prompt = f"""URL: {url}
            CONTENT: {page_content[:2000]}
            Respond in EXACT JSON:
            {{"page_purpose": "type of page", "content_brand": "brand or unknown", "sensitive_action_requested": true/false, "content_suspicious_signals": ["signal1", "signal2"]}}"""
            
            def call_text():
                return self.text_model.generate_content(prompt).text.strip()
            
            text = self._execute_with_fallback(call_text)
            json_match = re.search(r'\{[^}]+\}', text, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group())
                result.update(data)
        except Exception as e:
            result['error'] = str(e)
        return result

    def analyze_metadata(self, metadata, url):
        result = {'metadata_brand': 'unknown', 'metadata_suspicious': False, 'metadata_reason': '', 'error': None}
        if not metadata: return result
        try:
            meta_text = json.dumps(metadata)
            prompt = f"""URL: {url}
            METADATA: {meta_text}
            Respond in EXACT JSON:
            {{"metadata_brand": "brand or unknown", "metadata_suspicious": true/false, "metadata_reason": "explanation"}}"""
            
            def call_text():
                return self.text_model.generate_content(prompt).text.strip()
            
            text = self._execute_with_fallback(call_text)
            json_match = re.search(r'\{[^}]+\}', text, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group())
                result.update(data)
        except Exception as e:
            result['error'] = str(e)
        return result

    def cross_match(self, url, logo_res, content_res, meta_res):
        domain = urlparse(url).hostname or ''
        result = {'brand_domain_match': True, 'mismatch_type': 'none', 'matched_brand': 'none', 'actual_domain': domain, 'expected_domains': [], 'mismatch_reason': ''}
        
        brands = [b for b in [logo_res.get('detected_logo_brand'), content_res.get('content_brand'), meta_res.get('metadata_brand')] if b and b.lower() != 'unknown']
        if not brands: return result
        
        primary_brand = brands[0].lower().strip()
        result['matched_brand'] = primary_brand
        
        # Check domain
        expected = BRAND_DOMAINS.get(primary_brand, [])
        result['expected_domains'] = expected
        
        is_match = False
        if expected:
            for e in expected:
                if domain.lower() == e or domain.lower().endswith('.' + e):
                    is_match = True
        else:
            brand_no_space = primary_brand.replace(' ', '')
            domain_parts = domain.lower().split('.')
            if brand_no_space in domain_parts:
                is_match = True
        
        result['brand_domain_match'] = is_match
        if not is_match:
            result['mismatch_type'] = 'domain_mismatch'
            result['mismatch_reason'] = f"Brand '{primary_brand}' does not align with domain '{domain}'"
            
        return result

    def final_verdict(self, cross_match, logo_res, content_res, ml_prob, fast_score):
        score = 0
        signals = content_res.get('content_suspicious_signals', [])
        
        if not cross_match['brand_domain_match']: 
            score += 40
            signals.append("Brand-Domain mismatch")
        if logo_res.get('logo_suspicious'): 
            score += 15
            signals.append("Fake/Modified Logo")
        if content_res.get('sensitive_action_requested'):
            score += 20
        
        verdict = 'safe'
        if score >= 40: verdict = 'phishing'
        elif score >= 15: verdict = 'suspicious'
        
        return {
            'llm_verdict': verdict,
            'llm_confidence': 'high' if score >= 40 else 'medium',
            'llm_risk_score': score,
            'llm_explanation': cross_match.get('mismatch_reason', 'Analysis completed with no critical mismatch'),
            'llm_detected_signals': signals
        }

    def full_analysis(self, url, ml_prob=0.0, fast_score=0.0):
        if not LLM_ENABLED:
            return {'llm_status': 'skipped', 'reason': 'LLM not configured'}
            
        try:
            html, final_url = fetch_page(url)
            if not html: return {'llm_status': 'failed', 'reason': 'Failed to fetch page'}
            
            logo_url = extract_logo_url(html, final_url)
            meta = extract_metadata(html)
            content = extract_page_content(html)
            
            logo_res = self.analyze_logo(logo_url)
            time.sleep(1)
            content_res = self.analyze_content(content, url)
            time.sleep(1)
            meta_res = self.analyze_metadata(meta, url)
            
            cross_match = self.cross_match(url, logo_res, content_res, meta_res)
            verdict = self.final_verdict(cross_match, logo_res, content_res, ml_prob, fast_score)
            
            return {
                'llm_status': 'success',
                'logo': logo_res,
                'content': content_res,
                'metadata': meta_res,
                'cross_match': cross_match,
                'verdict': verdict
            }
        except Exception as e:
            return {'llm_status': 'failed', 'reason': str(e)}

_analyzer = None
def get_analyzer():
    global _analyzer
    if _analyzer is None: _analyzer = LLMAnalyzer()
    return _analyzer

def analyze_url_with_llm(url, ml_prob=0.0, fast_score=0.0):
    return get_analyzer().full_analysis(url, ml_prob, fast_score)

def is_llm_available():
    return LLM_ENABLED
