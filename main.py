from fastapi import FastAPI
from pydantic import BaseModel
import pickle
import pandas as pd
import requests
from fastapi.middleware.cors import CORSMiddleware
from features import extract_features
from urllib.parse import urlparse
import time
from datetime import datetime
import ssl
import socket
import re

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class URLRequest(BaseModel):
    url: str

# Load model and feature columns
with open("model.pkl", "rb") as f:
    model = pickle.load(f)

with open("feature_columns.pkl", "rb") as f:
    feature_columns = pickle.load(f)

def is_valid_domain_format(domain: str) -> bool:
    if not domain:
        return False
    if '.' not in domain:
        return False
    parts = domain.split('.')
    if len(parts) < 2:
        return False
    if len(parts[0]) < 2:
        return False
    if len(parts[-1]) < 2:
        return False
    return True

def domain_exists(domain: str) -> bool:
    try:
        socket.gethostbyname(domain)
        return True
    except socket.gaierror:
        return False

def detect_phishing_patterns(url: str, domain: str) -> tuple:
    """Detect phishing patterns from URL structure even if site is dead"""
    url_lower = url.lower()
    domain_lower = domain.lower()
    phishing_score = 0
    reasons = []
    
    # Pattern 1: Suspicious TLDs (heavily abused by phishers)
    suspicious_tlds = ['.xyz', '.top', '.club', '.online', '.site', '.click', '.win', '.bid', '.loan', '.download', '.cfd', '.icu', '.sbs', '.shop']
    for tld in suspicious_tlds:
        if domain_lower.endswith(tld):
            phishing_score += 30
            reasons.append(f"Suspicious TLD '{tld}' (commonly used for phishing)")
            break
    
    # Pattern 2: Brand impersonation
    brands = ['paypal', 'apple', 'microsoft', 'google', 'facebook', 'amazon', 'netflix', 'paypal', 'ebay', 'bank', 'icloud', 'icloud']
    for brand in brands:
        if brand in domain_lower:
            # Check if it's exactly the brand domain or has extra words
            if not domain_lower.endswith(f"{brand}.com") and not domain_lower.endswith(f"{brand}.org"):
                phishing_score += 25
                reasons.append(f"Brand impersonation detected: '{brand}' in domain")
                break
    
    # Pattern 3: Suspicious keywords in domain
    suspicious_keywords = ['login', 'verify', 'secure', 'account', 'update', 'confirm', 'validate', 'signin', 'sign-in', 'verification', 'alert', 'security']
    for keyword in suspicious_keywords:
        if keyword in domain_lower:
            phishing_score += 15
            reasons.append(f"Suspicious keyword '{keyword}' in domain")
            break
    
    # Pattern 4: Multiple hyphens or numbers (random-looking domains)
    if domain_lower.count('-') >= 2:
        phishing_score += 10
        reasons.append("Multiple hyphens in domain - suspicious pattern")
    
    digit_count = sum(c.isdigit() for c in domain_lower)
    if digit_count >= 3:
        phishing_score += 10
        reasons.append("Multiple numbers in domain - suspicious pattern")
    
    # Pattern 5: Very long domain (phishing sites often use long, random domains)
    if len(domain) > 25:
        phishing_score += 10
        reasons.append("Unusually long domain name")
    
    # Pattern 6: URL length (phishing URLs are often very long)
    if len(url) > 100:
        phishing_score += 10
        reasons.append("Very long URL - typical for phishing")
    
    # Pattern 7: Multiple subdomains
    subdomain_count = domain_lower.count('.')
    if subdomain_count >= 3:
        phishing_score += 15
        reasons.append("Multiple subdomains - domain obfuscation technique")
    
    # Pattern 8: Contains @ symbol (rare in legitimate URLs)
    if '@' in url:
        phishing_score += 25
        reasons.append("Contains '@' symbol - credential stealing attempt")
    
    # Pattern 9: IP address instead of domain name
    ip_pattern = re.compile(r'\d+\.\d+\.\d+\.\d+')
    if ip_pattern.search(domain):
        phishing_score += 30
        reasons.append("Uses IP address instead of domain name - highly suspicious")
    
    # Determine result based on score
    if phishing_score >= 40:
        return "PHISHING", reasons, phishing_score
    elif phishing_score >= 20:
        return "SUSPICIOUS", reasons, phishing_score
    else:
        return "CLEAN", reasons, phishing_score

def get_certificate_info(domain: str):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                issuer_parts = []
                for item in cert.get('issuer', []):
                    for key, value in item:
                        if key == 'commonName':
                            issuer_parts.append(value)
                        elif key == 'organizationName':
                            issuer_parts.insert(0, value)
                if issuer_parts:
                    issuer_str = " - ".join(issuer_parts)
                else:
                    issuer_str = "Unknown"
                return {
                    "has_ssl": True,
                    "issuer": issuer_str,
                    "expiry": cert.get('notAfter', 'Unknown'),
                }
    except Exception:
        return {"has_ssl": False, "issuer": "N/A", "expiry": "N/A"}

def get_ip_info(domain: str):
    try:
        ip = socket.gethostbyname(domain)
        return {"ip": ip, "country": "Unknown", "city": "Unknown", "asn": "Unknown", "org": "Unknown"}
    except Exception:
        return {"ip": "Unknown", "country": "Unknown", "city": "Unknown", "asn": "Unknown", "org": "Unknown"}

def check_url_accessible(url: str):
    try:
        response = requests.head(url, timeout=8, allow_redirects=True, headers={"User-Agent": "Mozilla/5.0"})
        return response.status_code == 200, response.status_code
    except:
        return False, 0

TRUSTED_DOMAINS = [
    'github.com', 'microsoft.com', 'google.com', 'wikipedia.org', 
    'kedah.gov.my', 'apple.com', 'amazon.com', 'facebook.com',
    'twitter.com', 'linkedin.com', 'youtube.com', 'netflix.com',
    'spotify.com', 'reddit.com', 'stackoverflow.com', 'gitlab.com'
]

@app.post("/predict")
def predict(data: URLRequest):
    start_time = time.time()
    url = data.url
    
    print(f"\n{'='*50}")
    print(f"Analyzing: {url}")
    
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path
    domain = domain.split(':')[0]
    domain_lower = domain.lower()
    
    # STEP 1: Validate domain format
    if not is_valid_domain_format(domain_lower):
        return {
            "result": "INVALID",
            "display_result": "INVALID WEBSITE ADDRESS",
            "confidence": "95%",
            "message": "Please enter a valid website address (e.g., google.com, github.com)",
            "analysis_time": f"{time.time() - start_time:.2f} seconds",
            "security_details": {},
            "html_features": {},
            "website_summary": "Invalid domain format."
        }
    
    # STEP 2: Check trusted domains
    is_trusted = any(td in domain_lower for td in TRUSTED_DOMAINS)
    if is_trusted:
        return {
            "result": "LEGITIMATE",
            "display_result": "LEGITIMATE",
            "confidence": "95%",
            "message": "This website appears to be legitimate based on our analysis.",
            "analysis_time": f"{time.time() - start_time:.2f} seconds",
            "security_details": {},
            "html_features": {},
            "website_summary": "This is a well-known, trusted website."
        }
    
    # STEP 3: Detect phishing patterns from URL structure (even if site is dead)
    pattern_result, pattern_reasons, phishing_score = detect_phishing_patterns(url, domain_lower)
    
    print(f"Phishing pattern score: {phishing_score}, Reasons: {pattern_reasons}")
    
    # STEP 4: Check if URL is accessible
    is_accessible, status_code = check_url_accessible(url)
    
    # STEP 5: Final decision based on pattern detection first
    if pattern_result == "PHISHING":
        return {
            "result": "PHISHING",
            "display_result": "PHISHING DETECTED",
            "confidence": f"{min(95, 50 + phishing_score)}%",
            "message": "WARNING! This URL shows strong phishing indicators based on its structure. Do NOT enter any personal information!",
            "analysis_time": f"{time.time() - start_time:.2f} seconds",
            "security_details": {
                "certificate": get_certificate_info(domain) if url.startswith("https") else {"has_ssl": False},
                "ip_info": get_ip_info(domain) if domain_exists(domain_lower) else {"ip": "N/A"}
            },
            "html_features": {},
            "website_summary": f"Phishing detected: {', '.join(pattern_reasons[:3])}",
            "phishing_indicators": pattern_reasons
        }
    
    if not is_accessible:
        if pattern_result == "SUSPICIOUS":
            return {
                "result": "PHISHING",
                "display_result": "PHISHING DETECTED",
                "confidence": f"{min(90, 40 + phishing_score)}%",
                "message": "WARNING! This URL shows suspicious patterns and the page is unreachable - common in phishing attacks.",
                "analysis_time": f"{time.time() - start_time:.2f} seconds",
                "security_details": {},
                "html_features": {},
                "website_summary": f"Phishing detected: {', '.join(pattern_reasons[:2])}",
                "phishing_indicators": pattern_reasons
            }
        else:
            return {
                "result": "UNREACHABLE",
                "display_result": "SUSPICIOUS - Page Unreachable",
                "confidence": "85%",
                "message": f"Page cannot be reached (Error {status_code}). Phishing sites often disappear quickly.",
                "analysis_time": f"{time.time() - start_time:.2f} seconds",
                "security_details": {},
                "html_features": {},
                "website_summary": "Page unreachable - this is common for phishing sites."
            }
    
    # STEP 6: Run ML model for accessible unknown domains
    feats = extract_features(url)
    website_summary = feats.pop('_website_summary', "No summary available.") if '_website_summary' in feats else "No summary available."
    
    for key in list(feats.keys()):
        if key.startswith('_'):
            feats.pop(key, None)
    
    df = pd.DataFrame([feats]).reindex(columns=feature_columns, fill_value=0)
    proba = model.predict_proba(df)[0]
    prediction = model.predict(df)[0]
    
    # Model mapping (0=Legitimate, 1=Phishing)
    if prediction == 0:
        result = "LEGITIMATE"
        display_result = "LEGITIMATE"
        confidence = round(proba[0] * 100, 2)
        message = "This website appears to be legitimate based on our analysis."
    else:
        result = "PHISHING"
        display_result = "PHISHING DETECTED"
        confidence = round(proba[1] * 100, 2)
        message = "WARNING! This website shows strong signs of phishing. Do NOT enter any personal information!"
    
    return {
        "result": result,
        "display_result": display_result,
        "confidence": f"{confidence}%",
        "message": message,
        "analysis_time": f"{time.time() - start_time:.2f} seconds",
        "security_details": {
            "certificate": get_certificate_info(domain) if url.startswith("https") else {"has_ssl": False},
            "ip_info": get_ip_info(domain)
        },
        "html_features": {
            "has_login_form": feats.get('has_login_form', False),
            "num_scripts": feats.get('num_scripts', 0),
            "num_iframes": feats.get('num_iframes', 0)
        },
        "website_summary": website_summary
    }