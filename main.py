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
    """Check if domain has proper format (contains dot, not just random characters)"""
    if not domain:
        return False
    # Must have at least one dot
    if '.' not in domain:
        return False
    # Must have at least 3 characters before the dot
    parts = domain.split('.')
    if len(parts) < 2:
        return False
    if len(parts[0]) < 2:
        return False
    # TLD must be at least 2 characters
    if len(parts[-1]) < 2:
        return False
    return True

def domain_exists(domain: str) -> bool:
    """Check if domain actually exists in DNS"""
    try:
        socket.gethostbyname(domain)
        return True
    except socket.gaierror:
        return False

def get_certificate_info(domain: str):
    """Get SSL certificate details"""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
                # Extract issuer as clean string
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
    """Get IP address and location info"""
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

# Trusted domains - always legitimate
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
    
    # STEP 1: Validate domain format (must be like "example.com", not just "h")
    if not is_valid_domain_format(domain_lower):
        print(f"INVALID DOMAIN FORMAT: {domain_lower}")
        return {
            "result": "INVALID",
            "display_result": "INVALID WEBSITE ADDRESS",
            "confidence": "95%",
            "message": "Please enter a valid website address (e.g., google.com, github.com)",
            "analysis_time": f"{time.time() - start_time:.2f} seconds",
            "security_details": {
                "certificate": {"has_ssl": False, "issuer": "N/A", "expiry": "N/A"},
                "ip_info": {"ip": "N/A", "country": "N/A", "city": "N/A", "asn": "N/A", "org": "N/A"}
            },
            "html_features": {},
            "website_summary": "Invalid domain format. Please enter a valid website address like 'example.com'."
        }
    
    # STEP 2: Check if domain actually exists in DNS
    if not domain_exists(domain_lower):
        print(f"DOMAIN DOES NOT EXIST: {domain_lower}")
        return {
            "result": "INVALID",
            "display_result": "WEBSITE DOES NOT EXIST",
            "confidence": "95%",
            "message": f"The domain '{domain}' does not exist. Please check the spelling and try again.",
            "analysis_time": f"{time.time() - start_time:.2f} seconds",
            "security_details": {
                "certificate": {"has_ssl": False, "issuer": "N/A", "expiry": "N/A"},
                "ip_info": {"ip": "N/A", "country": "N/A", "city": "N/A", "asn": "N/A", "org": "N/A"}
            },
            "html_features": {},
            "website_summary": f"The domain '{domain}' does not exist in the DNS system."
        }
    
    # STEP 3: Is this a trusted domain?
    is_trusted = any(td in domain_lower for td in TRUSTED_DOMAINS)
    
    if is_trusted:
        print(f"TRUSTED DOMAIN: {domain} -> LEGITIMATE")
        try:
            feats = extract_features(url)
            website_summary = feats.pop('_website_summary', "This is a well-known, trusted website.") if '_website_summary' in feats else "This is a well-known, trusted website."
        except:
            website_summary = "This is a well-known, trusted website."
        
        return {
            "result": "LEGITIMATE",
            "display_result": "LEGITIMATE",
            "confidence": "95%",
            "message": "This website appears to be legitimate based on our analysis.",
            "analysis_time": f"{time.time() - start_time:.2f} seconds",
            "security_details": {
                "certificate": get_certificate_info(domain) if url.startswith("https") else {"has_ssl": False, "issuer": "N/A", "expiry": "N/A"},
                "ip_info": get_ip_info(domain)
            },
            "html_features": {},
            "website_summary": website_summary
        }
    
    # STEP 4: Is the page accessible?
    is_accessible, status_code = check_url_accessible(url)
    
    if not is_accessible:
        return {
            "result": "UNREACHABLE",
            "display_result": "SUSPICIOUS - Page Unreachable",
            "confidence": "85%",
            "message": f"Page cannot be reached (Error {status_code})",
            "analysis_time": f"{time.time() - start_time:.2f} seconds",
            "security_details": {
                "certificate": get_certificate_info(domain) if url.startswith("https") else {"has_ssl": False, "issuer": "N/A", "expiry": "N/A"},
                "ip_info": get_ip_info(domain)
            },
            "html_features": {},
            "website_summary": "Unable to fetch website content - page unreachable."
        }
    
    # STEP 5: Run ML model for unknown domains
    feats = extract_features(url)
    website_summary = feats.pop('_website_summary', "No summary available.") if '_website_summary' in feats else "No summary available."
    
    # Clean up features
    for key in list(feats.keys()):
        if key.startswith('_'):
            feats.pop(key, None)
    
    df = pd.DataFrame([feats]).reindex(columns=feature_columns, fill_value=0)
    proba = model.predict_proba(df)[0]
    prediction = model.predict(df)[0]
    
    print(f"Raw prediction: {prediction}, Proba: {proba}")
    
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
            "certificate": get_certificate_info(domain) if url.startswith("https") else {"has_ssl": False, "issuer": "N/A", "expiry": "N/A"},
            "ip_info": get_ip_info(domain)
        },
        "html_features": {
            "has_login_form": feats.get('has_login_form', False),
            "num_scripts": feats.get('num_scripts', 0),
            "num_iframes": feats.get('num_iframes', 0)
        },
        "website_summary": website_summary
    }