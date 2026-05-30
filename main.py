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

def get_certificate_info(domain: str):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                issuer_dict = {}
                for item in cert.get('issuer', []):
                    for key, value in item:
                        issuer_dict[key] = value
                return {
                    "has_ssl": True,
                    "issuer": issuer_dict.get('organizationName', issuer_dict.get('commonName', 'Unknown')),
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
    
    # CHECK 1: Is this a trusted domain?
    is_trusted = any(td in domain_lower for td in TRUSTED_DOMAINS)
    
    if is_trusted:
        print(f"TRUSTED DOMAIN: {domain} -> LEGITIMATE")
        # Still try to get summary
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
                "certificate": get_certificate_info(domain) if url.startswith("https") else {"has_ssl": False},
                "ip_info": get_ip_info(domain)
            },
            "html_features": {},
            "website_summary": website_summary
        }
    
    # CHECK 2: Is the page accessible?
    is_accessible, status_code = check_url_accessible(url)
    
    if not is_accessible:
        return {
            "result": "UNREACHABLE",
            "display_result": "SUSPICIOUS - Page Unreachable",
            "confidence": "85%",
            "message": f"Page cannot be reached (Error {status_code})",
            "analysis_time": f"{time.time() - start_time:.2f} seconds",
            "security_details": {
                "certificate": get_certificate_info(domain) if url.startswith("https") else {"has_ssl": False},
                "ip_info": get_ip_info(domain)
            },
            "html_features": {},
            "website_summary": "Unable to fetch website content - page unreachable."
        }
    
    # CHECK 3: Run ML model for unknown domains
    feats = extract_features(url)
    website_summary = feats.pop('_website_summary', "No summary available.") if '_website_summary' in feats else "No summary available."
    
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