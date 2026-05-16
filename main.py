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

with open("model.pkl", "rb") as f:
    model = pickle.load(f)

with open("feature_columns.pkl", "rb") as f:
    feature_columns = pickle.load(f)

def get_certificate_info(domain: str):
    """Get SSL certificate details"""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
                issuer_dict = {}
                for item in cert.get('issuer', []):
                    for key, value in item:
                        issuer_dict[key] = value
                
                subject_dict = {}
                for item in cert.get('subject', []):
                    for key, value in item:
                        subject_dict[key] = value
                
                return {
                    "has_ssl": True,
                    "issuer": issuer_dict.get('organizationName', issuer_dict.get('commonName', 'Unknown')),
                    "subject": subject_dict.get('commonName', 'Unknown'),
                    "expiry": cert.get('notAfter', 'Unknown'),
                    "issued": cert.get('notBefore', 'Unknown'),
                }
    except Exception:
        return {"has_ssl": False, "issuer": "N/A", "subject": "N/A", "expiry": "N/A", "issued": "N/A"}

def get_ip_info(domain: str):
    """Get IP address and location info"""
    try:
        ip = socket.gethostbyname(domain)
        
        try:
            response = requests.get(f"https://ipapi.co/{ip}/json/", timeout=3)
            if response.status_code == 200:
                data = response.json()
                return {
                    "ip": ip,
                    "country": data.get('country_name', 'Unknown'),
                    "city": data.get('city', 'Unknown'),
                    "region": data.get('region', 'Unknown'),
                    "asn": data.get('asn', 'Unknown'),
                    "org": data.get('org', 'Unknown')
                }
        except:
            pass
        return {"ip": ip, "country": "Unknown", "city": "Unknown", "region": "Unknown", "asn": "Unknown", "org": "Unknown"}
    except Exception:
        return {"ip": "Unknown", "country": "Unknown", "city": "Unknown", "region": "Unknown", "asn": "Unknown", "org": "Unknown"}

def check_url_accessible(url: str):
    try:
        response = requests.head(url, timeout=8, allow_redirects=True, headers={"User-Agent": "Mozilla/5.0"})
        if response.status_code == 200:
            return True, response.status_code
        else:
            return False, response.status_code
    except:
        return False, 0

@app.post("/predict")
def predict(data: URLRequest):
    start_time = time.time()
    url = data.url
    
    print(f"\n{'='*50}")
    print(f"Analyzing: {url}")
    
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path
    domain = domain.split(':')[0]
    
    # Get security details
    if domain and url.startswith("https"):
        cert_info = get_certificate_info(domain)
        ip_info = get_ip_info(domain)
    else:
        cert_info = {"has_ssl": False, "issuer": "N/A", "subject": "N/A", "expiry": "N/A"}
        ip_info = {"ip": "Unknown", "country": "Unknown", "city": "Unknown", "asn": "Unknown", "org": "Unknown"}
    
    # Check if URL is accessible
    is_accessible, status_code = check_url_accessible(url)
    
    if not is_accessible:
        total_time = time.time() - start_time
        
        # Custom message based on status code
        if status_code == 404:
            custom_message = "Page not found (404). Legitimate pages should exist. This is suspicious."
        elif status_code == 403:
            custom_message = "Access forbidden (403). The site is blocking access."
        elif status_code == 500:
            custom_message = "Server error (500). Poorly configured or malicious."
        elif status_code == 0:
            custom_message = "Cannot reach the server. Domain may not exist."
        else:
            custom_message = f"Error {status_code}. Unusual for legitimate sites."
        
        return {
            "result": "UNREACHABLE",
            "display_result": "SUSPICIOUS - Page Unreachable",
            "confidence": "85%",
            "message": custom_message,
            "analysis_time": f"{total_time:.2f} seconds",
            "security_details": {
                "certificate": cert_info,
                "ip_info": ip_info
            }
        }
    
    # Extract features and run ML model
    feats = extract_features(url)
    df = pd.DataFrame([feats]).reindex(columns=feature_columns, fill_value=0)
    
    proba = model.predict_proba(df)[0]
    prediction = model.predict(df)[0]
    
    # INVERTED mapping (model was trained with swapped labels)
    if prediction == 0:
        result = "PHISHING"
        display_result = "PHISHING DETECTED"
        confidence = round(proba[0] * 100, 2)
        message = "WARNING! This website shows strong signs of phishing. Do NOT enter any personal information!"
    else:
        result = "LEGITIMATE"
        display_result = "LEGITIMATE"
        confidence = round(proba[1] * 100, 2)
        message = "This website appears to be legitimate based on our analysis."
    
    total_time = time.time() - start_time
    
    return {
        "result": result,
        "display_result": display_result,
        "confidence": f"{confidence}%",
        "message": message,
        "analysis_time": f"{total_time:.2f} seconds",
        "security_details": {
            "certificate": cert_info,
            "ip_info": ip_info
        },
        "html_features": {
            "has_login_form": feats.get('has_login_form', False),
            "num_scripts": feats.get('num_scripts', 0),
            "num_iframes": feats.get('num_iframes', 0)
        }
    }