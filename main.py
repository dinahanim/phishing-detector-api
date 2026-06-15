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
import os

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
    """Get SSL certificate details"""
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
                issuer_str = " - ".join(issuer_parts) if issuer_parts else "Unknown"
                return {
                    "has_ssl": True,
                    "issuer": issuer_str,
                    "expiry": cert.get('notAfter', 'Unknown'),
                }
    except Exception:
        return {"has_ssl": False, "issuer": "N/A", "expiry": "N/A"}

def get_ip_info(domain: str):
    """Get IP address and location info - FIXED with fallback APIs"""
    try:
        # Step 1: Resolve domain to IP
        ip = socket.gethostbyname(domain)
        
        location_data = {"ip": ip, "country": "Unknown", "city": "Unknown", "asn": "Unknown", "org": "Unknown"}
        
        # Try ip-api.com first (fast, free, no key needed)
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,city,isp,org,as,query", timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    location_data = {
                        "ip": data.get('query', ip),
                        "country": data.get('country', 'Unknown'),
                        "city": data.get('city', 'Unknown'),
                        "asn": data.get('as', 'Unknown'),
                        "org": data.get('org', data.get('isp', 'Unknown'))
                    }
        except:
            pass
        
        # If ip-api.com failed, try ipapi.co (fallback)
        if location_data['country'] == 'Unknown':
            try:
                response = requests.get(f"https://ipapi.co/{ip}/json/", timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    location_data = {
                        "ip": ip,
                        "country": data.get('country_name', 'Unknown'),
                        "city": data.get('city', 'Unknown'),
                        "asn": data.get('asn', 'Unknown'),
                        "org": data.get('org', 'Unknown')
                    }
            except:
                pass
        
        return location_data
        
    except Exception as e:
        print(f"IP info error for {domain}: {e}")
        return {"ip": "Unknown", "country": "Unknown", "city": "Unknown", "asn": "Unknown", "org": "Unknown"}

def check_url_accessible(url: str):
    """Check if URL is accessible"""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path
        domain = domain.split(':')[0]
        
        # Check DNS resolution
        try:
            socket.gethostbyname(domain)
        except socket.gaierror:
            return False, 0, "Domain does not exist"
        
        # Try HEAD request
        try:
            response = requests.head(url, timeout=8, allow_redirects=True, headers={"User-Agent": "Mozilla/5.0"})
            status_code = response.status_code
        except:
            # If HEAD fails, try GET
            try:
                response = requests.get(url, timeout=10, allow_redirects=True, headers={"User-Agent": "Mozilla/5.0"}, stream=True)
                status_code = response.status_code
                response.close()
            except:
                return False, 0, "Cannot establish connection"
        
        return True, status_code, f"HTTP {status_code}"
        
    except requests.exceptions.Timeout:
        return False, 408, "Connection timeout"
    except requests.exceptions.ConnectionError:
        return False, 0, "Cannot connect to server"
    except Exception as e:
        return False, 0, str(e)[:100]

# Trusted domains - always legitimate
TRUSTED_DOMAINS = [
    'github.com', 'microsoft.com', 'google.com', 'wikipedia.org', 
    'apple.com', 'amazon.com', 'facebook.com', 'twitter.com',
    'linkedin.com', 'youtube.com', 'netflix.com', 'spotify.com',
    'reddit.com', 'stackoverflow.com', 'gitlab.com', 'zoom.us',
    'deepseek.com', 'chatgpt.com', 'openai.com', 'claude.ai',
    'maybank2u.com.my', 'cimbclicks.com.my', 'pbebank.com', 'rhbgroup.com',
    'kedah.gov.my', 'uum.edu.my', 'learning.uum.edu.my'
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
    
    # Validate domain format
    if not domain or '.' not in domain:
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
            "website_summary": "Invalid domain format."
        }
    
    # Get certificate and IP info (works for all domains)
    cert_info = get_certificate_info(domain) if url.startswith("https") else {"has_ssl": False, "issuer": "N/A", "expiry": "N/A"}
    ip_info = get_ip_info(domain)
    
    # Check trusted domains
    is_trusted = any(td in domain_lower for td in TRUSTED_DOMAINS)
    
    if is_trusted:
        print(f"TRUSTED DOMAIN: {domain} -> LEGITIMATE")
        try:
            feats = extract_features(url)
            website_summary = feats.pop('_website_summary', "This is a well-known, trusted website.") if '_website_summary' in feats else "This is a well-known, trusted website."
            html_features = {
                "has_login_form": feats.get('has_login_form', False),
                "num_scripts": feats.get('num_scripts', 0),
                "num_iframes": feats.get('num_iframes', 0)
            }
        except:
            website_summary = "This is a well-known, trusted website."
            html_features = {}
        
        return {
            "result": "LEGITIMATE",
            "display_result": "LEGITIMATE",
            "confidence": "95%",
            "message": "This website appears to be legitimate based on our analysis.",
            "analysis_time": f"{time.time() - start_time:.2f} seconds",
            "security_details": {
                "certificate": cert_info,
                "ip_info": ip_info
            },
            "html_features": html_features,
            "website_summary": website_summary
        }
    
    # Check if URL is accessible
    is_accessible, status_code, status_message = check_url_accessible(url)
    
    if not is_accessible:
        return {
            "result": "UNREACHABLE",
            "display_result": "SUSPICIOUS - Page Unreachable",
            "confidence": "85%",
            "message": f"Cannot reach website: {status_message}",
            "analysis_time": f"{time.time() - start_time:.2f} seconds",
            "security_details": {
                "certificate": cert_info,
                "ip_info": ip_info
            },
            "html_features": {},
            "website_summary": "Unable to fetch website content - domain may not exist or server is down."
        }
    
    # Run ML analysis for non-trusted accessible domains
    feats = extract_features(url)
    website_summary = feats.pop('_website_summary', "No summary available.") if '_website_summary' in feats else "No summary available."
    
    html_features = {
        "has_login_form": feats.get('has_login_form', False),
        "num_scripts": feats.get('num_scripts', 0),
        "num_iframes": feats.get('num_iframes', 0)
    }
    
    # Clean up features for DataFrame
    for key in list(feats.keys()):
        if key.startswith('_'):
            feats.pop(key, None)
    
    df = pd.DataFrame([feats]).reindex(columns=feature_columns, fill_value=0)
    proba = model.predict_proba(df)[0]
    prediction = model.predict(df)[0]
    
    print(f"ML prediction: {prediction}, Proba: {proba}")
    
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
            "certificate": cert_info,
            "ip_info": ip_info
        },
        "html_features": html_features,
        "website_summary": website_summary
    }


# For local testing
if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)