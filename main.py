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
    """Get IP address and location info"""
    try:
        ip = socket.gethostbyname(domain)
        return {"ip": ip, "country": "Unknown", "city": "Unknown", "asn": "Unknown", "org": "Unknown"}
    except Exception:
        return {"ip": "Unknown", "country": "Unknown", "city": "Unknown", "asn": "Unknown", "org": "Unknown"}

def is_educational_domain(domain: str) -> bool:
    """Check if domain is educational (.edu, .gov, .my, etc.) or university portal"""
    educational_patterns = [
        '.edu', '.gov', '.ac.', '.sch.', '.school',
        'student.', 'portal.', 'elearn', 'moodle', 'blackboard',
        'um.edu.my', 'ukm.edu.my', 'upm.edu.my', 'usm.edu.my', 'utm.edu.my',
        'uum.edu.my', 'unimas.edu.my', 'unisza.edu.my', 'uitm.edu.my'
    ]
    domain_lower = domain.lower()
    for pattern in educational_patterns:
        if pattern in domain_lower:
            return True
    return False

def check_url_accessible(url: str):
    """
    Check if URL is accessible - IMPROVED for legitimate websites.
    Also detects private/educational portals.
    """
    try:
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path
        domain = domain.split(':')[0]
        
        # First, check if domain resolves (DNS lookup)
        try:
            socket.gethostbyname(domain)
        except socket.gaierror:
            return False, 0, "Domain does not exist", False
        
        # Check if this is likely an educational/private portal
        is_private = is_educational_domain(domain)
        
        # Try HEAD request first
        try:
            response = requests.head(url, timeout=8, allow_redirects=True, headers={"User-Agent": "Mozilla/5.0"})
            status_code = response.status_code
        except:
            # If HEAD fails, try GET (some servers block HEAD)
            try:
                response = requests.get(url, timeout=10, allow_redirects=True, headers={"User-Agent": "Mozilla/5.0"}, stream=True)
                status_code = response.status_code
                response.close()
            except:
                return False, 0, "Cannot establish connection", is_private
        
        # Domain exists and server responded - consider it accessible
        return True, status_code, f"Server responded with HTTP {status_code}", is_private
        
    except requests.exceptions.Timeout:
        return False, 408, "Connection timeout", False
    except requests.exceptions.ConnectionError:
        return False, 0, "Cannot connect to server", False
    except Exception as e:
        return False, 0, str(e)[:100], False

# Trusted domains - always legitimate
TRUSTED_DOMAINS = [
    # Tech & General
    'github.com', 'microsoft.com', 'google.com', 'wikipedia.org', 
    'apple.com', 'amazon.com', 'facebook.com', 'twitter.com',
    'linkedin.com', 'youtube.com', 'netflix.com', 'spotify.com',
    'reddit.com', 'stackoverflow.com', 'gitlab.com', 'zoom.us',
    'slack.com', 'dropbox.com', 'cloudflare.com', 'adobe.com',
    
    # AI Websites
    'deepseek.com', 'chat.deepseek.com', 'deepseek.ai',
    'chatgpt.com', 'openai.com', 'chat.openai.com',
    'claude.ai', 'claude.com', 'anthropic.com',
    'perplexity.ai', 'gemini.google.com', 'bard.google.com',
    'copilot.microsoft.com', 'huggingface.co',
    
    # Malaysian Banks
    'maybank2u.com.my', 'cimbclicks.com.my', 'pbebank.com', 
    'rhbgroup.com', 'bankislam.com', 'ambank.com.my',
    'hongleongconnect.my', 'ocbc.com.my', 'uob.com.my',
    
    # Malaysian Government
    'kedah.gov.my', 'selangor.gov.my', 'johor.gov.my',
    'penang.gov.my', 'perak.gov.my', 'pahang.gov.my',
    'terengganu.gov.my', 'kelantan.gov.my', 'ns.gov.my',
    'melaka.gov.my', 'perlis.gov.my', 'sabah.gov.my',
    'sarawak.gov.my', 'putrajaya.gov.my', 'kualalumpur.gov.my',
    'hasil.gov.my', 'jpj.gov.my', 'jpn.gov.my', 'moe.gov.my',
    'moh.gov.my', 'kkmm.gov.my', 'mdec.my',
    
    # Universities
    'um.edu.my', 'ukm.edu.my', 'upm.edu.my', 'usm.edu.my',
    'utm.edu.my', 'uum.edu.my', 'unimas.edu.my', 'unisza.edu.my',
    'uitm.edu.my', 'uiam.edu.my', 'mmu.edu.my', 'taylors.edu.my',
    'sunway.edu.my', 'monash.edu.my', 'nottingham.edu.my',
    'curtin.edu.my', 'swinburne.edu.my', 'newcastle.edu.my'
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
    if not domain or '.' not in domain:
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
    
    # STEP 2: Check trusted domains first
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
                "certificate": get_certificate_info(domain) if url.startswith("https") else {"has_ssl": False, "issuer": "N/A", "expiry": "N/A"},
                "ip_info": get_ip_info(domain)
            },
            "html_features": html_features,
            "website_summary": website_summary
        }
    
    # STEP 3: Check if domain exists and is accessible
    is_accessible, status_code, status_message, is_private = check_url_accessible(url)
    
    # STEP 4: Special handling for educational/private portals
    if is_private or is_educational_domain(domain_lower):
        return {
            "result": "LEGITIMATE",
            "display_result": "PRIVATE / EDUCATIONAL PORTAL",
            "confidence": "90%",
            "message": "This appears to be an educational institution or private portal. Access may be restricted to authorized users only. The domain is legitimate.",
            "analysis_time": f"{time.time() - start_time:.2f} seconds",
            "security_details": {
                "certificate": get_certificate_info(domain) if url.startswith("https") else {"has_ssl": False, "issuer": "N/A", "expiry": "N/A"},
                "ip_info": get_ip_info(domain)
            },
            "html_features": {},
            "website_summary": f"This is a legitimate {domain} website. It may require login credentials for full access."
        }
    
    if not is_accessible:
        # Only truly unreachable (DNS failure, connection refused) come here
        return {
            "result": "UNREACHABLE",
            "display_result": "SUSPICIOUS - Page Unreachable",
            "confidence": "85%",
            "message": f"Cannot reach website: {status_message}",
            "analysis_time": f"{time.time() - start_time:.2f} seconds",
            "security_details": {},
            "html_features": {},
            "website_summary": "Unable to fetch website content - domain may not exist or server is down."
        }
    
    # STEP 5: Domain exists - proceed with ML analysis
    print(f"Domain accessible (HTTP {status_code}) - proceeding with ML analysis")
    
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
            "certificate": get_certificate_info(domain) if url.startswith("https") else {"has_ssl": False, "issuer": "N/A", "expiry": "N/A"},
            "ip_info": get_ip_info(domain)
        },
        "html_features": html_features,
        "website_summary": website_summary
    }