import re
import requests
from bs4 import BeautifulSoup
from bs4 import XMLParsedAsHTMLWarning
import warnings
from datetime import datetime

warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)

def extract_features_from_html(url, html):
    features = {}
    features['url_length'] = len(url)
    features['num_dots'] = url.count('.')
    features['num_hyphens'] = url.count('-')
    features['num_slashes'] = url.count('/')
    features['https'] = 1 if url.startswith("https") else 0
    features['has_ip'] = 1 if re.match(r'http[s]?://\d+\.\d+\.\d+\.\d+', url) else 0
    
    if html:
        try:
            soup = BeautifulSoup(html, 'html.parser')
            features['has_login_form'] = 1 if soup.find('input', {'type': 'password'}) else 0
            title = ""
            if soup.title:
                title_text = soup.title.string
                if title_text:
                    title = title_text.lower()
            features['title_login'] = 1 if any(word in title for word in ['login', 'signin', 'verify']) else 0
            features['num_scripts'] = min(len(soup.find_all('script')), 100)
            features['num_iframes'] = min(len(soup.find_all('iframe')), 50)
        except:
            features['has_login_form'] = 0
            features['title_login'] = 0
            features['num_scripts'] = 0
            features['num_iframes'] = 0
    else:
        features['has_login_form'] = 0
        features['title_login'] = 0
        features['num_scripts'] = 0
        features['num_iframes'] = 0
    
    return features

def extract_features(url):
    features = {}
    
    print(f"\n{'='*60}")
    print(f"[REAL-TIME HTML ANALYSIS] Fetching: {url}")
    print(f"[TIME] {datetime.now().strftime('%H:%M:%S')}")
    print(f"{'='*60}")
    
    features['url_length'] = len(url)
    features['num_dots'] = url.count('.')
    features['num_hyphens'] = url.count('-')
    features['num_slashes'] = url.count('/')
    features['https'] = 1 if url.startswith("https") else 0
    features['has_ip'] = 1 if re.match(r'http[s]?://\d+\.\d+\.\d+\.\d+', url) else 0
    
    print(f"[URL ANALYSIS] Length: {features['url_length']}")
    print(f"[URL ANALYSIS] HTTPS: {features['https'] == 1}")
    
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(url, timeout=10, headers=headers, verify=False)
        html = response.text
        soup = BeautifulSoup(html, 'html.parser')
        
        features['has_login_form'] = 1 if soup.find('input', {'type': 'password'}) else 0
        title = ""
        if soup.title:
            title_text = soup.title.string
            if title_text:
                title = title_text.lower()
        features['title_login'] = 1 if any(word in title for word in ['login', 'signin', 'verify']) else 0
        features['num_scripts'] = len(soup.find_all('script'))
        features['num_iframes'] = len(soup.find_all('iframe'))
        
        print(f"[HTML ANALYSIS] Has login form: {features['has_login_form'] == 1}")
        print(f"[HTML ANALYSIS] Scripts found: {features['num_scripts']}")
        
    except Exception as e:
        print(f"[ERROR] HTML fetch failed: {str(e)[:100]}")
        features['has_login_form'] = 0
        features['title_login'] = 0
        features['num_scripts'] = 0
        features['num_iframes'] = 0
    
    print(f"{'='*60}\n")
    return features