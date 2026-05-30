import re
import requests
from bs4 import BeautifulSoup
from bs4 import XMLParsedAsHTMLWarning
import warnings
from datetime import datetime

warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)

def extract_website_description(html: str, url: str) -> str:
    """Extract meaningful description/summary from website HTML"""
    if not html:
        return "Unable to fetch website content."
    
    try:
        soup = BeautifulSoup(html, 'html.parser')
        
        # Priority 1: Meta description
        meta_desc = soup.find('meta', attrs={'name': 'description'})
        if meta_desc and meta_desc.get('content'):
            desc = meta_desc['content'].strip()
            if len(desc) > 30:
                return desc[:400] + "..." if len(desc) > 400 else desc
        
        # Priority 2: Open Graph description
        og_desc = soup.find('meta', attrs={'property': 'og:description'})
        if og_desc and og_desc.get('content'):
            desc = og_desc['content'].strip()
            if len(desc) > 30:
                return desc[:400] + "..." if len(desc) > 400 else desc
        
        # Priority 3: Page title
        if soup.title and soup.title.string:
            title = soup.title.string.strip()
            if len(title) > 10:
                return title
        
        # Priority 4: First meaningful paragraph
        main_content = soup.find('main') or soup.find('article') or soup.find('body')
        if main_content:
            paragraphs = main_content.find_all('p')
            for p in paragraphs:
                text = p.get_text().strip()
                if len(text) > 80:
                    return text[:400] + "..." if len(text) > 400 else text
        
        return "No descriptive summary available for this website."
        
    except Exception:
        return "Unable to generate website summary."

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
    
    website_summary = "Unable to fetch website content."
    
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        response = requests.get(url, timeout=15, headers=headers, verify=False)
        html = response.text
        soup = BeautifulSoup(html, 'html.parser')
        
        # Extract website summary
        website_summary = extract_website_description(html, url)
        print(f"[SUMMARY] Generated summary: {website_summary[:100]}...")
        
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
        website_summary = "Unable to fetch website content."
    
    print(f"{'='*60}\n")
    
    # Add summary to features
    features['_website_summary'] = website_summary
    
    return features