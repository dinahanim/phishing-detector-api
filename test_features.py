# Import the extract_features function from train_model.py
from features import extract_features

# Test phishing-like site
url1 = "http://login-secure-bank.com"
print("Features for phishing-like site:")
feats1 = extract_features(url1)
print(feats1)
print("Website summary:", feats1.get('_website_summary', 'N/A'))

# Test safe site
url2 = "https://github.com"
print("\nFeatures for safe site:")
feats2 = extract_features(url2)
print(feats2)
print("Website summary:", feats2.get('_website_summary', 'N/A'))
