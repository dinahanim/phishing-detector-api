# Import the extract_features function from train_model.py
from features import extract_features

# Test phishing-like site
url1 = "http://login-secure-bank.com"
print("Features for phishing-like site:")
print(extract_features(url1))

# Test safe site
url2 = "https://github.com"
print("\nFeatures for safe site:")
print(extract_features(url2))
