import pandas as pd
import pickle
import requests
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from features import extract_features_from_html
from tqdm import tqdm
import urllib3
import numpy as np

urllib3.disable_warnings()

print("=" * 60)
print("RETRAINING MODEL WITH BETTER FEATURES")
print("=" * 60)

# Load dataset
df = pd.read_csv("malicious_urls.csv")
df = df[df['type'].isin(['benign', 'phishing'])]
df['label'] = df['type'].map({'benign': 0, 'phishing': 1})

# Balance dataset
min_count = df['label'].value_counts().min()
df_balanced = df.groupby('label', group_keys=False).apply(
    lambda x: x.sample(min_count, random_state=42)
)
df_balanced = df_balanced.sample(frac=1, random_state=42).reset_index(drop=True)
df_balanced = df_balanced.head(2000)  # Use 2000 URLs

print(f"Using {len(df_balanced)} URLs for training")

# Load or fetch HTML
import os
CACHE_FILE = "balanced_with_html.csv"
if os.path.exists(CACHE_FILE):
    df_balanced = pd.read_csv(CACHE_FILE)
    print("Loaded cached HTML")
else:
    print("Fetching HTML...")
    html_list = []
    for url in tqdm(df_balanced['url'], desc="Fetching"):
        try:
            response = requests.get(url, timeout=10, headers={"User-Agent": "Mozilla/5.0"}, verify=False)
            html_list.append(response.text)
        except:
            html_list.append("")
    df_balanced['html'] = html_list
    df_balanced.to_csv(CACHE_FILE, index=False)

# Extract features
print("Extracting features...")
data = []
for _, row in tqdm(df_balanced.iterrows(), total=len(df_balanced)):
    feats = extract_features_from_html(row['url'], row['html'])
    # Cap extreme values
    feats['num_scripts'] = min(feats['num_scripts'], 50)
    feats['num_iframes'] = min(feats['num_iframes'], 10)
    data.append(feats)

X = pd.DataFrame(data)
y = df_balanced['label'].values

# Remove constant columns
for col in X.columns:
    if X[col].nunique() <= 1:
        X = X.drop(columns=[col])

print(f"Features: {list(X.columns)}")

# Train/Test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

# Train Random Forest (better than Logistic Regression for this)
model = RandomForestClassifier(n_estimators=100, random_state=42, class_weight='balanced')
model.fit(X_train, y_train)

# Evaluate
accuracy = model.score(X_test, y_test)
print(f"Accuracy: {accuracy:.2%}")

# Save model
with open("model.pkl", "wb") as f:
    pickle.dump(model, f)

with open("feature_columns.pkl", "wb") as f:
    pickle.dump(X.columns.tolist(), f)

print("Model saved! Restart your backend.")