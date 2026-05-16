import pickle
import requests
from features import extract_features
import pandas as pd

# Load model
with open("model.pkl", "rb") as f:
    model = pickle.load(f)

with open("feature_columns.pkl", "rb") as f:
    feature_columns = pickle.load(f)

print("=" * 60)
print("MODEL DEBUG - Checking what the model predicts")
print("=" * 60)

print(f"\nModel classes order: {model.classes_}")
print(f"Meaning: Class 0 = {model.classes_[0]}, Class 1 = {model.classes_[1]}")
print()

test_urls = [
    "https://github.com",
    "https://www.google.com",
]

for url in test_urls:
    print(f"\n--- Testing: {url} ---")
    feats = extract_features(url)
    df = pd.DataFrame([feats]).reindex(columns=feature_columns, fill_value=0)
    
    proba = model.predict_proba(df)[0]
    prediction = model.predict(df)[0]
    
    print(f"Feature values: {feats}")
    print(f"Probabilities: Class 0 = {proba[0]:.4f} ({proba[0]*100:.2f}%), Class 1 = {proba[1]:.4f} ({proba[1]*100:.2f}%)")
    print(f"Raw prediction (class index): {prediction}")
    print(f"Predicted class label: {model.classes_[prediction]}")
    
    # Determine what the prediction means
    if model.classes_[prediction] == 0:
        print(f"Model says: This URL belongs to class 0")
    else:
        print(f"Model says: This URL belongs to class 1")

        