"""
Test that HTML analysis happens in real-time for each URL
Run: python test_realtime.py
"""

import requests
import time

def test_realtime_analysis():
    print("=" * 60)
    print("TESTING REAL-TIME HTML ANALYSIS")
    print("=" * 60)
    
    test_urls = [
        "https://github.com",
        "https://www.google.com",
        "https://register.apl-id.com/1",
        "http://login-secure-bank.com",
    ]
    
    for url in test_urls:
        print(f"\n{'='*40}")
        print(f"Testing: {url}")
        print(f"{'='*40}")
        
        start_time = time.time()
        
        try:
            response = requests.post(
                "http://localhost:8000/predict",
                json={"url": url},
                timeout=30
            )
            
            elapsed = time.time() - start_time
            data = response.json()
            
            print(f"Response time: {elapsed:.2f} seconds")
            print(f"Result: {data.get('result')}")
            print(f"Confidence: {data.get('confidence')}")
            print(f"Analysis time reported: {data.get('analysis_time', 'N/A')}")
            
            if elapsed > 1:
                print("✅ PROOF: Real-time HTML fetch occurred (took >1 second)")
            else:
                print("⚠️ Very fast response - may be using cache")
                
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    test_realtime_analysis()