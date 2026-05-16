"""
Test SSL certificate extraction
Run: python test_ssl.py
"""

import asyncio
from security_features import check_certificate_info

async def test_ssl():
    print("=" * 60)
    print("Testing SSL Certificate Extraction")
    print("=" * 60)
    
    test_urls = [
        "https://www.google.com",
        "https://github.com", 
        "https://www.microsoft.com",
        "http://login-secure-bank.com",  # No SSL
    ]
    
    for url in test_urls:
        print(f"\n📡 Testing: {url}")
        result = await check_certificate_info(url)
        print(f"  Has SSL: {result.get('has_ssl', False)}")
        if result.get('has_ssl'):
            print(f"  Issuer: {result.get('issuer_cn', 'Unknown')}")
            print(f"  Days Valid: {result.get('days_valid', 'N/A')}")
            print(f"  Short Validity: {result.get('is_short_valid', False)}")
            print(f"  Free CA: {result.get('is_free_ca', False)}")
        else:
            print(f"  Error: {result.get('error', 'Unknown error')}")

if __name__ == "__main__":
    asyncio.run(test_ssl())