"""
Test script for new security features
Run: python test_security.py
"""

import asyncio
from security_features import analyze_security

async def test():
    print("=" * 60)
    print("Testing Security Features")
    print("=" * 60)
    
    test_urls = [
        "https://www.google.com",
        "https://github.com",
        "http://login-secure-bank.com",  # Suspicious
        "https://www.microsoft.com",
    ]
    
    for url in test_urls:
        print(f"\n📡 Testing: {url}")
        print("-" * 40)
        
        result = await analyze_security(url)
        
        # Certificate info
        cert = result.get("certificate", {})
        print(f"  🔐 Has SSL: {cert.get('has_ssl', False)}")
        if cert.get('has_ssl'):
            print(f"     Issuer: {cert.get('issuer_cn', 'Unknown')}")
            print(f"     Days Valid: {cert.get('days_valid', 'N/A')}")
            print(f"     Short Validity (<90 days): {cert.get('is_short_valid', False)}")
            print(f"     Free CA: {cert.get('is_free_ca', False)}")
        
        # IP Intelligence
        ip = result.get("ip_intelligence", {})
        print(f"  🌍 Location: {ip.get('city', 'Unknown')}, {ip.get('country', 'Unknown')}")
        print(f"  🏢 ASN: {ip.get('asn', 'Unknown')} - {ip.get('asn_name', 'Unknown')}")
        print(f"  🏭 Hosting/Datacenter: {ip.get('is_datacenter', False)}")
        print(f"  🔒 VPN/Proxy: {ip.get('is_vpn', False)}")
        print(f"  🏢 Organization: {ip.get('company_name', 'Unknown')}")

if __name__ == "__main__":
    asyncio.run(test())