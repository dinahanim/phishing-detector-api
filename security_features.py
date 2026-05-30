"""
Advanced security features for phishing detection
"""

import ssl
import socket
import asyncio
import aiohttp
from datetime import datetime, timezone
from urllib.parse import urlparse
from cryptography import x509
from cryptography.hazmat.backends import default_backend

async def check_certificate_info(url: str):
    """Extract certificate details using SSL handshake only."""
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path
    domain = domain.split(':')[0]
    
    if not domain:
        return {"has_ssl": False, "error": "No domain found"}
    
    if url.startswith("http://"):
        return {"has_ssl": False, "error": "HTTP URL (no SSL)"}
    
    try:
        loop = asyncio.get_event_loop()
        cert_dict = await loop.run_in_executor(None, _get_certificate_sync, domain)
        
        if cert_dict:
            return {
                "has_ssl": True,
                "issuer": cert_dict.get("issuer", "Unknown"),
                "issuer_cn": cert_dict.get("issuer_cn", "Unknown"),
                "subject": cert_dict.get("subject", "Unknown"),
                "subject_cn": cert_dict.get("subject_cn", "Unknown"),
                "days_valid": str(cert_dict.get("days_valid", "Unknown")),
                "is_short_valid": cert_dict.get("days_valid", 365) <= 90,
                "is_free_ca": _is_free_certificate_authority(cert_dict.get("issuer", "")),
                "is_self_signed": cert_dict.get("self_signed", False),
                "expired": cert_dict.get("expired", False),
                "valid_from": cert_dict.get("valid_from", ""),
                "valid_until": cert_dict.get("valid_until", ""),
            }
        else:
            return {"has_ssl": False, "error": "No certificate found"}
    except Exception as e:
        return {"has_ssl": False, "error": str(e)}

def _get_certificate_sync(domain: str):
    """Synchronous certificate extraction"""
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                
                if not der_cert:
                    return None
                
                x509_cert = x509.load_der_x509_certificate(der_cert, default_backend())
                
                not_before = x509_cert.not_valid_before_utc
                not_after = x509_cert.not_valid_after_utc
                now_utc = datetime.now(timezone.utc)
                
                days_valid = (not_after - not_before).days
                is_expired = not_after < now_utc
                
                issuer_cn = ""
                for attr in x509_cert.issuer:
                    if attr.oid._name == "commonName":
                        issuer_cn = attr.value
                        break
                
                subject_cn = ""
                for attr in x509_cert.subject:
                    if attr.oid._name == "commonName":
                        subject_cn = attr.value
                        break
                
                return {
                    "issuer": str(x509_cert.issuer),
                    "issuer_cn": issuer_cn,
                    "subject": str(x509_cert.subject),
                    "subject_cn": subject_cn,
                    "self_signed": x509_cert.issuer == x509_cert.subject,
                    "days_valid": days_valid,
                    "expired": is_expired,
                    "valid_from": not_before.strftime("%Y-%m-%d"),
                    "valid_until": not_after.strftime("%Y-%m-%d"),
                }
    except Exception as e:
        return None

def _is_free_certificate_authority(issuer: str) -> bool:
    """Check if certificate is from a free CA"""
    free_cas = ["Let's Encrypt", "Google Trust Services", "ZeroSSL", "Buypass", "SSL.com Free", "Cloudflare"]
    issuer_lower = issuer.lower()
    for ca in free_cas:
        if ca.lower() in issuer_lower:
            return True
    return False

def quick_ssl_check(domain: str) -> dict:
    """Simple synchronous SSL check for basic features"""
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return {
                    "has_ssl": True,
                    "subject": dict(x[0] for x in cert.get('subject', [])),
                    "issuer": dict(x[0] for x in cert.get('issuer', [])),
                }
    except:
        return {"has_ssl": False}

async def get_ip_intelligence(url: str):
    """Get IP geolocation, ASN, company info"""
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path
    domain = domain.split(':')[0]
    
    if not domain:
        return {"error": "No domain found"}
    
    try:
        loop = asyncio.get_event_loop()
        ip_address = await loop.run_in_executor(None, socket.gethostbyname, domain)
        
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"https://api.ipapi.is?q={ip_address}",
                timeout=aiohttp.ClientTimeout(total=5)
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    raw_asn = data.get("asn", {}).get("asn")
                    raw_asn_name = data.get("asn", {}).get("name")
                    raw_company_name = data.get("company", {}).get("name")
                    return {
                        "ip": str(ip_address),
                        "domain": str(domain),
                        "country": str(data.get("location", {}).get("country", "Unknown")),
                        "city": str(data.get("location", {}).get("city", "Unknown")),
                        "asn": str(raw_asn) if raw_asn is not None else "Unknown",
                        "asn_name": str(raw_asn_name) if raw_asn_name is not None else "Unknown",
                        "company_name": str(raw_company_name) if raw_company_name is not None else "Unknown",
                        "is_datacenter": data.get("company", {}).get("type") == "hosting",
                        "is_vpn": data.get("privacy", {}).get("is_vpn", False),
                    }
    except Exception as e:
        return {"error": str(e)}
    
    return {"error": "Failed to get IP info"}

async def analyze_security(url: str):
    """Run all security checks concurrently"""
    cert_info, ip_intel = await asyncio.gather(
        check_certificate_info(url),
        get_ip_intelligence(url),
        return_exceptions=True
    )
    
    if isinstance(cert_info, Exception):
        cert_info = {"has_ssl": False, "error": str(cert_info)}
    if isinstance(ip_intel, Exception):
        ip_intel = {"error": str(ip_intel)}
    
    return {
        "certificate": cert_info,
        "ip_intelligence": ip_intel,
    }