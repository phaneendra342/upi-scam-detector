"""
modules/url_analyzer.py
Defensive Payment Link & Phishing URL Analyzer.

Security Guarantees:
- Performs static URL parsing via urllib.parse without visiting untrusted targets.
- Prevents SSRF by detecting localhost, loopback, link-local, cloud metadata, and RFC1918 private IPs.
- Never treats HTTPS as proof of website legitimacy.
- Queries Google Safe Browsing API ONLY if GOOGLE_SAFE_BROWSING_API_KEY is explicitly configured
  and the target is a valid public host.
"""

from __future__ import annotations

import ipaddress
import os
import re
from difflib import SequenceMatcher
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, unquote, urlparse

import requests
from dotenv import load_dotenv

load_dotenv()

# ============================================================================
# Security Constants & Reference Dictionaries
# ============================================================================
MAX_URL_LENGTH = 2048

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rb.gy", "tiny.cc", "shorturl.at", "bitly.com", "rebrand.ly",
    "v.gd", "s.id", "bl.ink", "lnkd.in", "t.ly", "qr.ae"
}

SUSPICIOUS_TLDS = {
    "xyz", "top", "click", "link", "club", "work", "loan", "win", "gq",
    "tk", "ml", "cf", "ga", "zip", "mov", "icu", "buzz", "monster",
    "rest", "fit", "kim", "country", "stream", "download", "xin", "VIP".lower()
}

# Protected Indian Financial & Payment Brands -> Official Registrable Domains
PROTECTED_BRANDS: Dict[str, List[str]] = {
    "sbi": ["onlinesbi.sbi", "sbi.co.in", "sbicard.com", "yonobusiness.sbi"],
    "onlinesbi": ["onlinesbi.sbi", "sbi.co.in"],
    "hdfc": ["hdfcbank.com", "hdfc.com"],
    "hdfcbank": ["hdfcbank.com"],
    "icici": ["icicibank.com", "icicidirect.com"],
    "icicibank": ["icicibank.com"],
    "axis": ["axisbank.com", "axisbank.co.in"],
    "axisbank": ["axisbank.com", "axisbank.co.in"],
    "kotak": ["kotak.com", "kotak811.com"],
    "pnb": ["pnbindia.in", "netpnb.com"],
    "bob": ["bankofbaroda.in", "bobibanking.com"],
    "canarabank": ["canarabank.com", "canarabank.in"],
    "paytm": ["paytm.com", "paytmbank.com"],
    "phonepe": ["phonepe.com"],
    "googlepay": ["pay.google.com", "google.com"],
    "gpay": ["pay.google.com", "google.com"],
    "bhim": ["bhimupi.org.in", "npci.org.in"],
    "npci": ["npci.org.in", "bhimupi.org.in"],
    "razorpay": ["razorpay.com", "rzp.io"],
    "cashfree": ["cashfree.com"],
    "bharatpe": ["bharatpe.com"],
    "cred": ["cred.club"],
    "amazonpay": ["amazon.in", "amazon.com"],
    "mobikwik": ["mobikwik.com"],
    "freecharge": ["freecharge.in"],
    "rbi": ["rbi.org.in"],
}

PHISHING_URL_KEYWORDS = {
    "kyc", "verify", "verification", "update", "unblock", "suspend", "suspended",
    "refund", "cashback", "reward", "claim", "lottery", "bonus", "urgent",
    "secure-login", "netbanking", "validate", "pancard", "aadhaar", "reactivate",
    "reversal", "collect-approve", "pin-reset"
}

REDIRECT_QUERY_KEYS = {
    "url", "redirect", "redirect_uri", "redirect_url", "next", "dest",
    "destination", "return", "return_to", "goto", "out", "continue", "target"
}

LEET_TRANSLATION = str.maketrans({
    "0": "o",
    "1": "i",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "8": "b",
    "@": "a",
    "$": "s",
})


# ============================================================================
# Helper Functions
# ============================================================================
def _make_indicator(
    code: str,
    title: str,
    severity: str,
    weight: int,
    description: str,
    evidence: str,
) -> Dict[str, Any]:
    return {
        "code": code,
        "title": title,
        "severity": severity,
        "weight": weight,
        "description": description,
        "evidence": evidence,
    }


def _extract_registrable_domain(hostname: str) -> Tuple[str, str, str]:
    """
    Split a hostname into (subdomain, registrable_domain, tld).
    Handles common two-part Indian/UK suffixes like .co.in, .org.in, .gov.in, .ac.in.
    """
    host = hostname.lower().strip(".")
    if not host:
        return "", "", ""

    parts = host.split(".")
    if len(parts) == 1:
        return "", host, ""

    two_part_suffixes = {
        "co.in", "org.in", "gov.in", "ac.in", "net.in", "gen.in", "ind.in",
        "co.uk", "org.uk", "com.au", "co.jp"
    }

    last_two = ".".join(parts[-2:])
    if len(parts) >= 3 and last_two in two_part_suffixes:
        tld = last_two
        registrable = ".".join(parts[-3:])
        subdomain = ".".join(parts[:-3])
    else:
        tld = parts[-1]
        registrable = ".".join(parts[-2:])
        subdomain = ".".join(parts[:-2])

    return subdomain, registrable, tld


def _check_ip_and_ssrf_risk(hostname: str) -> Tuple[bool, bool, str]:
    """
    Check if hostname is an IP address and whether it targets private/loopback/metadata space.
    Returns (is_ip, is_private_or_reserved, reason_detail).
    """
    clean_host = hostname.strip("[]").lower()
    if clean_host in {"localhost", "localhost.localdomain", "metadata.google.internal"}:
        return False, True, f"Host '{clean_host}' resolves to local/internal infrastructure."

    try:
        ip_obj = ipaddress.ip_address(clean_host)
        if str(ip_obj) == "169.254.169.254":
            return True, True, "Cloud instance metadata IP address (169.254.169.254) — critical SSRF target."
        if ip_obj.is_loopback:
            return True, True, f"Loopback IP address ({ip_obj})."
        if ip_obj.is_private or ip_obj.is_link_local or ip_obj.is_reserved or ip_obj.is_multicast:
            return True, True, f"Private or reserved network IP address ({ip_obj})."
        return True, False, f"Public raw IP address ({ip_obj})."
    except ValueError:
        return False, False, ""


def _detect_brand_spoofing(hostname: str, registrable_domain: str) -> List[Dict[str, Any]]:
    """
    Detect brand impersonation via deceptive subdomains, hyphenated domains,
    homoglyph/leet substitutions, or close typosquatting.
    """
    findings: List[Dict[str, Any]] = []
    if not hostname or not registrable_domain:
        return findings

    # Collect all official domains across our protected list
    all_official_domains = {
        dom for dom_list in PROTECTED_BRANDS.values() for dom in dom_list
    }
    if registrable_domain in all_official_domains:
        return findings

    host_lower = hostname.lower()
    domain_label = registrable_domain.split(".")[0]  # e.g., 'paytm-kyc' or 'paytrn'
    normalized_label = domain_label.translate(LEET_TRANSLATION).replace("rn", "m").replace("vv", "w")

    for brand, official_domains in PROTECTED_BRANDS.items():
        # 1. Exact brand name appears in subdomain or hyphenated domain of an unofficial domain
        # Use word-boundary or substring check for brands >= 4 chars, strict boundary for 3-char brands
        if len(brand) >= 4:
            brand_in_host = brand in host_lower
        else:
            brand_in_host = bool(re.search(rf"(^|[.\-_]){re.escape(brand)}([.\-_]|$)", host_lower))

        if brand_in_host:
            findings.append(
                _make_indicator(
                    "URL_BRAND_IMPERSONATION_DOMAIN",
                    f"Deceptive Brand Impersonation Detected ('{brand.upper()}')",
                    "CRITICAL",
                    55,
                    f"This URL contains the financial brand '{brand.upper()}', but its actual registrable domain is '{registrable_domain}' instead of an official domain ({', '.join(official_domains)}).",
                    f"Host '{hostname}' is not an official {brand.upper()} domain",
                )
            )
            return findings

        # 2. Leet-speak / homoglyph substitution (e.g., paytrn, ph0nepe, sb1, hdfcbamk)
        clean_token = re.sub(r"[^a-z0-9]", "", normalized_label)
        if brand == clean_token and brand != domain_label:
            findings.append(
                _make_indicator(
                    "URL_TYPOSQUATTING_HOMOGLYPH",
                    f"Lookalike / Typosquatted Financial Domain ('{registrable_domain}')",
                    "CRITICAL",
                    55,
                    f"The domain '{registrable_domain}' uses visually deceptive character substitution to mimic '{brand.upper()}' ({', '.join(official_domains)}).",
                    f"Domain label '{domain_label}' mimics '{brand}'",
                )
            )
            return findings

        # 3. High edit-distance similarity for brands >= 5 chars (e.g., 'hdfcbamk', 'icicibnk', 'phonepee')
        if len(brand) >= 5 and len(domain_label) >= 4:
            similarity = SequenceMatcher(None, brand, domain_label).ratio()
            if 0.80 <= similarity < 1.0:
                findings.append(
                    _make_indicator(
                        "URL_TYPOSQUATTING_SIMILARITY",
                        f"Suspected Typosquatting Domain Resembling '{brand.upper()}'",
                        "HIGH",
                        45,
                        f"The domain '{registrable_domain}' is spelled very similarly to the protected financial brand '{brand.upper()}' ({', '.join(official_domains)}).",
                        f"'{domain_label}' closely resembles '{brand}' ({int(similarity * 100)}% match)",
                    )
                )
                return findings

    return findings


def check_google_safe_browsing(url_to_check: str) -> Dict[str, Any]:
    """
    Optional external reputation check via Google Safe Browsing API v4.
    Executes ONLY if GOOGLE_SAFE_BROWSING_API_KEY is configured in environment variables.
    Never sends requests if the key is absent.
    """
    api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
    if not api_key:
        return {
            "enabled": False,
            "queried": False,
            "malicious": False,
            "threats": [],
            "status_message": "Offline Heuristic Mode (Google Safe Browsing API key not configured).",
        }

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    payload = {
        "client": {"clientId": "upi-scam-detector", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url_to_check}],
        },
    }

    try:
        resp = requests.post(endpoint, json=payload, timeout=4.0)
        if resp.status_code == 200:
            data = resp.json()
            matches = data.get("matches", [])
            threat_types = sorted({m.get("threatType", "UNKNOWN") for m in matches})
            return {
                "enabled": True,
                "queried": True,
                "malicious": len(matches) > 0,
                "threats": threat_types,
                "status_message": (
                    f"Flagged by Google Safe Browsing: {', '.join(threat_types)}"
                    if matches
                    else "No known matches in Google Safe Browsing database."
                ),
            }
        return {
            "enabled": True,
            "queried": True,
            "malicious": False,
            "threats": [],
            "status_message": f"Safe Browsing API returned HTTP {resp.status_code}.",
        }
    except requests.RequestException as exc:
        return {
            "enabled": True,
            "queried": False,
            "malicious": False,
            "threats": [],
            "status_message": f"Safe Browsing lookup skipped safely ({type(exc).__name__}).",
        }


# ============================================================================
# Main URL Analysis Entry Point
# ============================================================================
def analyze_payment_url(raw_url: str) -> Dict[str, Any]:
    """
    Safely parse and analyze a payment URL or suspicious link without visiting it.
    Returns structured URL components, detected risk indicators, and reputation status.
    """
    cleaned_input = (raw_url or "").strip()
    indicators: List[Dict[str, Any]] = []

    if not cleaned_input:
        return {
            "valid_input": False,
            "error": "Please enter a URL or payment link to analyze.",
            "normalized_url": "",
            "components": {},
            "indicators": [],
            "reputation": {"enabled": False, "status_message": "No URL provided."},
            "https_notice": "HTTPS encryption alone never proves that a website is trustworthy.",
        }

    # Normalize missing scheme for user convenience while recording if scheme was absent
    has_explicit_scheme = bool(re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", cleaned_input))
    candidate_url = cleaned_input if has_explicit_scheme else f"http://{cleaned_input}"

    try:
        parsed = urlparse(candidate_url)
    except ValueError:
        return {
            "valid_input": False,
            "error": "The provided string is malformed and could not be parsed as a valid URL.",
            "normalized_url": cleaned_input[:200],
            "components": {},
            "indicators": [
                _make_indicator(
                    "URL_MALFORMED_SYNTAX",
                    "Malformed URL Structure",
                    "HIGH",
                    40,
                    "The URL contains invalid bracket or port syntax that violates RFC 3986.",
                    cleaned_input[:100],
                )
            ],
            "reputation": {"enabled": False, "status_message": "Skipped due to malformed URL."},
            "https_notice": "HTTPS encryption alone never proves that a website is trustworthy.",
        }

    scheme = (parsed.scheme or "").lower()
    hostname = (parsed.hostname or "").lower()
    path = parsed.path or "/"
    query = parsed.query or ""
    fragment = parsed.fragment or ""

    # Safely extract port
    try:
        port: Optional[int] = parsed.port
    except ValueError:
        port = -1

    if not hostname or ("." not in hostname and hostname != "localhost"):
        return {
            "valid_input": False,
            "error": "The input does not contain a valid domain name or host (e.g., https://example.com).",
            "normalized_url": cleaned_input[:200],
            "components": {},
            "indicators": [],
            "reputation": {"enabled": False, "status_message": "Invalid hostname."},
            "https_notice": "HTTPS encryption alone never proves that a website is trustworthy.",
        }

    subdomain, registrable_domain, tld = _extract_registrable_domain(hostname)
    is_ip, is_private_or_ssrf, ip_detail = _check_ip_and_ssrf_risk(hostname)

    # If the user pasted a upi://pay link into the URL analyzer, note it clearly
    if scheme == "upi":
        indicators.append(
            _make_indicator(
                "URL_IS_UPI_DEEP_LINK",
                "UPI Deep-Link URI Detected",
                "LOW",
                10,
                "This link uses the 'upi://' application scheme rather than a web browser URL.",
                f"Scheme: upi://{hostname}",
            )
        )

    # 1. Check for Dangerous Schemes
    if scheme not in {"http", "https", "upi"}:
        indicators.append(
            _make_indicator(
                "URL_DANGEROUS_SCHEME",
                f"Non-Standard or Dangerous URL Scheme ('{scheme}://')",
                "CRITICAL",
                65,
                f"Payment links should never use the '{scheme}:' protocol.",
                f"Scheme: {scheme}",
            )
        )

    # 2. Check for Unencrypted HTTP
    if scheme == "http":
        indicators.append(
            _make_indicator(
                "URL_INSECURE_HTTP",
                "Unencrypted HTTP Connection (No TLS/SSL)",
                "HIGH",
                30,
                "This link uses plain HTTP (or omitted 'https://'). Financial portals always enforce encrypted HTTPS connections.",
                f"Protocol: http:// on {hostname}",
            )
        )

    # 3. Check for Raw IP Host & SSRF / Internal Network Targets
    if is_private_or_ssrf:
        indicators.append(
            _make_indicator(
                "URL_SSRF_PRIVATE_OR_LOCAL_TARGET",
                "Internal, Loopback, or Cloud Metadata Network Target (SSRF Risk)",
                "CRITICAL",
                65,
                "This URL points to a private internal network, localhost, or cloud metadata address instead of a public financial service.",
                ip_detail,
            )
        )
    elif is_ip:
        indicators.append(
            _make_indicator(
                "URL_RAW_IP_HOST",
                "URL Hosted on Raw IP Address Instead of Domain Name",
                "CRITICAL",
                55,
                "Legitimate banks and payment providers use registered domain names, never raw IP addresses.",
                ip_detail,
            )
        )

    # 4. Check for Embedded Credentials (@ Trick)
    if parsed.username or parsed.password or "@" in parsed.netloc:
        indicators.append(
            _make_indicator(
                "URL_EMBEDDED_CREDENTIALS_AT_TRICK",
                "Deceptive '@' Credential Syntax in URL Authority",
                "CRITICAL",
                60,
                "Everything before the '@' symbol in a URL is treated as a username, allowing scammers to write a trusted bank name before '@' while sending you to the domain after '@'.",
                f"Netloc: {parsed.netloc}",
            )
        )

    # 5. Check for Unusual Ports
    if port == -1:
        indicators.append(
            _make_indicator(
                "URL_INVALID_PORT",
                "Malformed Network Port in URL",
                "HIGH",
                35,
                "The URL specifies an invalid network port number.",
                f"Netloc: {parsed.netloc}",
            )
        )
    elif port is not None and port not in {80, 443}:
        indicators.append(
            _make_indicator(
                "URL_UNUSUAL_PORT",
                f"Non-Standard Network Port (:{port})",
                "HIGH",
                35,
                f"Standard web links use port 443 (HTTPS) or 80 (HTTP). Port {port} is commonly used by temporary phishing servers.",
                f"Host: {hostname}:{port}",
            )
        )

    # 6. Check for URL Shorteners
    if not is_ip and (hostname in URL_SHORTENERS or registrable_domain in URL_SHORTENERS):
        indicators.append(
            _make_indicator(
                "URL_SHORTENER_SERVICE",
                "Link Destination Hidden Behind URL Shortener",
                "MEDIUM",
                28,
                "URL shorteners mask the true destination domain. Scammers frequently use shortened links in SMS phishing campaigns to hide malicious domains.",
                f"Shortener domain: {registrable_domain}",
            )
        )

    # 7. Check for Punycode / IDN Homograph Attack (xn--)
    if "xn--" in hostname:
        indicators.append(
            _make_indicator(
                "URL_PUNYCODE_IDN",
                "Internationalized Punycode Domain ('xn--') Detected",
                "HIGH",
                45,
                "This domain uses Punycode encoding ('xn--'), which can render non-Latin lookalike characters that visually mimic trusted bank domains.",
                f"Punycode host: {hostname}",
            )
        )

    # 8. Check for Brand Spoofing / Typosquatting
    if not is_ip:
        spoof_indicators = _detect_brand_spoofing(hostname, registrable_domain)
        indicators.extend(spoof_indicators)

    # 9. Check for Suspicious High-Abuse TLDs
    if not is_ip and tld in SUSPICIOUS_TLDS:
        indicators.append(
            _make_indicator(
                "URL_SUSPICIOUS_TLD",
                f"High-Risk Top-Level Domain ('.{tld}')",
                "MEDIUM",
                25,
                f"The '.{tld}' domain extension is inexpensive and disproportionately abused in disposable phishing and fake KYC campaigns.",
                f"Domain: {registrable_domain} (TLD: .{tld})",
            )
        )

    # 10. Check for Excessive Subdomains & Unusual URL Length
    subdomain_levels = [p for p in subdomain.split(".") if p] if subdomain else []
    if not is_ip and len(subdomain_levels) >= 3:
        indicators.append(
            _make_indicator(
                "URL_EXCESSIVE_SUBDOMAINS",
                f"Deep Subdomain Chain ({len(subdomain_levels)} Subdomain Levels)",
                "MEDIUM",
                22,
                "Attackers often chain multiple subdomains to push the real registrable domain off the right edge of mobile screens.",
                f"Subdomains: '{subdomain}' -> Real Domain: '{registrable_domain}'",
            )
        )

    if len(cleaned_input) > 150:
        indicators.append(
            _make_indicator(
                "URL_EXCESSIVE_LENGTH",
                f"Unusually Long URL ({len(cleaned_input)} characters)",
                "LOW",
                15,
                "Extremely long URLs are often used to hide redirect destinations or obfuscate phishing tokens.",
                f"Length: {len(cleaned_input)} chars",
            )
        )

    # 11. Check for Open Redirect Query Parameters & Heavy URL Encoding
    query_params = parse_qs(query, keep_blank_values=True)
    redirect_hits = [
        f"{k}={v[0][:40]}"
        for k, v in query_params.items()
        if k.lower() in REDIRECT_QUERY_KEYS and v
    ]
    if redirect_hits:
        indicators.append(
            _make_indicator(
                "URL_OPEN_REDIRECT_PARAM",
                "Redirect / Forwarding Parameter Found in URL",
                "MEDIUM",
                22,
                "This URL contains query parameters designed to redirect the browser to another destination.",
                f"Parameters: {', '.join(redirect_hits)}",
            )
        )

    percent_encoded_count = len(re.findall(r"%[0-9a-fA-F]{2}", cleaned_input))
    if percent_encoded_count >= 5:
        indicators.append(
            _make_indicator(
                "URL_HEAVY_OBFUSCATION_ENCODING",
                "Heavy URL Percent-Encoding Obfuscation",
                "MEDIUM",
                20,
                "The URL uses repeated '%XX' hex encoding, a technique frequently used to hide deceptive characters or scripts.",
                f"{percent_encoded_count} percent-encoded sequences found",
            )
        )

    # 12. Check for Urgent Phishing / Payment Bait Terms in URL Path or Host
    decoded_url_lower = unquote(cleaned_input).lower()
    matched_phishing_terms = sorted(
        [
            term
            for term in PHISHING_URL_KEYWORDS
            if re.search(rf"(^|[^a-z0-9]){re.escape(term)}([^a-z0-9]|$)", decoded_url_lower)
        ]
    )
    # Only flag keywords if the domain is NOT an official protected brand domain
    all_official_domains = {
        dom for dom_list in PROTECTED_BRANDS.values() for dom in dom_list
    }
    if matched_phishing_terms and registrable_domain not in all_official_domains:
        indicators.append(
            _make_indicator(
                "URL_PHISHING_BAIT_KEYWORDS",
                "Sensitive Banking / KYC / Refund Keywords in Unverified URL",
                "MEDIUM",
                25,
                "The URL contains urgent banking, KYC, or payment bait words on a domain that is not a verified financial institution.",
                f"Keywords: {', '.join(matched_phishing_terms)}",
            )
        )

    # 13. Optional Google Safe Browsing Lookup (ONLY if public host and key is configured)
    if not is_private_or_ssrf and scheme in {"http", "https"}:
        reputation = check_google_safe_browsing(candidate_url)
        if reputation.get("malicious"):
            indicators.append(
                _make_indicator(
                    "URL_SAFE_BROWSING_BLACKLISTED",
                    "Flagged as Dangerous by Google Safe Browsing Threat Intelligence",
                    "CRITICAL",
                    75,
                    "This URL matches active phishing or malware signatures in Google Safe Browsing.",
                    reputation.get("status_message", "Listed in Google Safe Browsing"),
                )
            )
    else:
        reputation = {
            "enabled": False,
            "queried": False,
            "malicious": False,
            "threats": [],
            "status_message": "External lookup blocked/skipped (non-public or non-HTTP target).",
        }

    components = {
        "scheme": scheme.upper(),
        "hostname": hostname,
        "subdomain": subdomain or "(none)",
        "registrable_domain": registrable_domain or hostname,
        "tld": f".{tld}" if tld else "(none)",
        "port": str(port) if port and port > 0 else ("443 (default)" if scheme == "https" else "80 (default)"),
        "path": path,
        "query_param_count": len(query_params),
        "is_https": scheme == "https",
        "is_ip_address": is_ip,
        "url_length": len(cleaned_input),
    }

    return {
        "valid_input": True,
        "error": None,
        "normalized_url": candidate_url,
        "components": components,
        "indicators": indicators,
        "reputation": reputation,
        "https_notice": (
            "Security Note: Even if a link starts with 'https://' and displays a padlock icon, "
            "that only means traffic is encrypted in transit—it does NOT mean the website owner is legitimate."
        ),
    }