"""
tests/test_url_analyzer.py
Automated unit tests for Payment Link & Phishing URL static analysis.
"""

from __future__ import annotations

from modules.url_analyzer import analyze_payment_url
from modules.risk_engine import evaluate_risk


def test_legitimate_https_bank_urls_have_zero_false_positives():
    """Official HTTPS domains for SBI, HDFC, and Paytm should trigger zero threat indicators."""
    for official_url in [
        "https://www.onlinesbi.sbi/personal/",
        "https://netbanking.hdfcbank.com/netbanking/",
        "https://paytm.com/recharge",
    ]:
        res = analyze_payment_url(official_url)
        assert res["valid_input"] is True
        assert res["indicators"] == []
        report = evaluate_risk("URL", res["indicators"])
        assert report["risk_score"] == 0
        assert report["risk_category"] == "Low"


def test_suspicious_lookalike_and_brand_impersonation_domains():
    """Detect brand spoofing in subdomains, hyphenated domains, and homoglyph typosquatting."""
    # 1. Subdomain & hyphenated brand spoofing + suspicious TLD
    res1 = analyze_payment_url("https://sbi-kyc.update-account.xyz/verify")
    codes1 = {i["code"] for i in res1["indicators"]}
    assert "URL_BRAND_IMPERSONATION_DOMAIN" in codes1
    assert "URL_SUSPICIOUS_TLD" in codes1
    assert "URL_PHISHING_BAIT_KEYWORDS" in codes1

    # 2. Homoglyph / character substitution ('paytrn.com' mimicking 'paytm.com')
    res2 = analyze_payment_url("https://paytrn.com/refund-claim")
    codes2 = {i["code"] for i in res2["indicators"]}
    assert "URL_TYPOSQUATTING_HOMOGLYPH" in codes2


def test_ip_based_urls_and_ssrf_protection():
    """Detect public raw IP hosts and block/flag internal SSRF targets."""
    # Public IP host over HTTP with unusual port
    public_ip_res = analyze_payment_url("http://103.45.67.89:8443/collect-payment")
    pub_codes = {i["code"] for i in public_ip_res["indicators"]}
    assert "URL_RAW_IP_HOST" in pub_codes
    assert "URL_INSECURE_HTTP" in pub_codes
    assert "URL_UNUSUAL_PORT" in pub_codes

    # Cloud Metadata SSRF target (169.254.169.254)
    ssrf_res = analyze_payment_url("http://169.254.169.254/latest/meta-data/")
    ssrf_codes = {i["code"] for i in ssrf_res["indicators"]}
    assert "URL_SSRF_PRIVATE_OR_LOCAL_TARGET" in ssrf_codes
    assert ssrf_res["reputation"]["queried"] is False


def test_url_shorteners_and_open_redirects():
    """Flag shortened links and redirect query parameters."""
    short_res = analyze_payment_url("https://bit.ly/3FakeRefundLink?redirect=http://evil.top")
    codes = {i["code"] for i in short_res["indicators"]}
    assert "URL_SHORTENER_SERVICE" in codes
    assert "URL_OPEN_REDIRECT_PARAM" in codes


def test_embedded_credentials_punycode_and_long_urls():
    """Flag user@host credential tricks, xn-- punycode, and excessively long URLs."""
    long_padding = "a" * 180
    tricky_url = f"https://onlinesbi.sbi@xn--80ak6aa92e.top/login?token={long_padding}"
    res = analyze_payment_url(tricky_url)
    codes = {i["code"] for i in res["indicators"]}

    assert "URL_EMBEDDED_CREDENTIALS_AT_TRICK" in codes
    assert "URL_PUNYCODE_IDN" in codes
    assert "URL_EXCESSIVE_LENGTH" in codes


def test_empty_and_invalid_url_inputs():
    """Gracefully handle empty string and non-domain gibberish."""
    empty_res = analyze_payment_url("   ")
    assert empty_res["valid_input"] is False

    invalid_host = analyze_payment_url("just_a_single_word_without_dot")
    assert invalid_host["valid_input"] is False