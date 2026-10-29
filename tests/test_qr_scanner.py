"""
tests/test_qr_scanner.py
Automated unit tests for QR code image validation, decoding, and UPI URI inspection.
Uses synthetic QR images generated in-memory via the qrcode and Pillow libraries.
"""

from __future__ import annotations

import io
import qrcode

from modules.qr_scanner import (
    analyze_qr_image_bytes,
    inspect_decoded_qr_payload,
    parse_upi_uri,
)
from modules.risk_engine import evaluate_risk


def _make_qr_png_bytes(payload: str) -> bytes:
    """Helper to generate a synthetic PNG QR image in memory."""
    img = qrcode.make(payload)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def test_valid_merchant_upi_qr_decoding_and_parsing():
    """Valid standard UPI URI should decode accurately and stay in Low risk category."""
    uri = "upi://pay?pa=freshmart.store@okaxis&pn=FreshMart%20Groceries&am=185.50&cu=INR&tn=Bill%20Payment"
    png_bytes = _make_qr_png_bytes(uri)

    result = analyze_qr_image_bytes(png_bytes, filename="merchant_qr.png")
    assert result["success"] is True
    assert result["decoded_text"] == uri

    inspection = result["inspection"]
    assert inspection["payload_type"] == "UPI_PAYMENT"
    upi = inspection["upi_details"]
    assert upi["payee_vpa"] == "freshmart.store@okaxis"
    assert upi["payee_name"] == "FreshMart Groceries"
    assert upi["amount"] == "185.50"
    assert upi["currency"] == "INR"

    # Evaluate risk: only a low pre-filled amount notice (+10) should appear -> Low risk
    report = evaluate_risk("QR", inspection["indicators"])
    assert report["risk_category"] == "Low"
    assert report["risk_score"] < 25


def test_scam_qr_refund_bait_and_authority_impersonation():
    """QR claiming 'Scan to receive SBI cashback refund' must trigger CRITICAL risk."""
    scam_uri = (
        "upi://pay?pa=fraudster881@ybl&pn=SBI%20Official%20Refund%20Desk"
        "&am=4999.00&cu=INR&tn=Scan%20QR%20to%20receive%20cashback%20refund"
    )
    png_bytes = _make_qr_png_bytes(scam_uri)

    result = analyze_qr_image_bytes(png_bytes, filename="refund_bait.png")
    assert result["success"] is True

    codes = {i["code"] for i in result["inspection"]["indicators"]}
    assert "QR_UPI_REFUND_RECEIVE_BAIT" in codes
    assert "QR_UPI_AUTHORITY_IMPERSONATION_NAME" in codes

    report = evaluate_risk("QR", result["inspection"]["indicators"])
    assert report["risk_category"] == "Critical"
    assert report["risk_score"] >= 75


def test_malformed_upi_qr_missing_vpa_and_invalid_amount():
    """Malformed UPI URI without 'pa' parameter must be flagged as critical."""
    malformed_uri = "upi://pay?pn=UnknownUser&am=abc&cu=USD"
    inspection = inspect_decoded_qr_payload(malformed_uri)

    codes = {i["code"] for i in inspection["indicators"]}
    assert "QR_UPI_MISSING_VPA" in codes
    assert "QR_UPI_MALFORMED_AMOUNT" in codes
    assert "QR_UPI_NON_INR_CURRENCY" in codes


def test_quishing_website_url_inside_qr():
    """QR code containing an external HTTP phishing link instead of upi://pay."""
    png_bytes = _make_qr_png_bytes("http://kyc-update-portal.xyz/login")
    result = analyze_qr_image_bytes(png_bytes, filename="quishing.png")

    assert result["success"] is True
    assert result["inspection"]["payload_type"] == "WEBSITE_URL"
    codes = {i["code"] for i in result["inspection"]["indicators"]}
    assert "QR_UNEXPECTED_WEB_URL" in codes
    assert "QR_INSECURE_HTTP_URL" in codes


def test_invalid_file_formats_and_empty_uploads():
    """Reject empty files, unsupported extensions, and corrupted non-image bytes."""
    # 1. Empty bytes
    empty_res = analyze_qr_image_bytes(b"", filename="empty.png")
    assert empty_res["success"] is False
    assert "empty" in empty_res["error"].lower()

    # 2. Invalid file extension (.exe / .pdf disguised)
    bad_ext = analyze_qr_image_bytes(b"fake_content", filename="malware.exe")
    assert bad_ext["success"] is False
    assert "unsupported file extension" in bad_ext["error"].lower()

    # 3. Corrupted binary bytes with .png extension
    corrupt_res = analyze_qr_image_bytes(b"not_a_real_png_header_12345", filename="corrupt.png")
    assert corrupt_res["success"] is False
    assert "corrupted" in corrupt_res["error"].lower() or "valid image" in corrupt_res["error"].lower()

    # 4. Oversized file limit check
    oversized_bytes = b"0" * (2 * 1024 * 1024)  # 2 MB
    over_res = analyze_qr_image_bytes(oversized_bytes, filename="huge.png", max_size_mb=1)
    assert over_res["success"] is False
    assert "exceeds" in over_res["error"].lower()


def test_parse_upi_uri_direct_fields():
    """Direct test of parse_upi_uri helper."""
    parsed = parse_upi_uri("upi://pay?pa=merchant@icici&pn=Test%20Shop&mc=5411&tr=TXN9988")
    assert parsed["payee_vpa"] == "merchant@icici"
    assert parsed["payee_name"] == "Test Shop"
    assert parsed["merchant_code"] == "5411"
    assert parsed["transaction_ref"] == "TXN9988"
    assert parsed["is_signed"] is False