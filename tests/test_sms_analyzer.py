"""
tests/test_sms_analyzer.py
Automated unit tests for Context-Aware SMS Scam & Social Engineering detection.
"""

from __future__ import annotations

from modules.sms_analyzer import analyze_sms_message
from modules.risk_engine import evaluate_risk


def test_sms_requesting_otp_and_upi_pin():
    """Messages asking user to share OTP or enter UPI PIN must be flagged as CRITICAL."""
    msg = (
        "URGENT: Your HDFC Bank account will be suspended today due to incomplete KYC. "
        "Please share your 6-digit OTP or enter your UPI PIN at http://hdfc-kyc-verify.top to unblock."
    )
    res = analyze_sms_message(msg)
    codes = {i["code"] for i in res["indicators"]}

    assert "SMS_CREDENTIAL_HARVEST" in codes
    assert "SMS_URGENT_KYC_SUSPENSION" in codes
    assert "SMS_EMBEDDED_SUSPICIOUS_URL" in codes
    assert "SMS_AUTHORITY_IMPERSONATION" in codes

    report = evaluate_risk("SMS", res["indicators"])
    assert report["risk_category"] == "Critical"
    assert report["risk_score"] >= 75


def test_sms_fake_refund_and_scan_qr_to_receive_trap():
    """Messages claiming user can receive money by scanning a QR or approving collect request."""
    msg = (
        "Congratulations! You have won Rs. 2,500 cashback reward on PhonePe. "
        "Open the app and scan this QR code or approve the collect request to receive your cashback."
    )
    res = analyze_sms_message(msg)
    codes = {i["code"] for i in res["indicators"]}

    assert "SMS_FAKE_REWARD_REFUND_BAIT" in codes
    assert "SMS_QR_COLLECT_RECEIVE_TRAP" in codes


def test_sms_remote_access_app_and_fake_helpline():
    """Detect AnyDesk/TeamViewer installation requests and personal mobile helplines."""
    msg = (
        "Dear Consumer, your electricity power supply will be disconnected tonight at 9:30 PM. "
        "Download AnyDesk support app and call electricity officer at +91 9876543210 immediately."
    )
    res = analyze_sms_message(msg)
    codes = {i["code"] for i in res["indicators"]}

    assert "SMS_REMOTE_ACCESS_APP" in codes
    assert "SMS_URGENT_KYC_SUSPENSION" in codes
    assert "SMS_UNVERIFIED_HELPLINE_CALLBACK" in codes


def test_legitimate_bank_transaction_notification_not_flagged():
    """
    Standard bank debit/credit SMS containing a protective 'Never share OTP or UPI PIN'
    disclaimer must NOT trigger false-positive credential harvest alerts.
    """
    legit_sms = (
        "Rs. 640.00 debited from A/c XX4321 on 28-Oct-26 to VPA swiggy@axisbank "
        "(UPI Ref No 630199887766). Avl Bal: Rs. 18,210.50. "
        " SBI never asks for confidential info. Never share your OTP or UPI PIN with anyone."
    )
    res = analyze_sms_message(legit_sms)
    assert res["valid_input"] is True
    assert res["has_protective_disclaimer"] is True
    assert res["is_likely_transactional_notice"] is True
    assert res["indicators"] == []

    report = evaluate_risk("SMS", res["indicators"])
    assert report["risk_score"] == 0
    assert report["risk_category"] == "Low"


def test_empty_and_very_long_sms_inputs():
    """Handle blank SMS and safely truncate oversized (>5000 char) inputs."""
    empty_res = analyze_sms_message("")
    assert empty_res["valid_input"] is False

    huge_sms = "Normal payment text " * 300  # 6,000 characters
    huge_res = analyze_sms_message(huge_sms)
    assert huge_res["valid_input"] is True
    assert huge_res["char_count"] == 5000
    codes = {i["code"] for i in huge_res["indicators"]}
    assert "SMS_TRUNCATED_OVERSIZED" in codes