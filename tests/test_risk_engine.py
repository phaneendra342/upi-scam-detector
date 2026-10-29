"""
tests/test_risk_engine.py
Automated unit tests for Risk Score boundaries, deduplication, and SQLite privacy storage.
"""

from __future__ import annotations

import os
from modules.risk_engine import evaluate_risk, map_score_to_category
from modules.storage import (
    clear_history,
    get_privacy_audit_info,
    get_recent_scans,
    get_summary_metrics,
    save_scan_record,
)


def test_exact_score_category_boundaries():
    """Verify exact heuristic score boundaries: 0-24 Low, 25-49 Medium, 50-74 High, 75-100 Critical."""
    assert map_score_to_category(0) == "Low"
    assert map_score_to_category(24) == "Low"
    assert map_score_to_category(25) == "Medium"
    assert map_score_to_category(49) == "Medium"
    assert map_score_to_category(50) == "High"
    assert map_score_to_category(74) == "High"
    assert map_score_to_category(75) == "Critical"
    assert map_score_to_category(100) == "Critical"
    # Out-of-bounds clamping
    assert map_score_to_category(-15) == "Low"
    assert map_score_to_category(250) == "Critical"


def test_duplicate_indicators_and_concept_families_not_double_counted():
    """Passing identical codes or overlapping concept family rules must not inflate the score."""
    duplicate_indicators = [
        {
            "code": "URL_SHORTENER_SERVICE",
            "title": "Shortener 1",
            "severity": "MEDIUM",
            "weight": 28,
            "description": "Desc",
            "evidence": "bit.ly",
        },
        {
            "code": "URL_SHORTENER_SERVICE",
            "title": "Shortener Duplicate",
            "severity": "MEDIUM",
            "weight": 28,
            "description": "Desc",
            "evidence": "bit.ly",
        },
    ]
    report = evaluate_risk("URL", duplicate_indicators)
    assert report["risk_score"] == 28
    assert report["risk_category"] == "Medium"

    # Overlapping brand spoofing family rules
    overlapping_family = [
        {
            "code": "URL_BRAND_IMPERSONATION_DOMAIN",
            "title": "Brand Spoof",
            "severity": "CRITICAL",
            "weight": 55,
            "description": "Desc",
            "evidence": "Ev1",
        },
        {
            "code": "URL_TYPOSQUATTING_HOMOGLYPH",
            "title": "Homoglyph Spoof",
            "severity": "CRITICAL",
            "weight": 55,
            "description": "Desc",
            "evidence": "Ev2",
        },
    ]
    family_report = evaluate_risk("URL", overlapping_family)
    # Only one should contribute 55 weight (no +10 synergy because the 2nd had effective_weight=0)
    assert family_report["risk_score"] == 55
    assert family_report["risk_category"] == "High"


def test_score_capped_at_100_and_zero_score_limitation_warning():
    """Verify score caps at 100 and zero-score reports warn that safety is not guaranteed."""
    massive_indicators = [
        {"code": f"CRIT_{i}", "title": "Crit", "severity": "CRITICAL", "weight": 65, "description": "D", "evidence": "E"}
        for i in range(4)
    ]
    capped_report = evaluate_risk("SMS", massive_indicators)
    assert capped_report["risk_score"] == 100
    assert capped_report["risk_category"] == "Critical"

    zero_report = evaluate_risk("QR", [])
    assert zero_report["risk_score"] == 0
    assert "does NOT guarantee" in zero_report["confidence_explanation"]


def test_privacy_storage_lifecycle(tmp_path):
    """Verify SQLite storage saves only metadata, respects opt-out, and wipes cleanly."""
    db_file = str(tmp_path / "pytest_history.db")

    # 1. Save enabled record
    ok1 = save_scan_record("QR", 80, "Critical", 3, "QR_UPI_REFUND_RECEIVE_BAIT", enabled=True, db_path=db_file)
    assert ok1 is True

    # 2. Skip disabled record (opt-out)
    ok2 = save_scan_record("SMS", 90, "Critical", 4, "SMS_CREDENTIAL_HARVEST", enabled=False, db_path=db_file)
    assert ok2 is False

    scans = get_recent_scans(db_path=db_file)
    assert len(scans) == 1
    assert scans[0]["input_type"] == "QR"
    assert scans[0]["risk_score"] == 80

    metrics = get_summary_metrics(db_path=db_file)
    assert metrics["total_scans"] == 1
    assert metrics["high_risk_count"] == 1

    audit = get_privacy_audit_info(db_path=db_file)
    for forbidden_col in ("sms_text", "raw_url", "payee_vpa", "api_key"):
        assert forbidden_col not in audit["stored_columns"]

    assert clear_history(db_path=db_file) is True
    assert len(get_recent_scans(db_path=db_file)) == 0
    if os.path.exists(db_file):
        os.remove(db_file)