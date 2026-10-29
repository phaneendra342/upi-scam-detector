"""
modules/risk_engine.py
Transparent, Rule-Based Cybersecurity Risk Scoring Engine.

Design Principles:
- Deduplicates repeated indicator codes and overlapping concept families so the
  same underlying issue is never counted multiple times.
- Maps scores deterministically to Low (0-24), Medium (25-49), High (50-74),
  and Critical (75-100).
- Provides non-color-dependent accessible labels and severity icons.
- Explicitly explains evidence quality, confidence, and heuristic limitations
  (including why a score of 0 never guarantees recipient legitimacy).
"""

from __future__ import annotations

from typing import Any, Dict, List

# ============================================================================
# Severity Ordering & Concept Families for Deduplication
# ============================================================================
SEVERITY_RANK = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}

# Indicators in the same concept group represent the same underlying threat family.
# Only the highest-weight indicator within a concept group contributes full weight;
# any secondary indicator in the same group is prevented from inflating the score.
CONCEPT_FAMILY_MAP = {
    "URL_BRAND_IMPERSONATION_DOMAIN": "BRAND_SPOOFING",
    "URL_TYPOSQUATTING_HOMOGLYPH": "BRAND_SPOOFING",
    "URL_TYPOSQUATTING_SIMILARITY": "BRAND_SPOOFING",
    "QR_UPI_REFUND_RECEIVE_BAIT": "RECEIVE_MONEY_DECEPTION",
    "SMS_QR_COLLECT_RECEIVE_TRAP": "RECEIVE_MONEY_DECEPTION",
    "URL_INSECURE_HTTP": "INSECURE_TRANSPORT",
    "QR_INSECURE_HTTP_URL": "INSECURE_TRANSPORT",
}

CATEGORY_STYLES = {
    "Low": {
        "color": "#22C55E",
        "badge_text": "LOW RISK",
        "accessible_symbol": "[OK / LOW RISK]",
        "headline": "No high-severity technical scam patterns were triggered, but standard verification is still required.",
    },
    "Medium": {
        "color": "#F59E0B",
        "badge_text": "MEDIUM RISK",
        "accessible_symbol": "[CAUTION / MEDIUM RISK]",
        "headline": "Caution advised: One or more unusual or unverifiable payment characteristics were detected.",
    },
    "High": {
        "color": "#F97316",
        "badge_text": "HIGH RISK",
        "accessible_symbol": "[WARNING / HIGH RISK]",
        "headline": "High Risk: Multiple suspicious indicators associated with payment phishing or social engineering were found.",
    },
    "Critical": {
        "color": "#EF4444",
        "badge_text": "CRITICAL RISK",
        "accessible_symbol": "[DANGER / CRITICAL RISK]",
        "headline": "Critical Risk: Strong indicators of a payment scam or credential theft attempt. Do NOT proceed.",
    },
}


# ============================================================================
# Core Scoring Functions
# ============================================================================
def map_score_to_category(score: int) -> str:
    """
    Map a 0-100 numeric score to its heuristic category:
    - 0-24: Low
    - 25-49: Medium
    - 50-74: High
    - 75-100: Critical
    """
    clamped = max(0, min(100, int(score)))
    if clamped <= 24:
        return "Low"
    if clamped <= 49:
        return "Medium"
    if clamped <= 74:
        return "High"
    return "Critical"


def deduplicate_indicators(raw_indicators: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Deduplicate indicators by exact code and by underlying concept family.
    Sorts final indicators from highest severity/weight to lowest.
    """
    by_code: Dict[str, Dict[str, Any]] = {}
    for ind in raw_indicators or []:
        code = str(ind.get("code", "UNKNOWN_INDICATOR"))
        weight = int(ind.get("weight", 0))
        if code not in by_code or weight > int(by_code[code].get("weight", 0)):
            by_code[code] = dict(ind)

    # Sort by severity rank descending, then weight descending
    unique_list = sorted(
        by_code.values(),
        key=lambda x: (
            SEVERITY_RANK.get(str(x.get("severity", "INFO")).upper(), 0),
            int(x.get("weight", 0)),
        ),
        reverse=True,
    )

    seen_families: set[str] = set()
    final_indicators: List[Dict[str, Any]] = []

    for item in unique_list:
        code = item.get("code", "")
        family = CONCEPT_FAMILY_MAP.get(code)
        if family:
            if family in seen_families:
                # Keep the indicator visible as supporting evidence with effective_weight = 0
                item["effective_weight"] = 0
                item["deduplicated_note"] = (
                    f"Grouped under '{family}' to avoid counting the same threat twice."
                )
            else:
                seen_families.add(family)
                item["effective_weight"] = int(item.get("weight", 0))
                item["deduplicated_note"] = None
        else:
            item["effective_weight"] = int(item.get("weight", 0))
            item["deduplicated_note"] = None

        final_indicators.append(item)

    return final_indicators


def _build_recommendations(
    input_type: str,
    category: str,
    indicators: List[Dict[str, Any]],
) -> List[str]:
    """Generate actionable, context-specific safety steps for the user."""
    codes = {i.get("code", "") for i in indicators}
    recs: List[str] = []

    # Specific targeted advice based on exact indicators triggered
    if "QR_UPI_REFUND_RECEIVE_BAIT" in codes or "SMS_QR_COLLECT_RECEIVE_TRAP" in codes:
        recs.append(
            "NEVER scan a QR code or enter your UPI PIN to 'receive' a refund, cashback, or prize. Entering a UPI PIN only deducts money from your bank account."
        )

    if "SMS_CREDENTIAL_HARVEST" in codes:
        recs.append(
            "Do NOT share your OTP, UPI PIN, ATM PIN, or CVV with anyone. Banks, NPCI, and RBI never ask for these credentials via call, SMS, or link."
        )

    if "SMS_REMOTE_ACCESS_APP" in codes:
        recs.append(
            "Do NOT install AnyDesk, TeamViewer, QuickSupport, or any '.apk' file sent via SMS or WhatsApp. If already installed, uninstall it immediately and disconnect from the internet."
        )

    if any(
        c in codes
        for c in (
            "URL_BRAND_IMPERSONATION_DOMAIN",
            "URL_TYPOSQUATTING_HOMOGLYPH",
            "URL_TYPOSQUATTING_SIMILARITY",
            "SMS_EMBEDDED_SUSPICIOUS_URL",
            "QR_UNEXPECTED_WEB_URL",
        )
    ):
        recs.append(
            "Do NOT click or log in through this link. Open your official banking app directly from your phone screen or manually type the bank's official domain in your browser."
        )

    if "SMS_URGENT_KYC_SUSPENSION" in codes or "SMS_UNVERIFIED_HELPLINE_CALLBACK" in codes:
        recs.append(
            "Do NOT call phone numbers written inside suspicious SMS messages. Look up your bank's official toll-free customer care number on the back of your debit card or official website."
        )

    if input_type.upper() == "QR":
        recs.append(
            "Remember that the Payee Name ('pn') inside a QR code can be faked. Before entering your PIN, confirm the recipient's verified banking name inside your UPI app and verify with the merchant in person."
        )

    # Category-level escalation guidance
    if category in {"High", "Critical"}:
        recs.append(
            "Block and report the sender immediately. If you have lost money or shared sensitive details, call India's National Cyber Crime Helpline at 1930 or file a report at https://cybercrime.gov.in immediately."
        )
    elif category == "Medium":
        recs.append(
            "Pause and verify the payment request with the intended recipient through an independent, trusted phone call before authorizing any transfer."
        )
    else:
        recs.append(
            "Even with a Low technical risk score, always double-check the exact recipient UPI ID (VPA) and amount inside your UPI app before entering your PIN."
        )

    return recs


def _build_confidence_explanation(
    input_type: str,
    score: int,
    indicators: List[Dict[str, Any]],
) -> str:
    """Explain the evidence quality and limitations of heuristic static analysis."""
    active_indicators = [i for i in indicators if int(i.get("effective_weight", 0)) > 0]
    high_or_crit = [
        i for i in active_indicators if i.get("severity") in {"HIGH", "CRITICAL"}
    ]

    if len(high_or_crit) >= 2:
        evidence_quality = (
            "High Evidence Confidence: Multiple independent high-severity fraud patterns "
            f"({len(high_or_crit)} critical/high indicators) corroborate this risk assessment."
        )
    elif len(active_indicators) >= 1:
        evidence_quality = (
            f"Moderate Evidence Confidence: {len(active_indicators)} rule-based heuristic indicator(s) "
            "matched known phishing or payment scam characteristics."
        )
    else:
        evidence_quality = (
            "Baseline Heuristic Check Only: No known syntactic phishing or social engineering rules "
            "triggered on this input."
        )

    limitation_note = (
        " Limitation Notice: These score thresholds (0-24 Low, 25-49 Medium, 50-74 High, 75-100 Critical) "
        "are heuristic educational weights, not statistical probabilities. A score of 0 does NOT guarantee "
        "that a payee or website is genuine—for example, a scammer's personal UPI QR code can be technically "
        "well-formed while still belonging to an impostor."
    )
    return evidence_quality + limitation_note


# ============================================================================
# Main Risk Evaluation Entry Point
# ============================================================================
def evaluate_risk(
    input_type: str,
    raw_indicators: List[Dict[str, Any]],
    context_metadata: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    """
    Calculate a transparent, deduplicated 0-100 risk score and complete assessment report.

    Parameters:
        input_type: "QR", "URL", or "SMS"
        raw_indicators: List of indicator dicts produced by an analyzer module
        context_metadata: Optional extra context from the analyzer
    """
    deduped = deduplicate_indicators(raw_indicators or [])

    base_score = sum(int(i.get("effective_weight", 0)) for i in deduped)

    # Multi-threat synergy bonus: if 2 or more independent HIGH/CRITICAL threats co-occur,
    # add a +10 compound risk bonus before capping at 100.
    active_high_crit = [
        i
        for i in deduped
        if int(i.get("effective_weight", 0)) > 0
        and str(i.get("severity", "")).upper() in {"HIGH", "CRITICAL"}
    ]
    synergy_bonus = 10 if len(active_high_crit) >= 2 else 0

    final_score = max(0, min(100, base_score + synergy_bonus))
    category = map_score_to_category(final_score)
    style = CATEGORY_STYLES[category]

    scored_indicators = [i for i in deduped if int(i.get("weight", 0)) > 0]
    info_indicators = [i for i in deduped if int(i.get("weight", 0)) == 0]

    reasons = [
        f"[{i.get('severity', 'INFO')}] {i.get('title')}: {i.get('description')}"
        for i in scored_indicators
    ]
    if not reasons:
        reasons = [
            "No known malicious syntax patterns, deceptive lookalike domains, or coercive social-engineering phrases were detected by the rule set."
        ]

    recommendations = _build_recommendations(input_type, category, deduped)
    confidence_text = _build_confidence_explanation(input_type, final_score, deduped)

    return {
        "input_type": input_type.upper(),
        "risk_score": final_score,
        "base_score": base_score,
        "synergy_bonus": synergy_bonus,
        "risk_category": category,
        "color": style["color"],
        "badge_text": style["badge_text"],
        "accessible_symbol": style["accessible_symbol"],
        "headline": style["headline"],
        "indicators": deduped,
        "scored_indicator_count": len(scored_indicators),
        "info_indicator_count": len(info_indicators),
        "reasons": reasons,
        "recommendations": recommendations,
        "confidence_explanation": confidence_text,
        "disclaimer": (
            "Automated heuristic analysis can produce both false positives (flagging unusual but legitimate messages) "
            "and false negatives (missing novel scams with clean syntax). Never rely solely on an automated score to authorize payments."
        ),
        "context_metadata": context_metadata or {},
    }