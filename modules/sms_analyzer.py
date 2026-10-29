"""
modules/sms_analyzer.py
Context-Aware SMS Scam, Phishing, and Social Engineering Analyzer.

Security Guarantees:
- Distinguishes between genuine bank security disclaimers ("Never share your OTP/PIN")
  and malicious credential solicitation ("Share your OTP / Enter UPI PIN").
- Extracts embedded URLs and analyzes them statically via modules.url_analyzer
  without visiting or executing any links.
- Identifies highlighted threat phrases for accessible UI explanation.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Set

from modules.url_analyzer import analyze_payment_url

# ============================================================================
# Security Constants & Pattern Definitions
# ============================================================================
MAX_SMS_LENGTH = 5000

# Protective disclaimer patterns found in legitimate transactional bank alerts
PROTECTIVE_DISCLAIMER_REGEX = re.compile(
    r"\b(never\s+share|do\s+not\s+share|don'?t\s+share|bank\s+never\s+asks)\b"
    r".{0,50}\b(otp|pin|cvv|password|mpin|upi\s*pin)\b",
    re.IGNORECASE | re.DOTALL,
)

# Legitimate transactional notification structure (e.g., "debited from A/c", "credited to A/c", "UPI Ref")
LEGIT_TRANSACTION_NOTICE_REGEX = re.compile(
    r"\b(debited\s+from|credited\s+to|spent\s+on|avl\s+bal|available\s+balance|upi\s+ref|utr\s+no|imps\s+ref)\b",
    re.IGNORECASE,
)

# Rule 1: Malicious Credential Solicitation (asking user to provide/enter/share PIN, OTP, CVV)
CREDENTIAL_SOLICITATION_PATTERNS = [
    re.compile(
        r"\b(share|send|reply\s+with|provide|submit|confirm|verify|enter|input|type)\b"
        r".{0,35}\b(otp|upi\s*pin|mpin|atm\s*pin|cvv|netbanking\s+password|card\s+pin)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(otp|upi\s*pin|mpin|cvv)\b.{0,25}\b(is\s+required\s+to\s+receive|to\s+claim|to\s+unblock|to\s+avoid\s+suspension|to\s+reverse)\b",
        re.IGNORECASE,
    ),
]

# Rule 2: Remote Access Apps & Unsolicited APK Malware
REMOTE_ACCESS_PATTERNS = [
    re.compile(
        r"\b(anydesk|teamviewer|quicksupport|rustdesk|airmirror|airdroid|screen\s*share|remote\s*support\s*app)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\b(download|install|open)\b.{0,30}\b(\.apk|kyc\s*app|support\s*apk)\b", re.IGNORECASE),
]

# Rule 3: Scan QR / Approve Collect Request to "Receive" Money
QR_COLLECT_TRAP_PATTERNS = [
    re.compile(
        r"\b(scan\s+(this\s+|the\s+)?qr|enter\s+(your\s+)?(upi\s*)?pin|approve\s+(the\s+)?collect\s+request|accept\s+payment\s+request)\b"
        r".{0,45}\b(to\s+receive|to\s+get|for\s+refund|for\s+cashback|to\s+credit|to\s+claim)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(receive|get|claim)\b.{0,30}\b(money|refund|cashback|reward|payment|rs\.?|inr|₹)\b"
        r".{0,40}\b(by\s+scanning|scan\s+qr|enter\s+(upi\s*)?pin|approve\s+request)\b",
        re.IGNORECASE,
    ),
]

# Rule 4: Urgent Account Suspension / KYC / Utility Disconnection Coercion
URGENT_KYC_COERCION_PATTERNS = [
    re.compile(
        r"\b(kyc|pan\s*card|aadhaar|account|sim\s*card|netbanking|upi\s*id|fastag|electricity\s+power|power\s+supply)\b"
        r".{0,45}\b(suspended|blocked|deactivated|disconnected|expired|freeze|frozen|terminated|closed\s+today|tonight)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(update|verify|complete|link)\b.{0,25}\b(kyc|pan|aadhaar)\b"
        r".{0,35}\b(immediately|urgent|within\s+\d+\s*(hours|hrs|mins|minutes)|today|otherwise|else)\b",
        re.IGNORECASE,
    ),
]

# Rule 5: Fake Refund, Lottery, Cashback, or "Accidental Transfer" Bait
FAKE_REWARD_OR_REFUND_PATTERNS = [
    re.compile(
        r"\b(congratulations|congrats|you\s+have\s+won|selected\s+for|unclaimed|eligible\s+for)\b"
        r".{0,40}\b(cashback|reward|lottery|prize|bonus|gift\s+voucher|iphone|rs\.?\s*\d+|₹\s*\d+)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(sent|transferred|credited)\b.{0,30}\b(by\s+mistake|accidentally|wrongly)\b"
        r".{0,45}\b(please\s+return|send\s+back|refund\s+back|upi)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(income\s+tax\s+refund|itr\s+refund|pending\s+refund|failed\s+transaction\s+refund)\b"
        r".{0,40}\b(click|link|verify|approve|claim)\b",
        re.IGNORECASE,
    ),
]

# Rule 6: Unverified Personal Mobile Callback in "Support / Helpline" Context
CALLBACK_HELPLINE_REGEX = re.compile(
    r"\b(call|contact|whatsapp|helpline|customer\s+care|support\s+no|officer)\b"
    r".{0,30}(\+?91[\s\-]?[6-9]\d{9}|\b[6-9]\d{9}\b)",
    re.IGNORECASE,
)

# Rule 7: URL Extraction Regex ( catches https://..., http://..., www..., and bare domains with paths )
URL_EXTRACTION_REGEX = re.compile(
    r"(?:https?://|www\.)[^\s<>\"']+|(?:\b[a-zA-Z0-9.\-]+\.(?:com|in|co\.in|org\.in|xyz|top|click|link|club|work|loan|win|tk|ml|cf|ga|ly|gl|gy|cc|at|io|me)/[^\s<>\"']*)",
    re.IGNORECASE,
)

AUTHORITY_NAMES = {
    "sbi", "state bank", "hdfc", "icici", "axis bank", "kotak", "pnb",
    "paytm", "phonepe", "google pay", "gpay", "bhim", "npci", "rbi",
    "reserve bank", "income tax", "electricity board", "bescom", "mseb", "tata power"
}


# ============================================================================
# Helper Function
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


# ============================================================================
# Main SMS Analysis Entry Point
# ============================================================================
def analyze_sms_message(raw_message: str) -> Dict[str, Any]:
    """
    Analyze an SMS or messaging app payment text for scam indicators,
    social engineering patterns, and embedded malicious URLs.
    """
    text = (raw_message or "").strip()
    indicators: List[Dict[str, Any]] = []
    highlighted_phrases: Set[str] = set()
    extracted_urls: List[Dict[str, Any]] = []

    if not text:
        return {
            "valid_input": False,
            "error": "Please enter or paste an SMS message to analyze.",
            "char_count": 0,
            "word_count": 0,
            "is_likely_transactional_notice": False,
            "has_protective_disclaimer": False,
            "extracted_urls": [],
            "highlighted_phrases": [],
            "indicators": [],
        }

    if len(text) > MAX_SMS_LENGTH:
        text = text[:MAX_SMS_LENGTH]
        indicators.append(
            _make_indicator(
                "SMS_TRUNCATED_OVERSIZED",
                "Oversized Message Input Truncated for Safety",
                "LOW",
                10,
                f"Input exceeded {MAX_SMS_LENGTH} characters and was truncated prior to pattern evaluation.",
                f"Original length > {MAX_SMS_LENGTH} chars",
            )
        )

    # Remove protective disclaimers from a copy of text before checking credential solicitation
    has_protective_disclaimer = bool(PROTECTIVE_DISCLAIMER_REGEX.search(text))
    text_without_disclaimers = PROTECTIVE_DISCLAIMER_REGEX.sub(" [SAFE_DISCLAIMER] ", text)
    is_transactional_format = bool(LEGIT_TRANSACTION_NOTICE_REGEX.search(text))

    # ------------------------------------------------------------------------
    # Check 1: Credential Harvesting (Soliciting OTP, UPI PIN, CVV, Password)
    # ------------------------------------------------------------------------
    cred_matches: List[str] = []
    for pattern in CREDENTIAL_SOLICITATION_PATTERNS:
        m = pattern.search(text_without_disclaimers)
        if m:
            snippet = m.group(0).strip()
            cred_matches.append(snippet)
            highlighted_phrases.add(snippet)

    if cred_matches:
        indicators.append(
            _make_indicator(
                "SMS_CREDENTIAL_HARVEST",
                "Direct Request for Sensitive Banking Credentials (OTP / UPI PIN / CVV)",
                "CRITICAL",
                65,
                "Legitimate banks and UPI apps NEVER ask you to share an OTP, enter your UPI PIN to receive money, or reply with your CVV/password.",
                f"Matched phrase: \"{cred_matches[0]}\"",
            )
        )

    # ------------------------------------------------------------------------
    # Check 2: Remote Access / Screen-Sharing App Request
    # ------------------------------------------------------------------------
    remote_matches: List[str] = []
    for pattern in REMOTE_ACCESS_PATTERNS:
        m = pattern.search(text)
        if m:
            snippet = m.group(0).strip()
            remote_matches.append(snippet)
            highlighted_phrases.add(snippet)

    if remote_matches:
        indicators.append(
            _make_indicator(
                "SMS_REMOTE_ACCESS_APP",
                "Request to Install Remote-Access App or Unverified APK",
                "CRITICAL",
                65,
                "Scammers ask victims to install screen-sharing apps (like AnyDesk, TeamViewer, or QuickSupport) or '.apk' files so they can secretly watch your screen and steal OTPs.",
                f"Detected software/file request: \"{remote_matches[0]}\"",
            )
        )

    # ------------------------------------------------------------------------
    # Check 3: Scan QR / Approve Collect Request to "Receive" Money
    # ------------------------------------------------------------------------
    qr_trap_matches: List[str] = []
    for pattern in QR_COLLECT_TRAP_PATTERNS:
        m = pattern.search(text_without_disclaimers)
        if m:
            snippet = m.group(0).strip()
            qr_trap_matches.append(snippet)
            highlighted_phrases.add(snippet)

    if qr_trap_matches:
        indicators.append(
            _make_indicator(
                "SMS_QR_COLLECT_RECEIVE_TRAP",
                "Deceptive Instruction to Scan QR or Enter PIN to 'Receive' Money",
                "CRITICAL",
                60,
                "You NEVER need to scan a QR code, approve a collect request, or enter a UPI PIN to receive money into your bank account.",
                f"Matched trap phrase: \"{qr_trap_matches[0]}\"",
            )
        )

    # ------------------------------------------------------------------------
    # Check 4: Urgent Account Suspension / KYC / Utility Disconnection Coercion
    # ------------------------------------------------------------------------
    kyc_matches: List[str] = []
    for pattern in URGENT_KYC_COERCION_PATTERNS:
        m = pattern.search(text)
        if m:
            snippet = m.group(0).strip()
            kyc_matches.append(snippet)
            highlighted_phrases.add(snippet)

    if kyc_matches:
        indicators.append(
            _make_indicator(
                "SMS_URGENT_KYC_SUSPENSION",
                "Urgent Account Block / KYC Expiration / Utility Disconnection Threat",
                "HIGH",
                42,
                "This message uses artificial urgency and fear (threatening immediate account suspension, KYC block, or electricity disconnection) to pressure you into acting hastily.",
                f"Urgent threat phrase: \"{kyc_matches[0]}\"",
            )
        )

    # ------------------------------------------------------------------------
    # Check 5: Fake Refund, Lottery, Cashback, or Wrong-Transfer Bait
    # ------------------------------------------------------------------------
    reward_matches: List[str] = []
    for pattern in FAKE_REWARD_OR_REFUND_PATTERNS:
        m = pattern.search(text)
        if m:
            snippet = m.group(0).strip()
            reward_matches.append(snippet)
            highlighted_phrases.add(snippet)

    if reward_matches:
        indicators.append(
            _make_indicator(
                "SMS_FAKE_REWARD_REFUND_BAIT",
                "Suspicious Refund, Lottery, Cashback, or 'Accidental Transfer' Bait",
                "HIGH",
                38,
                "Scammers frequently lure victims with fake cashback/lottery rewards or send fake 'credited by mistake' messages to trick you into sending real money.",
                f"Matched bait phrase: \"{reward_matches[0]}\"",
            )
        )

    # ------------------------------------------------------------------------
    # Check 6: Unverified 10-Digit Personal Mobile Number as "Customer Care"
    # ------------------------------------------------------------------------
    callback_match = CALLBACK_HELPLINE_REGEX.search(text)
    if callback_match:
        snippet = callback_match.group(0).strip()
        highlighted_phrases.add(snippet)
        indicators.append(
            _make_indicator(
                "SMS_UNVERIFIED_HELPLINE_CALLBACK",
                "Personal Mobile Number Presented as Bank / Utility Helpline",
                "HIGH",
                35,
                "Official banks and electricity boards use toll-free or verified shortcodes, not regular 10-digit personal mobile numbers (6/7/8/9XXXXXXXXX) via SMS or WhatsApp.",
                f"Callback instruction: \"{snippet}\"",
            )
        )

    # ------------------------------------------------------------------------
    # Check 7: Embedded URL Extraction & Deep Inspection
    # ------------------------------------------------------------------------
    raw_urls = URL_EXTRACTION_REGEX.findall(text)
    seen_urls: Set[str] = set()
    for raw_u in raw_urls:
        clean_u = raw_u.rstrip(".,;:!?)")
        if clean_u.lower() in seen_urls:
            continue
        seen_urls.add(clean_u.lower())
        highlighted_phrases.add(clean_u)

        url_report = analyze_payment_url(clean_u)
        url_indicators = url_report.get("indicators", [])
        extracted_urls.append(
            {
                "url": clean_u,
                "registrable_domain": url_report.get("components", {}).get("registrable_domain", clean_u),
                "indicator_count": len(url_indicators),
                "indicators": url_indicators,
            }
        )

        if url_indicators:
            top_titles = ", ".join(i["title"] for i in url_indicators[:2])
            max_url_weight = max((i["weight"] for i in url_indicators), default=30)
            indicators.append(
                _make_indicator(
                    "SMS_EMBEDDED_SUSPICIOUS_URL",
                    f"Suspicious Link Embedded Inside SMS ({clean_u[:45]})",
                    "CRITICAL" if max_url_weight >= 50 else "HIGH",
                    min(55, max_url_weight + 10),
                    f"The SMS contains a web link with {len(url_indicators)} security warning(s): {top_titles}.",
                    f"Link: {clean_u}",
                )
            )
        else:
            indicators.append(
                _make_indicator(
                    "SMS_CONTAINS_EXTERNAL_LINK",
                    "External Link Present in SMS Message",
                    "LOW",
                    12,
                    "This SMS contains a clickable link. Always verify the domain independently before entering any personal or financial details.",
                    f"Link: {clean_u}",
                )
            )

    # ------------------------------------------------------------------------
    # Check 8: Authority / Bank Impersonation Amplified by Suspicious Action
    # ------------------------------------------------------------------------
    text_lower = text.lower()
    claimed_authorities = sorted([auth.upper() for auth in AUTHORITY_NAMES if auth in text_lower])
    # Only flag authority impersonation if there is at least one other coercive/link/callback signal
    if claimed_authorities and (
        cred_matches or remote_matches or qr_trap_matches or kyc_matches or callback_match or any(u["indicator_count"] > 0 for u in extracted_urls)
    ):
        indicators.append(
            _make_indicator(
                "SMS_AUTHORITY_IMPERSONATION",
                f"Suspected Impersonation of Financial / Official Entity ({', '.join(claimed_authorities[:2])})",
                "MEDIUM",
                25,
                "This message references a known bank, payment network, or utility provider while asking you to click an unverified link, call a mobile number, or urgently verify credentials.",
                f"Referenced entity: {', '.join(claimed_authorities[:3])}",
            )
        )

    return {
        "valid_input": True,
        "error": None,
        "char_count": len(text),
        "word_count": len(text.split()),
        "is_likely_transactional_notice": is_transactional_format and len(indicators) == 0,
        "has_protective_disclaimer": has_protective_disclaimer,
        "extracted_urls": extracted_urls,
        "highlighted_phrases": sorted(highlighted_phrases),
        "indicators": indicators,
    }