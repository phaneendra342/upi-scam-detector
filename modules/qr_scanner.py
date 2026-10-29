"""
modules/qr_scanner.py
Defensive QR Code Image Decoder and NPCI UPI Payment URI Inspector.

Security Guarantees:
- Enforces strict file size and pixel dimension limits.
- Validates actual image binary headers via Pillow before decoding.
- Uses a resilient dual-engine decoder (OpenCV QRCodeDetector + optional pyzbar).
- Never executes, opens, or makes network requests to decoded QR payloads.
- Never treats the 'pn' (Payee Name) field as verified identity proof.
"""

from __future__ import annotations

import io
import os
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, unquote, urlparse

import cv2
import numpy as np
from PIL import Image, UnidentifiedImageError

# Optional pyzbar import with graceful fallback for Windows systems without libzbar-64.dll
try:
    from pyzbar.pyzbar import decode as pyzbar_decode  # type: ignore
    PYZBAR_AVAILABLE = True
except Exception:
    pyzbar_decode = None
    PYZBAR_AVAILABLE = False

# ============================================================================
# Security Constants & Heuristic Dictionaries
# ============================================================================
ALLOWED_EXTENSIONS = {".png", ".jpg", ".jpeg"}
ALLOWED_PIL_FORMATS = {"PNG", "JPEG", "MPO"}
DEFAULT_MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_SIZE_MB", "5"))
MAX_IMAGE_PIXELS = 25_000_000  # 25 Megapixels max to prevent decompression bombs

# NPCI UPI VPA Regex: handle@provider (e.g., merchant@okaxis, 9876543210@ybl)
VPA_REGEX = re.compile(r"^[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z][a-zA-Z0-9.\-]{1,63}$")

# Scam keywords frequently stuffed into UPI Transaction Notes (tn) or Payee Names (pn)
REFUND_BAIT_KEYWORDS = {
    "refund", "cashback", "reward", "lottery", "prize", "winner",
    "claim", "receive", "credit", "bonus", "reversal", "govt", "subsidy",
    "kyc", "unblock", "verification"
}

# Authority / brand impersonation terms often placed in unverified 'pn' (Payee Name)
AUTHORITY_IMPERSONATION_TERMS = {
    "rbi", "npci", "sbi", "hdfc", "icici", "axis", "paytm", "phonepe",
    "gpay", "google pay", "bhim", "amazon pay", "customer care", "support",
    "helpline", "official", "verified", "pm cares", "income tax", "police",
    "cyber cell", "electricity board", "bescom", "mseb"
}

DANGEROUS_SCHEMES = {"javascript", "data", "vbscript", "file", "intent", "tel", "sms"}


# ============================================================================
# Helper Function: Indicator Builder
# ============================================================================
def _make_indicator(
    code: str,
    title: str,
    severity: str,
    weight: int,
    description: str,
    evidence: str,
) -> Dict[str, Any]:
    """Create a standardized risk indicator dictionary for the Risk Engine."""
    return {
        "code": code,
        "title": title,
        "severity": severity,  # "LOW", "MEDIUM", "HIGH", "CRITICAL", or "INFO"
        "weight": weight,      # Numeric weight (0 to 65)
        "description": description,
        "evidence": evidence,
    }


# ============================================================================
# Stage 1: Safe Image Validation & Decoding
# ============================================================================
def validate_and_load_image(
    file_bytes: bytes,
    filename: str = "uploaded_qr.png",
    max_size_mb: int = DEFAULT_MAX_UPLOAD_MB,
) -> Tuple[Optional[np.ndarray], Optional[str], Dict[str, Any]]:
    """
    Safely validate uploaded file size, extension, and binary image headers.
    Returns (opencv_bgr_image, error_message, image_metadata).
    """
    metadata: Dict[str, Any] = {
        "filename": filename,
        "size_bytes": len(file_bytes) if file_bytes else 0,
        "format": None,
        "dimensions": None,
    }

    if not file_bytes or len(file_bytes) == 0:
        return None, "The uploaded file is empty. Please select a valid PNG or JPG image.", metadata

    max_bytes = max_size_mb * 1024 * 1024
    if len(file_bytes) > max_bytes:
        size_mb = len(file_bytes) / (1024 * 1024)
        return (
            None,
            f"File size ({size_mb:.2f} MB) exceeds the {max_size_mb} MB security limit.",
            metadata,
        )

    ext = os.path.splitext(filename.lower())[1]
    if ext and ext not in ALLOWED_EXTENSIONS:
        return (
            None,
            f"Unsupported file extension '{ext}'. Only PNG, JPG, and JPEG images are allowed.",
            metadata,
        )

    try:
        with Image.open(io.BytesIO(file_bytes)) as img:
            img_format = (img.format or "").upper()
            width, height = img.size
            metadata["format"] = img_format
            metadata["dimensions"] = f"{width}x{height}"

            if img_format not in ALLOWED_PIL_FORMATS:
                return (
                    None,
                    f"Invalid image header format '{img_format}'. Please upload a genuine PNG or JPEG image.",
                    metadata,
                )

            if width * height > MAX_IMAGE_PIXELS:
                return (
                    None,
                    "Image resolution is unusually large and exceeds safety limits. Please crop or resize the QR image.",
                    metadata,
                )

            # Convert to standard RGB in memory and convert to OpenCV BGR numpy array
            rgb_img = img.convert("RGB")
            rgb_array = np.array(rgb_img, dtype=np.uint8)
            bgr_array = cv2.cvtColor(rgb_array, cv2.COLOR_RGB2BGR)
            return bgr_array, None, metadata

    except UnidentifiedImageError:
        return (
            None,
            "Could not verify image contents. The file appears corrupted or is not a valid image.",
            metadata,
        )
    except Exception as exc:
        return (
            None,
            f"Image validation failed safely: {type(exc).__name__}. Please upload a clear PNG or JPG screenshot.",
            metadata,
        )


def decode_qr_from_array(bgr_image: np.ndarray) -> Tuple[Optional[str], str]:
    """
    Decode QR code text from an OpenCV BGR array using multiple preprocessing passes.
    Uses pyzbar if available and OpenCV's built-in QRCodeDetector as primary/fallback.
    Returns (decoded_string, decoder_engine_used).
    """
    gray = cv2.cvtColor(bgr_image, cv2.COLOR_BGR2GRAY)

    # Create candidate images to handle screenshots without white borders, low contrast, or small size
    padded_gray = cv2.copyMakeBorder(
        gray, 40, 40, 40, 40, cv2.BORDER_CONSTANT, value=255
    )
    _, thresh = cv2.threshold(
        padded_gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU
    )
    upscaled = cv2.resize(
        padded_gray, None, fx=2.0, fy=2.0, interpolation=cv2.INTER_CUBIC
    )

    candidates = [
        ("original", bgr_image),
        ("grayscale", gray),
        ("padded_border", padded_gray),
        ("otsu_threshold", thresh),
        ("upscaled_2x", upscaled),
    ]

    # 1. Try pyzbar first if its C library is active on the host OS
    if PYZBAR_AVAILABLE and pyzbar_decode is not None:
        for pass_name, candidate in candidates:
            try:
                results = pyzbar_decode(candidate)
                for res in results:
                    text = res.data.decode("utf-8", errors="replace").strip()
                    if text:
                        return text, f"pyzbar ({pass_name})"
            except Exception:
                continue

    # 2. Native OpenCV QRCodeDetector (works across all Windows systems without external DLLs)
    detector = cv2.QRCodeDetector()
    for pass_name, candidate in candidates:
        try:
            data, _, _ = detector.detectAndDecode(candidate)
            if data and data.strip():
                return data.strip(), f"OpenCV QRCodeDetector ({pass_name})"

            # Also try detectAndDecodeMulti in case multiple QR codes exist
            ok, decoded_info, _, _ = detector.detectAndDecodeMulti(candidate)
            if ok and decoded_info:
                for item in decoded_info:
                    if item and item.strip():
                        return item.strip(), f"OpenCV MultiQR ({pass_name})"
        except Exception:
            continue

    return None, "none"


# ============================================================================
# Stage 2: UPI Payment URI Parser & Risk Inspector
# ============================================================================
def parse_upi_uri(raw_text: str) -> Dict[str, Any]:
    """
    Parse an NPCI upi://pay URI into structured payment fields without executing it.
    """
    parsed = urlparse(raw_text.strip())
    query_params = parse_qs(parsed.query, keep_blank_values=True)

    def _get_param(key: str) -> str:
        # Case-insensitive lookup for query keys
        for k, values in query_params.items():
            if k.lower() == key.lower() and values:
                return unquote(values[0]).strip()
        return ""

    pa = _get_param("pa")      # Payee VPA (Mandatory in NPCI spec)
    pn = _get_param("pn")      # Payee Name
    am = _get_param("am")      # Transaction Amount
    mam = _get_param("mam")    # Minimum Amount
    cu = _get_param("cu") or "INR"
    tn = _get_param("tn")      # Transaction Note
    tr = _get_param("tr")      # Transaction Reference ID
    mc = _get_param("mc")      # Merchant Category Code
    url_param = _get_param("url")  # Callback/Reference URL
    mode = _get_param("mode")  # Initiation mode
    sign = _get_param("sign")  # Digital signature (UPI 2.0 signed QR)

    return {
        "scheme": parsed.scheme.lower(),
        "host": parsed.netloc.lower(),
        "payee_vpa": pa,
        "payee_name": pn,
        "amount": am,
        "min_amount": mam,
        "currency": cu.upper(),
        "transaction_note": tn,
        "transaction_ref": tr,
        "merchant_code": mc,
        "reference_url": url_param,
        "initiation_mode": mode,
        "is_signed": bool(sign),
        "signature_preview": (sign[:24] + "...") if len(sign) > 24 else sign,
        "raw_query_keys": list(query_params.keys()),
    }


def inspect_decoded_qr_payload(raw_payload: str) -> Dict[str, Any]:
    """
    Analyze any decoded QR payload string (UPI URI, website URL, or raw text)
    for scam, spoofing, and phishing indicators.
    """
    payload = (raw_payload or "").strip()
    indicators: List[Dict[str, Any]] = []
    upi_details: Optional[Dict[str, Any]] = None
    payload_type = "UNKNOWN_TEXT"

    if not payload:
        return {
            "payload_type": "EMPTY",
            "raw_payload": "",
            "upi_details": None,
            "indicators": [
                _make_indicator(
                    "QR_EMPTY_PAYLOAD",
                    "Empty QR Code Payload",
                    "MEDIUM",
                    25,
                    "The QR code decoded to an empty string.",
                    "Empty payload",
                )
            ],
            "identity_warning": "No valid payment recipient could be read from this QR code.",
        }

    parsed = urlparse(payload)
    scheme = (parsed.scheme or "").lower()
    netloc = (parsed.netloc or "").lower()

    # ------------------------------------------------------------------------
    # Case 1: UPI Payment URI (upi://pay?...)
    # ------------------------------------------------------------------------
    if scheme == "upi" or payload.lower().startswith("upi://"):
        payload_type = "UPI_PAYMENT"
        upi_details = parse_upi_uri(payload)

        vpa = upi_details["payee_vpa"]
        name = upi_details["payee_name"]
        amount_str = upi_details["amount"]
        min_amount_str = upi_details["min_amount"]
        note = upi_details["transaction_note"]
        currency = upi_details["currency"]
        ref_url = upi_details["reference_url"]
        is_signed = upi_details["is_signed"]

        # Check 1.1: Non-standard UPI action (e.g., upi://collect or malformed host)
        if upi_details["host"] != "pay":
            indicators.append(
                _make_indicator(
                    "QR_UPI_NONSTANDARD_HOST",
                    "Non-Standard or Malformed UPI Action",
                    "HIGH",
                    35,
                    f"Standard UPI QR codes use 'upi://pay'. This QR uses 'upi://{upi_details['host']}'.",
                    f"Host: upi://{upi_details['host']}",
                )
            )

        # Check 1.2: Missing or Malformed Payee VPA (pa)
        if not vpa:
            indicators.append(
                _make_indicator(
                    "QR_UPI_MISSING_VPA",
                    "Missing Payee UPI ID (pa parameter)",
                    "CRITICAL",
                    55,
                    "A valid UPI QR code must specify a payee Virtual Payment Address (pa). This QR code is malformed.",
                    "pa=<missing>",
                )
            )
        elif not VPA_REGEX.match(vpa):
            indicators.append(
                _make_indicator(
                    "QR_UPI_INVALID_VPA_FORMAT",
                    "Malformed Payee UPI ID (VPA)",
                    "HIGH",
                    40,
                    "The payee VPA does not match the standard NPCI handle@provider format.",
                    f"pa={vpa}",
                )
            )

        # Check 1.3: Refund / Cashback / "Scan to Receive" Bait in Note or Payee Name
        combined_text = f"{name} {note}".lower()
        matched_bait = sorted(
            [kw for kw in REFUND_BAIT_KEYWORDS if re.search(rf"\b{re.escape(kw)}\b", combined_text)]
        )
        if matched_bait:
            indicators.append(
                _make_indicator(
                    "QR_UPI_REFUND_RECEIVE_BAIT",
                    "Deceptive 'Receive Money / Refund / Reward' Bait inside Payment QR",
                    "CRITICAL",
                    60,
                    "Scanning a UPI QR code ONLY sends money out of your account—it is technically impossible to receive a refund, cashback, or prize by scanning a upi://pay QR code.",
                    f"Keywords found in QR fields: {', '.join(matched_bait)} (Name: '{name}', Note: '{note}')",
                )
            )

        # Check 1.4: Authority / Bank Impersonation in unverified Payee Name (pn)
        name_lower = name.lower()
        vpa_lower = vpa.lower()
        matched_auth = [
            term for term in AUTHORITY_IMPERSONATION_TERMS if term in name_lower
        ]
        if matched_auth:
            indicators.append(
                _make_indicator(
                    "QR_UPI_AUTHORITY_IMPERSONATION_NAME",
                    "High-Risk Brand or Authority Name in Unverified Payee Field",
                    "HIGH",
                    40,
                    "Anyone generating a QR code can type any Payee Name ('pn') they want (such as a bank, government fund, or support desk) while routing money to a completely unrelated UPI ID.",
                    f"Claimed Name (pn): '{name}' vs Actual Recipient VPA (pa): '{vpa}'",
                )
            )
        elif name and vpa:
            # Check if VPA handle looks like a random phone number while claiming a corporate name
            vpa_user = vpa_lower.split("@")[0]
            if re.fullmatch(r"\d{10}", vpa_user) and any(
                corp in name_lower for corp in ("pvt", "ltd", "limited", "official", "corp", "enterprise")
            ):
                indicators.append(
                    _make_indicator(
                        "QR_UPI_CORP_NAME_PERSONAL_VPA",
                        "Corporate Display Name Paired with Mobile-Number VPA",
                        "MEDIUM",
                        22,
                        "The QR displays a corporate-sounding name ('pn') but routes funds to a 10-digit mobile number VPA.",
                        f"Payee Name: '{name}' | VPA: '{vpa}'",
                    )
                )

        # Check 1.5: Pre-filled Amount Inspection (am & mam)
        if amount_str != "" or "am=" in payload.lower():
            try:
                amount_val = float(amount_str)
                if amount_val <= 0:
                    indicators.append(
                        _make_indicator(
                            "QR_UPI_INVALID_AMOUNT",
                            "Zero or Negative Pre-filled Amount",
                            "MEDIUM",
                            20,
                            "NPCI guidelines prohibit am=0 or negative amounts in UPI QR codes, which can trigger parser anomalies.",
                            f"am={amount_str}",
                        )
                    )
                elif amount_val >= 10000:
                    indicators.append(
                        _make_indicator(
                            "QR_UPI_HIGH_PREFILLED_AMOUNT",
                            "High Pre-Locked Payment Amount in QR Code",
                            "HIGH",
                            35,
                            f"This QR code automatically locks a large deduction of ₹{amount_val:,.2f}. Verify the exact invoice total before entering your UPI PIN.",
                            f"Locked Amount: {currency} {amount_val:,.2f}",
                        )
                    )
                else:
                    indicators.append(
                        _make_indicator(
                            "QR_UPI_PREFILLED_AMOUNT_NOTICE",
                            "Pre-Filled Payment Amount Detected",
                            "LOW",
                            10,
                            f"This QR code pre-fills an amount of ₹{amount_val:,.2f} so you cannot edit it on the payment screen.",
                            f"Pre-filled Amount: {currency} {amount_val:,.2f}",
                        )
                    )
            except ValueError:
                indicators.append(
                    _make_indicator(
                        "QR_UPI_MALFORMED_AMOUNT",
                        "Non-Numeric or Malformed Amount Parameter",
                        "MEDIUM",
                        25,
                        "The 'am' (amount) parameter contains non-standard characters instead of a clean decimal value.",
                        f"am='{amount_str}'",
                    )
                )

        if min_amount_str and min_amount_str.lower() != "null":
            indicators.append(
                _make_indicator(
                    "QR_UPI_MINIMUM_AMOUNT_FLOOR",
                    "Minimum Payment Floor ('mam') Enforced",
                    "LOW",
                    12,
                    "This QR code sets a minimum amount ('mam') parameter that prevents paying less than the specified floor.",
                    f"mam={min_amount_str}",
                )
            )

        # Check 1.6: Non-INR Currency
        if currency != "INR":
            indicators.append(
                _make_indicator(
                    "QR_UPI_NON_INR_CURRENCY",
                    "Non-Standard Currency Parameter in UPI URI",
                    "MEDIUM",
                    25,
                    "The NPCI UPI specification primarily mandates 'INR'. A different currency code is unusual and suspicious.",
                    f"cu={currency}",
                )
            )

        # Check 1.7: Unsigned QR Notice (Informational / Low heuristic notice)
        if not is_signed:
            indicators.append(
                _make_indicator(
                    "QR_UPI_UNSIGNED_PAYLOAD",
                    "Unsigned UPI QR Code (No Cryptographic 'sign' Parameter)",
                    "INFO",
                    0,
                    "This QR code does not carry an NPCI cryptographic merchant signature ('sign'). Anyone can generate an unsigned QR code with any display name.",
                    "sign=<absent>",
                )
            )

        # Check 1.8: Embedded External Reference URL inside UPI QR
        if ref_url:
            indicators.append(
                _make_indicator(
                    "QR_UPI_EMBEDDED_CALLBACK_URL",
                    "Embedded External URL Parameter in UPI QR",
                    "MEDIUM",
                    18,
                    "This UPI QR code includes an external 'url' parameter. Never open untrusted callback URLs outside your payment app.",
                    f"url={ref_url}",
                )
            )

    # ------------------------------------------------------------------------
    # Case 2: Website URL disguised inside a QR Code ("Quishing")
    # ------------------------------------------------------------------------
    elif scheme in {"http", "https"} or re.match(r"^www\.", payload, re.IGNORECASE):
        payload_type = "WEBSITE_URL"
        indicators.append(
            _make_indicator(
                "QR_UNEXPECTED_WEB_URL",
                "QR Code Directs to an External Website Instead of UPI App (Quishing Risk)",
                "HIGH",
                35,
                "Legitimate countertop UPI QR codes use the 'upi://pay' scheme. This QR code points to a web URL, which scammers frequently use to open fake banking or KYC phishing websites.",
                f"Decoded URL: {payload[:100]}",
            )
        )
        if scheme == "http":
            indicators.append(
                _make_indicator(
                    "QR_INSECURE_HTTP_URL",
                    "Unencrypted HTTP Website Link in QR Code",
                    "HIGH",
                    30,
                    "The URL inside this QR code uses insecure HTTP without encryption.",
                    f"Scheme: http:// ({netloc})",
                )
            )

    # ------------------------------------------------------------------------
    # Case 3: Dangerous URI Schemes (javascript:, data:, intent:, tel:, sms:)
    # ------------------------------------------------------------------------
    elif scheme in DANGEROUS_SCHEMES:
        payload_type = "DANGEROUS_URI"
        indicators.append(
            _make_indicator(
                "QR_DANGEROUS_URI_SCHEME",
                f"Dangerous or Executable URI Scheme ('{scheme}:') in QR Code",
                "CRITICAL",
                65,
                f"This QR code encodes a '{scheme}:' action instead of a payment request. It may attempt to trigger scripts, dial USSD codes, or launch arbitrary device intents.",
                f"Payload starts with: {payload[:60]}",
            )
        )

    # ------------------------------------------------------------------------
    # Case 4: Plain Text or Unknown Format
    # ------------------------------------------------------------------------
    else:
        payload_type = "PLAIN_TEXT"
        indicators.append(
            _make_indicator(
                "QR_NON_UPI_TEXT",
                "QR Code Contains Plain Text (Not a Valid UPI Payment URI)",
                "LOW",
                15,
                "This QR code does not contain a standard 'upi://pay' URI. Inspect the raw text carefully before taking any action.",
                f"Text preview: {payload[:80]}",
            )
        )
        # Check if plain text contains social engineering bait
        lower_payload = payload.lower()
        bait_hits = [kw for kw in REFUND_BAIT_KEYWORDS if kw in lower_payload]
        if bait_hits:
            indicators.append(
                _make_indicator(
                    "QR_TEXT_SCAM_BAIT",
                    "Suspicious Financial Bait Terms in QR Text",
                    "HIGH",
                    35,
                    "The decoded text contains terms commonly used in reward, refund, or KYC scams.",
                    f"Matched terms: {', '.join(bait_hits)}",
                )
            )

    return {
        "payload_type": payload_type,
        "raw_payload": payload,
        "upi_details": upi_details,
        "indicators": indicators,
        "identity_warning": (
            "IMPORTANT: The Payee Name ('pn') encoded inside a QR code is self-declared text. "
            "A scammer can write any merchant or bank name in the QR code while routing money "
            "to their own UPI ID ('pa'). Always verify the verified banking name shown inside "
            "your UPI app and never enter your UPI PIN to 'receive' money."
        ),
    }


# ============================================================================
# Stage 3: End-to-End Image File Analysis Entry Point
# ============================================================================
def analyze_qr_image_bytes(
    file_bytes: bytes,
    filename: str = "uploaded_qr.png",
    max_size_mb: int = DEFAULT_MAX_UPLOAD_MB,
) -> Dict[str, Any]:
    """
    Main entry point for scanning an uploaded QR image file from bytes.
    Validates image safely, decodes QR payload, inspects UPI/URL structure,
    and returns structured findings ready for the Risk Engine and UI.
    """
    bgr_img, error_msg, metadata = validate_and_load_image(
        file_bytes=file_bytes,
        filename=filename,
        max_size_mb=max_size_mb,
    )

    if error_msg or bgr_img is None:
        return {
            "success": False,
            "error": error_msg or "Failed to load image.",
            "troubleshooting_tips": [
                "Upload a clear, uncropped PNG, JPG, or JPEG image under 5 MB.",
                "Ensure the entire QR code (including the three corner squares) is visible.",
                "Avoid glare, heavy shadows, or tilted photos—try taking a flat screenshot.",
            ],
            "metadata": metadata,
            "decoder_used": None,
            "decoded_text": None,
            "inspection": None,
        }

    decoded_text, decoder_used = decode_qr_from_array(bgr_img)

    if not decoded_text:
        return {
            "success": False,
            "error": "No readable QR code was detected in the uploaded image.",
            "troubleshooting_tips": [
                "Make sure the QR code has a quiet white border around all four sides.",
                "Check that the image is sharp and not heavily pixelated or blurry.",
                "Crop out excessive background clutter so the QR code fills most of the frame.",
            ],
            "metadata": metadata,
            "decoder_used": decoder_used,
            "decoded_text": None,
            "inspection": None,
        }

    inspection = inspect_decoded_qr_payload(decoded_text)

    return {
        "success": True,
        "error": None,
        "troubleshooting_tips": [],
        "metadata": metadata,
        "decoder_used": decoder_used,
        "decoded_text": decoded_text,
        "inspection": inspection,
    }