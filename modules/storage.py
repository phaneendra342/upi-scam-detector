"""
modules/storage.py
Privacy-First Local SQLite Analysis History, Analytics & False-Positive Review Store.

Security & Privacy Guarantees:
- Stores ONLY anonymized metadata: id, UTC timestamp, input_type (QR/URL/SMS),
  risk_score (0-100), risk_category (Low/Medium/High/Critical), indicator_count,
  top_indicator_code, fraud_category, and review_status.
- NEVER stores raw SMS text, URLs, domains, UPI IDs (VPAs), payee names,
  uploaded images, or API keys.
- Explicitly closes SQLite file handles via contextlib.closing() to prevent
  Windows [WinError 32] file locking.
"""

from __future__ import annotations

import os
import sqlite3
from contextlib import closing
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv

load_dotenv()

DEFAULT_DB_PATH = os.getenv("DB_PATH", "scan_history.db")
ALLOWED_INPUT_TYPES = {"QR", "URL", "SMS"}
ALLOWED_CATEGORIES = {"Low", "Medium", "High", "Critical"}
ALLOWED_REVIEW_STATUSES = {"None", "Needs Review", "Reviewed"}

FRAUD_CATEGORIES = [
    "Phishing",
    "QR Payment Risk",
    "Impersonation",
    "Credential Theft",
    "Suspicious Payment Requests",
]


def map_indicator_to_fraud_category(top_code: str, input_type: str = "URL") -> str:
    """
    Map a rule indicator code to one of the 5 SecurePay Fraud Categories:
    - Phishing
    - QR Payment Risk
    - Impersonation
    - Credential Theft
    - Suspicious Payment Requests
    """
    code = (top_code or "NONE").upper()

    if any(k in code for k in ("CREDENTIAL", "REMOTE_ACCESS", "EMBEDDED_CREDENTIALS")):
        return "Credential Theft"
    if any(k in code for k in ("IMPERSONATION", "TYPOSQUATTING", "PUNYCODE", "CORP_NAME")):
        return "Impersonation"
    if any(
        k in code
        for k in (
            "REFUND_RECEIVE_BAIT",
            "COLLECT_RECEIVE_TRAP",
            "FAKE_REWARD",
            "HIGH_PREFILLED_AMOUNT",
            "PREFILLED_AMOUNT",
            "MINIMUM_AMOUNT",
            "URGENT_KYC",
            "HELPLINE_CALLBACK",
        )
    ):
        return "Suspicious Payment Requests"
    if code.startswith("QR_"):
        return "QR Payment Risk"
    if code.startswith("URL_") or "URL" in code or "LINK" in code:
        return "Phishing"

    clean_type = (input_type or "").upper()
    if clean_type == "QR":
        return "QR Payment Risk"
    if clean_type == "SMS":
        return "Suspicious Payment Requests"
    return "Phishing"


def is_history_enabled_by_env() -> bool:
    """Return True if local history is enabled by default in .env configuration."""
    val = os.getenv("ENABLE_LOCAL_HISTORY", "true").strip().lower()
    return val in {"1", "true", "yes", "on"}


def get_connection(db_path: str = DEFAULT_DB_PATH) -> sqlite3.Connection:
    """Create a SQLite connection with row factory enabled."""
    conn = sqlite3.connect(db_path, timeout=5.0)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: str = DEFAULT_DB_PATH) -> None:
    """
    Initialize the local SQLite database and scan_history table.
    Automatically adds fraud_category and review_status columns if migrating
    from an earlier schema, while keeping stored_columns privacy-audited.
    """
    with closing(get_connection(db_path)) as conn:
        with conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    input_type TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    risk_category TEXT NOT NULL,
                    indicator_count INTEGER NOT NULL,
                    top_indicator_code TEXT DEFAULT 'NONE',
                    fraud_category TEXT DEFAULT 'Phishing',
                    review_status TEXT DEFAULT 'None'
                )
                """
            )
            cursor = conn.execute("PRAGMA table_info(scan_history)")
            existing_cols = {row["name"] for row in cursor.fetchall()}
            if "top_indicator_code" not in existing_cols:
                conn.execute(
                    "ALTER TABLE scan_history ADD COLUMN top_indicator_code TEXT DEFAULT 'NONE'"
                )
            if "fraud_category" not in existing_cols:
                conn.execute(
                    "ALTER TABLE scan_history ADD COLUMN fraud_category TEXT DEFAULT 'Phishing'"
                )
            if "review_status" not in existing_cols:
                conn.execute(
                    "ALTER TABLE scan_history ADD COLUMN review_status TEXT DEFAULT 'None'"
                )


def save_scan_record(
    input_type: str,
    risk_score: int,
    risk_category: str,
    indicator_count: int,
    top_indicator_code: str = "NONE",
    enabled: bool = True,
    db_path: str = DEFAULT_DB_PATH,
    fraud_category: Optional[str] = None,
    review_status: str = "None",
) -> bool:
    """
    Save an anonymized scan metadata record to local SQLite storage.
    If enabled is False, skips writing to disk and returns False.
    """
    if not enabled:
        return False

    clean_type = str(input_type).upper().strip()
    if clean_type not in ALLOWED_INPUT_TYPES:
        clean_type = "UNKNOWN"

    clean_score = max(0, min(100, int(risk_score)))
    clean_category = str(risk_category).strip()
    if clean_category not in ALLOWED_CATEGORIES:
        clean_category = "Low"

    clean_count = max(0, int(indicator_count))
    clean_code = "".join(
        ch for ch in str(top_indicator_code or "NONE").upper() if ch.isalnum() or ch == "_"
    )[:64] or "NONE"

    resolved_fraud_cat = (
        fraud_category
        if fraud_category in FRAUD_CATEGORIES
        else map_indicator_to_fraud_category(clean_code, clean_type)
    )
    clean_review = (
        review_status if review_status in ALLOWED_REVIEW_STATUSES else "None"
    )

    try:
        init_db(db_path)
        with closing(get_connection(db_path)) as conn:
            with conn:
                conn.execute(
                    """
                    INSERT INTO scan_history (
                        input_type, risk_score, risk_category, indicator_count,
                        top_indicator_code, fraud_category, review_status
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        clean_type,
                        clean_score,
                        clean_category,
                        clean_count,
                        clean_code,
                        resolved_fraud_cat,
                        clean_review,
                    ),
                )
        return True
    except Exception:
        return False


def update_review_status(
    scan_id: int,
    new_status: str,
    db_path: str = DEFAULT_DB_PATH,
) -> bool:
    """
    Update the false-positive review status ('None', 'Needs Review', 'Reviewed')
    for a specific scan record ID.
    """
    if new_status not in ALLOWED_REVIEW_STATUSES:
        return False
    try:
        init_db(db_path)
        with closing(get_connection(db_path)) as conn:
            with conn:
                conn.execute(
                    "UPDATE scan_history SET review_status = ? WHERE id = ?",
                    (new_status, int(scan_id)),
                )
        return True
    except Exception:
        return False


def get_latest_scan_id(db_path: str = DEFAULT_DB_PATH) -> Optional[int]:
    """Return the most recently inserted scan_history ID, or None if empty."""
    try:
        init_db(db_path)
        with closing(get_connection(db_path)) as conn:
            row = conn.execute("SELECT id FROM scan_history ORDER BY id DESC LIMIT 1").fetchone()
            return int(row["id"]) if row else None
    except Exception:
        return None


def get_recent_scans(
    limit: int = 25,
    fraud_categories: Optional[List[str]] = None,
    db_path: str = DEFAULT_DB_PATH,
) -> List[Dict[str, Any]]:
    """
    Retrieve recent anonymized scan records ordered newest first.
    Optionally filters by selected Fraud Categories from the Right Sidebar.
    """
    try:
        init_db(db_path)
        with closing(get_connection(db_path)) as conn:
            if fraud_categories is not None and len(fraud_categories) == 0:
                return []

            if fraud_categories and len(fraud_categories) < len(FRAUD_CATEGORIES):
                placeholders = ",".join("?" for _ in fraud_categories)
                query = f"""
                    SELECT id, timestamp, input_type, risk_score, risk_category,
                           indicator_count, top_indicator_code, fraud_category, review_status
                    FROM scan_history
                    WHERE fraud_category IN ({placeholders})
                    ORDER BY id DESC
                    LIMIT ?
                """
                params = [*fraud_categories, max(1, int(limit))]
            else:
                query = """
                    SELECT id, timestamp, input_type, risk_score, risk_category,
                           indicator_count, top_indicator_code, fraud_category, review_status
                    FROM scan_history
                    ORDER BY id DESC
                    LIMIT ?
                """
                params = [max(1, int(limit))]

            cursor = conn.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]
    except Exception:
        return []


def get_review_queue(
    limit: int = 15,
    db_path: str = DEFAULT_DB_PATH,
) -> List[Dict[str, Any]]:
    """
    Retrieve findings marked as 'Needs Review' or 'Reviewed' for the
    Right Sidebar False Positive Review panel.
    """
    try:
        init_db(db_path)
        with closing(get_connection(db_path)) as conn:
            cursor = conn.execute(
                """
                SELECT id, timestamp, input_type, risk_score, risk_category,
                       indicator_count, top_indicator_code, fraud_category, review_status
                FROM scan_history
                WHERE review_status IN ('Needs Review', 'Reviewed')
                ORDER BY CASE WHEN review_status = 'Needs Review' THEN 0 ELSE 1 END, id DESC
                LIMIT ?
                """,
                (max(1, int(limit)),),
            )
            return [dict(row) for row in cursor.fetchall()]
    except Exception:
        return []


def get_summary_metrics(
    fraud_categories: Optional[List[str]] = None,
    db_path: str = DEFAULT_DB_PATH,
) -> Dict[str, Any]:
    """
    Calculate aggregate dashboard metrics from local anonymized storage:
    - total_scans
    - high_risk_count (High + Critical)
    - suspicious_links_count (URL scans with indicator_count > 0)
    - qr_analyzed_count (QR scans completed)
    - genuine today_scans count (only used when actual records exist)
    """
    try:
        init_db(db_path)
        with closing(get_connection(db_path)) as conn:
            where_clause = ""
            params: List[Any] = []
            if fraud_categories is not None:
                if len(fraud_categories) == 0:
                    return {
                        "total_scans": 0,
                        "high_risk_count": 0,
                        "suspicious_links_count": 0,
                        "qr_analyzed_count": 0,
                        "today_scans": 0,
                        "average_score": 0.0,
                        "type_breakdown": {},
                        "category_breakdown": {"Low": 0, "Medium": 0, "High": 0, "Critical": 0},
                    }
                if len(fraud_categories) < len(FRAUD_CATEGORIES):
                    placeholders = ",".join("?" for _ in fraud_categories)
                    where_clause = f"WHERE fraud_category IN ({placeholders})"
                    params = list(fraud_categories)

            def _build_where(extra_cond: str) -> str:
                if where_clause:
                    return f"{where_clause} AND ({extra_cond})"
                return f"WHERE {extra_cond}"

            total_scans = conn.execute(
                f"SELECT COUNT(*) FROM scan_history {where_clause}", params
            ).fetchone()[0]

            high_risk_where = _build_where("risk_category IN ('High', 'Critical')")
            high_risk_count = conn.execute(
                f"SELECT COUNT(*) FROM scan_history {high_risk_where}",
                params,
            ).fetchone()[0]

            susp_links_where = _build_where("input_type = 'URL' AND indicator_count > 0")
            suspicious_links_count = conn.execute(
                f"SELECT COUNT(*) FROM scan_history {susp_links_where}",
                params,
            ).fetchone()[0]

            qr_where = _build_where("input_type = 'QR'")
            qr_analyzed_count = conn.execute(
                f"SELECT COUNT(*) FROM scan_history {qr_where}",
                params,
            ).fetchone()[0]

            today_where = _build_where("date(timestamp) = date('now')")
            today_scans = conn.execute(
                f"SELECT COUNT(*) FROM scan_history {today_where}",
                params,
            ).fetchone()[0]

            avg_row = conn.execute(
                f"SELECT AVG(risk_score) FROM scan_history {where_clause}", params
            ).fetchone()[0]
            avg_score = round(float(avg_row), 1) if avg_row is not None else 0.0

            type_cursor = conn.execute(
                f"SELECT input_type, COUNT(*) as cnt FROM scan_history {where_clause} GROUP BY input_type",
                params,
            )
            type_breakdown = {row["input_type"]: row["cnt"] for row in type_cursor.fetchall()}

            cat_cursor = conn.execute(
                f"SELECT risk_category, COUNT(*) as cnt FROM scan_history {where_clause} GROUP BY risk_category",
                params,
            )
            raw_cats = {row["risk_category"]: row["cnt"] for row in cat_cursor.fetchall()}
            category_breakdown = {
                "Low": raw_cats.get("Low", 0),
                "Medium": raw_cats.get("Medium", 0),
                "High": raw_cats.get("High", 0),
                "Critical": raw_cats.get("Critical", 0),
            }

            return {
                "total_scans": total_scans,
                "high_risk_count": high_risk_count,
                "suspicious_links_count": suspicious_links_count,
                "qr_analyzed_count": qr_analyzed_count,
                "today_scans": today_scans,
                "average_score": avg_score,
                "type_breakdown": type_breakdown,
                "category_breakdown": category_breakdown,
            }
    except Exception:
        return {
            "total_scans": 0,
            "high_risk_count": 0,
            "suspicious_links_count": 0,
            "qr_analyzed_count": 0,
            "today_scans": 0,
            "average_score": 0.0,
            "type_breakdown": {},
            "category_breakdown": {"Low": 0, "Medium": 0, "High": 0, "Critical": 0},
        }


def get_scan_activity_series(
    fraud_categories: Optional[List[str]] = None,
    db_path: str = DEFAULT_DB_PATH,
) -> List[Dict[str, Any]]:
    """
    Return chronological scan activity grouped by date (or hour:minute when all scans
    occurred on the same day) for Chart A: Scan Activity.
    """
    try:
        init_db(db_path)
        with closing(get_connection(db_path)) as conn:
            where_clause = ""
            params: List[Any] = []
            if fraud_categories is not None:
                if len(fraud_categories) == 0:
                    return []
                if len(fraud_categories) < len(FRAUD_CATEGORIES):
                    placeholders = ",".join("?" for _ in fraud_categories)
                    where_clause = f"WHERE fraud_category IN ({placeholders})"
                    params = list(fraud_categories)

            day_rows = conn.execute(
                f"""
                SELECT strftime('%Y-%m-%d', timestamp) AS period,
                       COUNT(*) AS total_scans,
                       SUM(CASE WHEN risk_category IN ('High', 'Critical') THEN 1 ELSE 0 END) AS high_risk
                FROM scan_history
                {where_clause}
                GROUP BY strftime('%Y-%m-%d', timestamp)
                ORDER BY period ASC
                LIMIT 14
                """,
                params,
            ).fetchall()

            if len(day_rows) == 1:
                hour_rows = conn.execute(
                    f"""
                    SELECT strftime('%H:%M', timestamp) AS period,
                           COUNT(*) AS total_scans,
                           SUM(CASE WHEN risk_category IN ('High', 'Critical') THEN 1 ELSE 0 END) AS high_risk
                    FROM scan_history
                    {where_clause}
                    GROUP BY strftime('%Y-%m-%d %H:%M', timestamp)
                    ORDER BY timestamp ASC
                    LIMIT 20
                    """,
                    params,
                ).fetchall()
                return [dict(r) for r in hour_rows]

            return [dict(r) for r in day_rows]
    except Exception:
        return []


def clear_history(db_path: str = DEFAULT_DB_PATH) -> bool:
    """Delete all scan history records and reclaim SQLite space via VACUUM."""
    try:
        init_db(db_path)
        with closing(get_connection(db_path)) as conn:
            with conn:
                conn.execute("DELETE FROM scan_history")
            conn.execute("VACUUM")
        return True
    except Exception:
        return False


def get_privacy_audit_info(db_path: str = DEFAULT_DB_PATH) -> Dict[str, Any]:
    """
    Return verifiable database schema and privacy metadata for UI transparency.
    Confirms that no sensitive content columns exist in the SQLite table.
    """
    try:
        init_db(db_path)
        with closing(get_connection(db_path)) as conn:
            cursor = conn.execute("PRAGMA table_info(scan_history)")
            columns = [row["name"] for row in cursor.fetchall()]
    except Exception:
        columns = []

    file_size_kb = 0.0
    if os.path.exists(db_path):
        file_size_kb = round(os.path.getsize(db_path) / 1024.0, 2)

    return {
        "database_file": os.path.basename(db_path),
        "file_size_kb": file_size_kb,
        "stored_columns": columns,
        "excluded_sensitive_fields": [
            "Raw SMS text / message bodies",
            "Complete URLs, query parameters, and domains",
            "Payee UPI IDs (VPAs) and Payee Display Names",
            "Uploaded QR code images",
            "API keys or environment credentials",
        ],
    }