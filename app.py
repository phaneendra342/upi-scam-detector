"""
app.py
SecurePay — UPI / QR Payment Scam & Phishing Detection Dashboard.
Designed to match the SecurePay Fraud Detection visual reference while preserving
all defensive QR, URL, SMS, Risk Engine, and Privacy-First SQLite capabilities.
"""

from __future__ import annotations

import html
import io
import os
from typing import List

import pandas as pd
import plotly.graph_objects as go
import qrcode
import streamlit as st

from modules.qr_scanner import PYZBAR_AVAILABLE, analyze_qr_image_bytes
from modules.report_generator import (
    render_highlighted_sms_box,
    render_risk_report_card,
)
from modules.risk_engine import evaluate_risk
from modules.sms_analyzer import analyze_sms_message
from modules.storage import (
    FRAUD_CATEGORIES,
    clear_history,
    get_latest_scan_id,
    get_privacy_audit_info,
    get_recent_scans,
    get_review_queue,
    get_scan_activity_series,
    get_summary_metrics,
    is_history_enabled_by_env,
    map_indicator_to_fraud_category,
    save_scan_record,
    update_review_status,
)
from modules.url_analyzer import analyze_payment_url

# ============================================================================
# 1. Page Configuration & SecurePay Design System CSS
# ============================================================================
st.set_page_config(
    page_title="SecurePay | Fraud Detection Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');

    /* Hide native Streamlit header, footer, and default left sidebar chrome */
    header[data-testid="stHeader"] {
        display: none !important;
    }
    footer {
        display: none !important;
    }
    section[data-testid="stSidebar"] {
        display: none !important;
    }

    /* Outer Muted Blue-to-Green Gradient Viewport */
    .stApp {
        background: linear-gradient(135deg, #162836 0%, #1A3335 45%, #233D32 100%) !important;
        color: #E8ECF3 !important;
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif !important;
    }

    /* Centered Rounded Main Dashboard Frame (#080E18) */
    .block-container {
        max-width: 1420px !important;
        margin: 22px auto 32px auto !important;
        background-color: #080E18 !important;
        border: 1px solid #39414D !important;
        border-radius: 24px !important;
        padding: 24px 32px 36px 32px !important;
        box-shadow: 0 24px 60px rgba(0, 0, 0, 0.65) !important;
    }

    /* Typography */
    h1, h2, h3, h4, h5, h6 {
        color: #E8ECF3 !important;
        font-family: 'Inter', sans-serif !important;
        letter-spacing: -0.02em;
    }

    /* Default Secondary Buttons (Top Nav, Sidebar Nav, Presets) */
    div.stButton > button[kind="secondary"] {
        background-color: #131821 !important;
        color: #E8ECF3 !important;
        border: 1px solid #39414D !important;
        border-radius: 10px !important;
        font-weight: 600 !important;
        font-size: 13.5px !important;
        padding: 0.48rem 0.9rem !important;
        transition: all 0.16s ease-in-out !important;
    }
    div.stButton > button[kind="secondary"]:hover {
        border-color: #A8F044 !important;
        color: #A8F044 !important;
        background-color: rgba(168, 240, 68, 0.08) !important;
    }

    /* Primary Lime-Green CTA Buttons (#A8F044) */
    div.stButton > button[kind="primary"] {
        background-color: #A8F044 !important;
        color: #080E18 !important;
        border: 1px solid #A8F044 !important;
        border-radius: 10px !important;
        font-weight: 700 !important;
        font-size: 13.5px !important;
        padding: 0.5rem 1.05rem !important;
        box-shadow: 0 4px 14px rgba(168, 240, 68, 0.22) !important;
        transition: all 0.16s ease-in-out !important;
    }
    div.stButton > button[kind="primary"]:hover {
        background-color: #C3E99B !important;
        border-color: #C3E99B !important;
        color: #080E18 !important;
        box-shadow: 0 6px 18px rgba(168, 240, 68, 0.35) !important;
    }

    /* Input Fields & Text Areas */
    div[data-baseweb="input"] > div,
    div[data-baseweb="textarea"] > div,
    div[data-baseweb="select"] > div {
        background-color: #131821 !important;
        border: 1px solid #39414D !important;
        border-radius: 10px !important;
        color: #E8ECF3 !important;
    }

    /* File Uploader Dropzone */
    section[data-testid="stFileUploaderDropzone"] {
        background-color: #131821 !important;
        border: 1.5px dashed #39414D !important;
        border-radius: 14px !important;
    }
    section[data-testid="stFileUploaderDropzone"]:hover {
        border-color: #A8F044 !important;
    }

    /* SecurePay Card Primitives */
    .sp-card {
        background-color: #131821;
        border: 1px solid #39414D;
        border-radius: 14px;
        padding: 18px 20px;
        transition: border-color 0.18s ease, transform 0.18s ease;
    }
    .sp-card:hover {
        border-color: #525E6F;
    }

    .sp-metric-card {
        background-color: #131821;
        border: 1px solid #39414D;
        border-radius: 14px;
        padding: 16px 18px;
        min-height: 118px;
        display: flex;
        flex-direction: column;
        justify-content: space-between;
    }
    .sp-metric-card:hover {
        border-color: #A8F044;
    }

    .sp-sidebar-panel {
        background-color: #131821;
        border: 1px solid #39414D;
        border-radius: 16px;
        padding: 18px;
        margin-bottom: 16px;
    }

    .sp-nav-shell {
        background-color: #131821;
        border: 1px solid #39414D;
        border-radius: 16px;
        padding: 12px 18px;
        margin-bottom: 22px;
    }

    /* Responsive adjustments */
    @media (max-width: 992px) {
        .block-container {
            margin: 8px !important;
            padding: 16px !important;
            border-radius: 16px !important;
        }
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# ============================================================================
# 2. Session State Initialization
# ============================================================================
ALL_VIEWS = [
    "Dashboard",
    "QR Scanner",
    "Link Analyzer",
    "SMS Analyzer",
    "Scan Reports",
    "Settings",
    "Features",
    "About",
]

if "current_view" not in st.session_state:
    st.session_state["current_view"] = "Dashboard"
if "dashboard_subtab" not in st.session_state:
    st.session_state["dashboard_subtab"] = "Overview"
if "history_opt_in" not in st.session_state:
    st.session_state["history_opt_in"] = is_history_enabled_by_env()
if "selected_fraud_categories" not in st.session_state:
    st.session_state["selected_fraud_categories"] = list(FRAUD_CATEGORIES)
if "url_input_text" not in st.session_state:
    st.session_state["url_input_text"] = ""
if "sms_input_text" not in st.session_state:
    st.session_state["sms_input_text"] = ""
if "demo_qr_bytes" not in st.session_state:
    st.session_state["demo_qr_bytes"] = None
if "demo_qr_name" not in st.session_state:
    st.session_state["demo_qr_name"] = ""


def set_view(view_name: str, subtab: str | None = None) -> None:
    st.session_state["current_view"] = view_name
    if subtab:
        st.session_state["dashboard_subtab"] = subtab


def _generate_synthetic_qr_bytes(payload: str) -> bytes:
    img = qrcode.make(payload)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def _top_indicator_code(indicators: list) -> str:
    if not indicators:
        return "NONE"
    return str(indicators[0].get("code", "NONE"))


# ============================================================================
# 3. Plotly Chart Builders (Matching SecurePay Reference Styling)
# ============================================================================
def build_scan_activity_chart(activity_rows: List[dict]) -> go.Figure:
    """Build Chart A: Scan Activity lime-green area/line chart."""
    periods = [r["period"] for r in activity_rows]
    totals = [int(r["total_scans"]) for r in activity_rows]
    high_risks = [int(r.get("high_risk") or 0) for r in activity_rows]

    fig = go.Figure()
    fig.add_trace(
        go.Scatter(
            x=periods,
            y=totals,
            mode="lines+markers",
            name="Total Scans",
            line=dict(color="#A8F044", width=3, shape="spline"),
            marker=dict(size=7, color="#A8F044", line=dict(width=1.5, color="#080E18")),
            fill="tozeroy",
            fillcolor="rgba(168, 240, 68, 0.16)",
        )
    )
    fig.add_trace(
        go.Scatter(
            x=periods,
            y=high_risks,
            mode="lines+markers",
            name="High / Critical",
            line=dict(color="#FF5252", width=2, dash="dot", shape="spline"),
            marker=dict(size=6, color="#FF5252"),
        )
    )
    fig.update_layout(
        paper_bgcolor="#131821",
        plot_bgcolor="#131821",
        margin=dict(l=8, r=8, t=10, b=8),
        height=240,
        font=dict(family="Inter, sans-serif", color="#9AA4B2", size=11),
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=1.02,
            xanchor="right",
            x=1,
            font=dict(size=11, color="#E8ECF3"),
        ),
        xaxis=dict(
            showgrid=False,
            zeroline=False,
            linecolor="#39414D",
            tickfont=dict(color="#9AA4B2", size=11),
        ),
        yaxis=dict(
            showgrid=True,
            gridcolor="rgba(57, 65, 77, 0.45)",
            zeroline=False,
            dtick=1 if max(totals, default=1) <= 5 else None,
            tickfont=dict(color="#9AA4B2", size=11),
        ),
        hovermode="x unified",
    )
    return fig


def build_risk_distribution_chart(cat_breakdown: dict) -> go.Figure:
    """Build Chart B: Risk Distribution bar chart with accessible labels."""
    categories = ["Low", "Medium", "High", "Critical"]
    counts = [int(cat_breakdown.get(c, 0)) for c in categories]
    colors = ["#A8F044", "#F5C451", "#FF914D", "#FF5252"]
    accessible_x = ["● Low", "▲ Medium", "◆ High", "■ Critical"]

    fig = go.Figure(
        data=[
            go.Bar(
                x=accessible_x,
                y=counts,
                marker=dict(
                    color=colors,
                    line=dict(color="#39414D", width=1),
                ),
                text=[str(v) for v in counts],
                textposition="outside",
                textfont=dict(color="#E8ECF3", size=12, family="Inter, sans-serif"),
                width=0.48,
            )
        ]
    )
    max_y = max(counts, default=1)
    fig.update_layout(
        paper_bgcolor="#131821",
        plot_bgcolor="#131821",
        margin=dict(l=8, r=8, t=22, b=8),
        height=240,
        font=dict(family="Inter, sans-serif", color="#9AA4B2", size=11),
        xaxis=dict(
            showgrid=False,
            zeroline=False,
            linecolor="#39414D",
            tickfont=dict(color="#E8ECF3", size=11.5),
        ),
        yaxis=dict(
            showgrid=True,
            gridcolor="rgba(57, 65, 77, 0.45)",
            zeroline=False,
            range=[0, max(max_y * 1.28, 3)],
            dtick=1 if max_y <= 5 else None,
            tickfont=dict(color="#9AA4B2", size=11),
        ),
    )
    return fig


# ============================================================================
# 4. Top Horizontal Navigation Bar (Inspired by SecurePay Reference)
# ============================================================================
top_left, top_center, top_right = st.columns([2.3, 3.6, 3.1], gap="small")

with top_left:
    st.markdown(
        """
        <div style="display: flex; align-items: center; gap: 11px; padding-top: 2px;">
            <div style="width: 38px; height: 38px; border-radius: 10px; background-color: rgba(168, 240, 68, 0.14);
                        border: 1.5px solid #A8F044; display: flex; align-items: center; justify-content: center;
                        box-shadow: 0 0 14px rgba(168, 240, 68, 0.25);">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#A8F044" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                    <path d="m9 12 2 2 4-4"/>
                </svg>
            </div>
            <div>
                <div style="color: #E8ECF3; font-size: 19px; font-weight: 800; letter-spacing: -0.02em; line-height: 1.1;">
                    Secure<span style="color: #A8F044;">Pay</span>
                </div>
                <div style="color: #9AA4B2; font-size: 11px; font-weight: 500;">
                    UPI &amp; QR Threat Intelligence
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with top_center:
    nc1, nc2, nc3, nc4 = st.columns(4, gap="small")
    with nc1:
        if st.button(
            "Home",
            key="topnav_home",
            type="primary" if st.session_state["current_view"] == "Dashboard" else "secondary",
            use_container_width=True,
        ):
            set_view("Dashboard", "Overview")
            st.rerun()
    with nc2:
        if st.button(
            "Features",
            key="topnav_features",
            type="primary" if st.session_state["current_view"] == "Features" else "secondary",
            use_container_width=True,
        ):
            set_view("Features")
            st.rerun()
    with nc3:
        if st.button(
            "Reports",
            key="topnav_reports",
            type="primary" if st.session_state["current_view"] == "Scan Reports" else "secondary",
            use_container_width=True,
        ):
            set_view("Scan Reports")
            st.rerun()
    with nc4:
        if st.button(
            "About",
            key="topnav_about",
            type="primary" if st.session_state["current_view"] == "About" else "secondary",
            use_container_width=True,
        ):
            set_view("About")
            st.rerun()

with top_right:
    rc1, rc2, rc3 = st.columns([1.45, 1.05, 1.2], gap="small")
    with rc1:
        privacy_dot = "#A8F044" if st.session_state["history_opt_in"] else "#F5C451"
        privacy_text = "Local Metadata" if st.session_state["history_opt_in"] else "Ephemeral Mode"
        st.markdown(
            f"""
            <div style="background-color: #131821; border: 1px solid #39414D; border-radius: 10px;
                        padding: 7px 10px; font-size: 11.5px; color: #E8ECF3; text-align: center;
                        white-space: nowrap; overflow: hidden; text-overflow: ellipsis;"
                 title="Zero raw SMS, URLs, or VPAs are ever stored on disk.">
                <span style="color: {privacy_dot}; font-weight: 800;">●</span> {privacy_text}
            </div>
            """,
            unsafe_allow_html=True,
        )
    with rc2:
        if st.button(
            "⚙ Settings",
            key="topnav_settings",
            type="primary" if st.session_state["current_view"] == "Settings" else "secondary",
            use_container_width=True,
        ):
            set_view("Settings")
            st.rerun()
    with rc3:
        if st.button("Scan Now", key="topnav_scan_now", type="primary", use_container_width=True):
            set_view("QR Scanner")
            st.rerun()

st.markdown(
    "<hr style='border: none; border-top: 1px solid #39414D; margin: 10px 0 22px 0;'>",
    unsafe_allow_html=True,
)


# ============================================================================
# 5. Reusable View Renderers (Reports & Settings shared between Tabs & Sidebar)
# ============================================================================
def render_scan_reports_section(active_categories: List[str]) -> None:
    """Render the Scan Reports table with category filtering & review actions."""
    st.markdown("### 📋 Local Scan Reports & Review Log")
    st.markdown(
        "<p style='color: #9AA4B2; font-size: 13.5px; margin-top: -6px;'>"
        "Displaying anonymized metadata from local SQLite storage filtered by your active Fraud Categories in the right sidebar."
        "</p>",
        unsafe_allow_html=True,
    )

    scans = get_recent_scans(limit=50, fraud_categories=active_categories)
    if not scans:
        st.markdown(
            """
            <div class="sp-card" style="text-align: center; padding: 32px 20px;">
                <div style="color: #A8F044; font-size: 15px; font-weight: 700;">No Matching Scan Reports</div>
                <div style="color: #9AA4B2; font-size: 13px; margin-top: 6px;">
                    Run a QR, Link, or SMS scan—or enable additional Fraud Category filters in the right sidebar.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        return

    df_scans = pd.DataFrame(scans)[
        [
            "id",
            "timestamp",
            "input_type",
            "fraud_category",
            "risk_score",
            "risk_category",
            "indicator_count",
            "top_indicator_code",
            "review_status",
        ]
    ]
    df_scans.columns = [
        "ID",
        "Timestamp (UTC)",
        "Vector",
        "Fraud Category",
        "Score",
        "Risk Level",
        "Indicators",
        "Primary Rule",
        "Review Status",
    ]
    st.dataframe(df_scans, use_container_width=True, hide_index=True)

    # Interactive False Positive Review Tagger
    st.markdown("#### 🚩 Update False Positive Review Status")
    ucol1, ucol2, ucol3, ucol4 = st.columns([1.4, 1.5, 1.2, 1.2], gap="small")
    scan_ids = [int(s["id"]) for s in scans]
    with ucol1:
        selected_id = st.selectbox("Select Scan ID", options=scan_ids, key="rep_select_id")
    with ucol2:
        selected_status = st.selectbox(
            "Review Status",
            options=["Needs Review", "Reviewed", "None"],
            key="rep_select_status",
        )
    with ucol3:
        st.markdown("<div style='height: 28px;'></div>", unsafe_allow_html=True)
        if st.button("Update Status", key="rep_btn_update", type="primary", use_container_width=True):
            update_review_status(selected_id, selected_status)
            st.toast(f"Scan #{selected_id} marked as '{selected_status}'.", icon="✅")
            st.rerun()
    with ucol4:
        st.markdown("<div style='height: 28px;'></div>", unsafe_allow_html=True)
        if st.button("🗑 Clear All History", key="rep_btn_clear_all", use_container_width=True):
            clear_history()
            st.toast("Local SQLite scan history cleared.", icon="🗑️")
            st.rerun()


def render_settings_section() -> None:
    """Render Privacy, SQLite Schema Audit, and Threat Intelligence Settings."""
    st.markdown("### ⚙️ Security, Privacy & Engine Settings")
    audit = get_privacy_audit_info()
    has_gsb = bool(os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip())

    sc1, sc2 = st.columns(2, gap="medium")
    with sc1:
        st.markdown(
            """
            <div class="sp-card">
                <div style="color: #A8F044; font-size: 13px; font-weight: 700; text-transform: uppercase;">
                    Local History &amp; Data Minimization
                </div>
                <p style="color: #9AA4B2; font-size: 13px; margin-top: 6px;">
                    Control whether anonymized scan metadata is saved to your local SQLite database.
                    Raw SMS messages, complete URLs, and UPI IDs are strictly excluded from disk storage.
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )
        new_opt = st.toggle(
            "Enable Local Anonymized Scan History",
            value=st.session_state["history_opt_in"],
            key="settings_toggle_history",
        )
        if new_opt != st.session_state["history_opt_in"]:
            st.session_state["history_opt_in"] = new_opt
            st.rerun()

        if st.button("🗑️ Wipe Local SQLite Database (DELETE + VACUUM)", key="settings_wipe_db"):
            clear_history()
            st.success("All local scan records deleted and vacuumed.")
            st.rerun()

    with sc2:
        st.markdown(
            f"""
            <div class="sp-card">
                <div style="color: #A8F044; font-size: 13px; font-weight: 700; text-transform: uppercase;">
                    Runtime Engine &amp; API Status
                </div>
                <div style="margin-top: 10px; font-size: 13.5px; color: #E8ECF3; line-height: 1.75;">
                    <div>&bull; <strong>QR Decoder Engine:</strong> <span style="color: #C3E99B;">
                        {'OpenCV + pyzbar Dual Decoder' if PYZBAR_AVAILABLE else 'OpenCV Native C++ QRCodeDetector'}
                    </span></div>
                    <div>&bull; <strong>URL Reputation API:</strong> <span style="color: {'#A8F044' if has_gsb else '#F5C451'};">
                        {'Google Safe Browsing Active' if has_gsb else 'Offline Static Heuristics Only'}
                    </span></div>
                    <div>&bull; <strong>SQLite File:</strong> <code>{html.escape(audit['database_file'])}</code> ({audit['file_size_kb']} KB)</div>
                    <div>&bull; <strong>Verified DB Columns:</strong> <code>{html.escape(', '.join(audit['stored_columns']))}</code></div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )


# ============================================================================
# 6. Two-Column Desktop Layout (72% Left Workspace | 28% Right Sidebar)
# ============================================================================
main_col, right_sidebar_col = st.columns([0.72, 0.28], gap="large")

# ----------------------------------------------------------------------------
# RIGHT PERSISTENT SIDEBAR (28% Width — Navigation, Fraud Categories, FP Review)
# ----------------------------------------------------------------------------
with right_sidebar_col:
    # Panel 1: Persistent Sidebar Navigation
    st.markdown(
        """
        <div style="background-color: #131821; border: 1px solid #39414D; border-radius: 14px;
                    padding: 14px 16px 6px 16px; margin-bottom: 10px;">
            <div style="color: #9AA4B2; font-size: 11.5px; font-weight: 700; text-transform: uppercase;
                        letter-spacing: 0.9px; margin-bottom: 8px;">
                Workspace Navigation
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    sidebar_nav_items = [
        ("Dashboard", "📊 Dashboard"),
        ("QR Scanner", "📸 QR Scanner"),
        ("Link Analyzer", "🔗 Link Analyzer"),
        ("SMS Analyzer", "💬 SMS Analyzer"),
        ("Scan Reports", "📋 Scan Reports"),
        ("Settings", "⚙️ Settings"),
    ]
    for view_key, label_text in sidebar_nav_items:
        is_current = st.session_state["current_view"] == view_key
        if st.button(
            label_text,
            key=f"rnav_{view_key}",
            type="primary" if is_current else "secondary",
            use_container_width=True,
        ):
            set_view(view_key)
            st.rerun()

    st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)

    # Panel 2: Fraud Categories Filter
    st.markdown(
        """
        <div style="background-color: #131821; border: 1px solid #39414D; border-radius: 14px;
                    padding: 14px 16px 10px 16px; margin-bottom: 8px;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <span style="color: #E8ECF3; font-size: 14px; font-weight: 700;">Fraud Categories</span>
                <span style="color: #A8F044; font-size: 11px; font-weight: 600;">Filter Active</span>
            </div>
            <div style="color: #9AA4B2; font-size: 12px; margin-top: 3px;">
                Filter dashboard metrics, charts, and scan reports by threat vector:
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    updated_categories: List[str] = []
    for cat_name in FRAUD_CATEGORIES:
        checked = st.checkbox(
            cat_name,
            value=(cat_name in st.session_state["selected_fraud_categories"]),
            key=f"fcat_chk_{cat_name}",
        )
        if checked:
            updated_categories.append(cat_name)

    if updated_categories != st.session_state["selected_fraud_categories"]:
        st.session_state["selected_fraud_categories"] = updated_categories
        st.rerun()

    fbtn1, fbtn2 = st.columns(2, gap="small")
    with fbtn1:
        if st.button("Select All", key="fcat_all", use_container_width=True):
            st.session_state["selected_fraud_categories"] = list(FRAUD_CATEGORIES)
            st.rerun()
    with fbtn2:
        if st.button("Reset", key="fcat_reset", use_container_width=True):
            st.session_state["selected_fraud_categories"] = list(FRAUD_CATEGORIES)
            st.rerun()

    st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)

    # Panel 3: False Positive Review Queue
    review_items = get_review_queue(limit=6)
    st.markdown(
        f"""
        <div style="background-color: #131821; border: 1px solid #39414D; border-radius: 14px;
                    padding: 14px 16px; margin-bottom: 10px;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <span style="color: #E8ECF3; font-size: 14px; font-weight: 700;">False Positive Review</span>
                <span style="background-color: rgba(168, 240, 68, 0.14); color: #A8F044;
                             border: 1px solid #A8F044; border-radius: 999px; padding: 1px 8px;
                             font-size: 11px; font-weight: 700;">
                    {len(review_items)}
                </span>
            </div>
            <div style="color: #9AA4B2; font-size: 11.5px; margin-top: 4px;">
                Findings flagged by users as potentially over-triggered. Heuristic rules require manual verification before confirming a false positive.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if not review_items:
        st.markdown(
            """
            <div style="background-color: #131821; border: 1px dashed #39414D; border-radius: 12px;
                        padding: 14px; color: #9AA4B2; font-size: 12px; text-align: center;">
                No findings currently flagged for review.<br>
                Use <strong>"Flag as Needs Review"</strong> on any scan result or inside <strong>Scan Reports</strong>.
            </div>
            """,
            unsafe_allow_html=True,
        )
    else:
        for item in review_items:
            rid = int(item["id"])
            r_status = str(item["review_status"])
            r_cat = str(item["risk_category"])
            r_rule = html.escape(str(item["top_indicator_code"]))
            status_color = "#F5C451" if r_status == "Needs Review" else "#A8F044"

            st.markdown(
                f"""
                <div style="background-color: #131821; border: 1px solid #39414D;
                            border-left: 3px solid {status_color}; border-radius: 10px;
                            padding: 10px 12px; margin-bottom: 6px;">
                    <div style="display: flex; justify-content: space-between; font-size: 12px;">
                        <strong style="color: #E8ECF3;">Scan #{rid} ({html.escape(item['input_type'])})</strong>
                        <span style="color: {status_color}; font-weight: 700;">{html.escape(r_status)}</span>
                    </div>
                    <div style="color: #9AA4B2; font-size: 11.5px; margin-top: 3px;">
                        Rule: <code>{r_rule}</code> &bull; Class: <strong>{html.escape(r_cat)} ({item['risk_score']})</strong>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )
            b1, b2 = st.columns(2, gap="small")
            with b1:
                if r_status != "Reviewed":
                    if st.button("✓ Mark Reviewed", key=f"fp_rev_{rid}", use_container_width=True):
                        update_review_status(rid, "Reviewed")
                        st.rerun()
                else:
                    if st.button("↺ Needs Review", key=f"fp_reopen_{rid}", use_container_width=True):
                        update_review_status(rid, "Needs Review")
                        st.rerun()
            with b2:
                if st.button("✕ Dismiss", key=f"fp_clear_{rid}", use_container_width=True):
                    update_review_status(rid, "None")
                    st.rerun()


# ----------------------------------------------------------------------------
# LEFT MAIN WORKSPACE (72% Width)
# ----------------------------------------------------------------------------
with main_col:
    active_cats = st.session_state["selected_fraud_categories"]
    current_view = st.session_state["current_view"]

    # ========================================================================
    # VIEW 1: MAIN DASHBOARD ("Fraud Detection" + Overview / Scan Reports / Settings)
    # ========================================================================
    if current_view == "Dashboard":
        st.markdown(
            """
            <div style="margin-bottom: 14px;">
                <h1 style="font-size: 32px; font-weight: 800; margin: 0; color: #E8ECF3;">
                    Fraud Detection
                </h1>
                <p style="color: #9AA4B2; font-size: 15px; margin: 4px 0 0 0;">
                    Identify suspicious QR codes, payment links, and SMS messages before you pay.
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )

        tab_overview, tab_reports, tab_settings = st.tabs(
            ["Overview", "Scan Reports", "Settings"]
        )

        # --------------------------------------------------------------------
        # TAB 1: OVERVIEW
        # --------------------------------------------------------------------
        with tab_overview:
            metrics = get_summary_metrics(fraud_categories=active_cats)
            total_scans = metrics["total_scans"]
            high_risk = metrics["high_risk_count"]
            susp_links = metrics["suspicious_links_count"]
            qr_count = metrics["qr_analyzed_count"]
            today_scans = metrics["today_scans"]

            # 4 Horizontally Aligned Summary Cards (100% genuine data, zero fake percentages)
            mc1, mc2, mc3, mc4 = st.columns(4, gap="medium")

            with mc1:
                trend_html = (
                    f'<span style="color: #A8F044; font-size: 11.5px; font-weight: 600;">+{today_scans} recorded today</span>'
                    if total_scans > 0 and today_scans > 0
                    else '<span style="color: #9AA4B2; font-size: 11.5px;">No scan history yet</span>'
                )
                st.markdown(
                    f"""
                    <div class="sp-metric-card">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <span style="color: #9AA4B2; font-size: 12.5px; font-weight: 600;">Total Scans</span>
                            <span style="color: #A8F044; font-size: 14px;">🛡️</span>
                        </div>
                        <div style="color: #E8ECF3; font-size: 32px; font-weight: 800; margin: 6px 0;">
                            {total_scans}
                        </div>
                        <div>{trend_html}</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

            with mc2:
                hr_color = "#FF5252" if high_risk > 0 else "#E8ECF3"
                hr_sub = (
                    f'<span style="color: #FF914D; font-size: 11.5px; font-weight: 600;">{(high_risk / total_scans * 100):.0f}% of completed scans</span>'
                    if total_scans > 0
                    else '<span style="color: #9AA4B2; font-size: 11.5px;">Awaiting first analysis</span>'
                )
                st.markdown(
                    f"""
                    <div class="sp-metric-card">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <span style="color: #9AA4B2; font-size: 12.5px; font-weight: 600;">High-Risk Findings</span>
                            <span style="color: #FF5252; font-size: 14px;">⚠️</span>
                        </div>
                        <div style="color: {hr_color}; font-size: 32px; font-weight: 800; margin: 6px 0;">
                            {high_risk}
                        </div>
                        <div>{hr_sub}</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

            with mc3:
                sl_color = "#FF914D" if susp_links > 0 else "#E8ECF3"
                sl_sub = (
                    '<span style="color: #F5C451; font-size: 11.5px;">URLs with threat indicators</span>'
                    if susp_links > 0
                    else '<span style="color: #9AA4B2; font-size: 11.5px;">0 flagged URLs recorded</span>'
                )
                st.markdown(
                    f"""
                    <div class="sp-metric-card">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <span style="color: #9AA4B2; font-size: 12.5px; font-weight: 600;">Suspicious Links</span>
                            <span style="color: #F5C451; font-size: 14px;">🔗</span>
                        </div>
                        <div style="color: {sl_color}; font-size: 32px; font-weight: 800; margin: 6px 0;">
                            {susp_links}
                        </div>
                        <div>{sl_sub}</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

            with mc4:
                qr_sub = (
                    '<span style="color: #C3E99B; font-size: 11.5px;">Decoded via OpenCV/pyzbar</span>'
                    if qr_count > 0
                    else '<span style="color: #9AA4B2; font-size: 11.5px;">No QR images scanned yet</span>'
                )
                st.markdown(
                    f"""
                    <div class="sp-metric-card">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <span style="color: #9AA4B2; font-size: 12.5px; font-weight: 600;">QR Codes Analyzed</span>
                            <span style="color: #A8F044; font-size: 14px;">📸</span>
                        </div>
                        <div style="color: #E8ECF3; font-size: 32px; font-weight: 800; margin: 6px 0;">
                            {qr_count}
                        </div>
                        <div>{qr_sub}</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

            st.markdown("<div style='height: 16px;'></div>", unsafe_allow_html=True)

            # ----------------------------------------------------------------
            # Two Side-by-Side Analytics Chart Cards (Matching Reference)
            # ----------------------------------------------------------------
            ch_left, ch_right = st.columns(2, gap="medium")

            with ch_left:
                st.markdown(
                    """
                    <div style="background-color: #131821; border: 1px solid #39414D; border-radius: 14px 14px 0 0;
                                padding: 14px 18px 4px 18px; border-bottom: none;">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <span style="color: #E8ECF3; font-size: 15px; font-weight: 700;">Scan Activity</span>
                            <span style="color: #A8F044; font-size: 11.5px; font-weight: 600;">● Live Local History</span>
                        </div>
                        <div style="color: #9AA4B2; font-size: 12px;">Completed analyses over time</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
                activity_series = get_scan_activity_series(fraud_categories=active_cats)
                if not activity_series:
                    st.markdown(
                        """
                        <div style="background-color: #131821; border: 1px solid #39414D; border-top: none;
                                    border-radius: 0 0 14px 14px; padding: 48px 18px; text-align: center;">
                            <div style="color: #E8ECF3; font-size: 14px; font-weight: 600;">No Scan Activity Recorded Yet</div>
                            <div style="color: #9AA4B2; font-size: 12.5px; margin-top: 4px;">
                                Complete a QR, Link, or SMS analysis to populate your real-time activity timeline.
                            </div>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )
                else:
                    fig_activity = build_scan_activity_chart(activity_series)
                    st.plotly_chart(fig_activity, use_container_width=True, config={"displayModeBar": False})

            with ch_right:
                st.markdown(
                    """
                    <div style="background-color: #131821; border: 1px solid #39414D; border-radius: 14px 14px 0 0;
                                padding: 14px 18px 4px 18px; border-bottom: none;">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <span style="color: #E8ECF3; font-size: 15px; font-weight: 700;">Risk Distribution</span>
                            <span style="color: #C3E99B; font-size: 11.5px; font-weight: 600;">Severity Breakdown</span>
                        </div>
                        <div style="color: #9AA4B2; font-size: 12px;">Low, Medium, High, and Critical classifications</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
                if total_scans == 0:
                    st.markdown(
                        """
                        <div style="background-color: #131821; border: 1px solid #39414D; border-top: none;
                                    border-radius: 0 0 14px 14px; padding: 48px 18px; text-align: center;">
                            <div style="color: #E8ECF3; font-size: 14px; font-weight: 600;">No Risk Classifications Yet</div>
                            <div style="color: #9AA4B2; font-size: 12.5px; margin-top: 4px;">
                                Severity distribution bars will appear automatically after your first scan.
                            </div>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )
                else:
                    fig_dist = build_risk_distribution_chart(metrics["category_breakdown"])
                    st.plotly_chart(fig_dist, use_container_width=True, config={"displayModeBar": False})

            st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)

            # ----------------------------------------------------------------
            # Quick Scanner Launchers & Filtered Recent Findings
            # ----------------------------------------------------------------
            q1, q2, q3 = st.columns(3, gap="medium")
            with q1:
                st.markdown(
                    """
                    <div class="sp-card">
                        <div style="color: #A8F044; font-weight: 700; font-size: 15px;">📸 QR Code Scanner</div>
                        <p style="color: #9AA4B2; font-size: 12.5px; margin: 6px 0 0 0;">
                            Inspect <code>upi://pay</code> URIs, payee VPAs, locked amounts, and fake refund baits.
                        </p>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
                if st.button("Launch QR Scanner →", key="ov_btn_qr", use_container_width=True):
                    set_view("QR Scanner")
                    st.rerun()
            with q2:
                st.markdown(
                    """
                    <div class="sp-card">
                        <div style="color: #C3E99B; font-weight: 700; font-size: 15px;">🔗 Payment Link Analyzer</div>
                        <p style="color: #9AA4B2; font-size: 12.5px; margin: 6px 0 0 0;">
                            Detect lookalike bank domains, URL shorteners, raw IP hosts, and SSRF targets.
                        </p>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
                if st.button("Launch Link Analyzer →", key="ov_btn_url", use_container_width=True):
                    set_view("Link Analyzer")
                    st.rerun()
            with q3:
                st.markdown(
                    """
                    <div class="sp-card">
                        <div style="color: #FF914D; font-weight: 700; font-size: 15px;">💬 SMS Scam Analyzer</div>
                        <p style="color: #9AA4B2; font-size: 12.5px; margin: 6px 0 0 0;">
                            Flag OTP/PIN harvesting, AnyDesk remote traps, and fake KYC suspension threats.
                        </p>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
                if st.button("Launch SMS Analyzer →", key="ov_btn_sms", use_container_width=True):
                    set_view("SMS Analyzer")
                    st.rerun()

            # Recent Findings List (Filtered by Right Sidebar Fraud Categories)
            st.markdown("#### 🕒 Recent Filtered Findings")
            recent_rows = get_recent_scans(limit=6, fraud_categories=active_cats)
            if not recent_rows:
                st.caption("No recent findings match the currently selected Fraud Categories.")
            else:
                for row in recent_rows:
                    r_cat = str(row["risk_category"])
                    badge_col = (
                        "#A8F044"
                        if r_cat == "Low"
                        else ("#F5C451" if r_cat == "Medium" else ("#FF914D" if r_cat == "High" else "#FF5252"))
                    )
                    st.markdown(
                        f"""
                        <div style="background-color: #131821; border: 1px solid #39414D;
                                    border-left: 4px solid {badge_col}; border-radius: 10px;
                                    padding: 10px 16px; margin-bottom: 8px;
                                    display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center;">
                            <div>
                                <strong style="color: #E8ECF3;">#{row['id']} [{html.escape(row['input_type'])}]</strong>
                                &nbsp;&bull;&nbsp;
                                <span style="color: #C3E99B; font-size: 13px;">{html.escape(str(row.get('fraud_category', 'Phishing')))}</span>
                                &nbsp;&bull;&nbsp;
                                <code style="font-size: 12px; color: #9AA4B2;">{html.escape(row['top_indicator_code'])}</code>
                            </div>
                            <div style="display: flex; align-items: center; gap: 14px;">
                                <span style="color: {badge_col}; font-weight: 700; font-size: 13px;">
                                    {row['risk_score']}/100 ({html.escape(r_cat)})
                                </span>
                                <span style="color: #9AA4B2; font-size: 12px;">{html.escape(str(row['timestamp']))}</span>
                            </div>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )

        # --------------------------------------------------------------------
        # TAB 2: SCAN REPORTS
        # --------------------------------------------------------------------
        with tab_reports:
            render_scan_reports_section(active_cats)

        # --------------------------------------------------------------------
        # TAB 3: SETTINGS
        # --------------------------------------------------------------------
        with tab_settings:
            render_settings_section()

    # ========================================================================
    # VIEW 2: QR SCANNER PAGE
    # ========================================================================
    elif current_view == "QR Scanner":
        st.markdown(
            """
            <div style="margin-bottom: 14px;">
                <h1 style="font-size: 28px; font-weight: 800; margin: 0; color: #E8ECF3;">
                    📸 QR Code Payment Scanner
                </h1>
                <p style="color: #9AA4B2; font-size: 14.5px; margin: 4px 0 0 0;">
                    Decode QR code images safely in memory and inspect NPCI <code>upi://pay</code> fields before scanning in your banking app.
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # Synthetic QR Presets for rapid testing
        st.markdown(
            "<div style='color: #9AA4B2; font-size: 12.5px; font-weight: 600; margin-bottom: 6px;'>"
            "Quick Test Presets (Generate Synthetic QR in Memory):"
            "</div>",
            unsafe_allow_html=True,
        )
        qp1, qp2, qp3 = st.columns(3, gap="small")
        with qp1:
            if st.button("✓ Valid Merchant UPI QR", key="qr_pre_legit", use_container_width=True):
                st.session_state["demo_qr_bytes"] = _generate_synthetic_qr_bytes(
                    "upi://pay?pa=freshmart.retail@okaxis&pn=FreshMart%20Supermarket&am=240.00&cu=INR&tn=Grocery%20Bill"
                )
                st.session_state["demo_qr_name"] = "synthetic_legit_merchant_qr.png"
        with qp2:
            if st.button("⚠ 'Scan to Receive Refund' Scam QR", key="qr_pre_scam", use_container_width=True):
                st.session_state["demo_qr_bytes"] = _generate_synthetic_qr_bytes(
                    "upi://pay?pa=scammer9911@ybl&pn=SBI%20Official%20Refund%20Desk&am=4999.00&cu=INR&tn=Scan%20QR%20to%20receive%20cashback%20refund"
                )
                st.session_state["demo_qr_name"] = "synthetic_scam_refund_qr.png"
        with qp3:
            if st.button("🔗 Quishing Website Link QR", key="qr_pre_quish", use_container_width=True):
                st.session_state["demo_qr_bytes"] = _generate_synthetic_qr_bytes(
                    "http://sbi-kyc-update.verify-account.xyz/login"
                )
                st.session_state["demo_qr_name"] = "synthetic_quishing_url_qr.png"

        uploaded_qr = st.file_uploader(
            "Drag and drop a QR code image (PNG, JPG, JPEG — Max 5 MB)",
            type=["png", "jpg", "jpeg"],
        )

        active_bytes = None
        active_filename = ""
        if uploaded_qr is not None:
            active_bytes = uploaded_qr.getvalue()
            active_filename = uploaded_qr.name
            st.session_state["demo_qr_bytes"] = None
        elif st.session_state["demo_qr_bytes"] is not None:
            active_bytes = st.session_state["demo_qr_bytes"]
            active_filename = st.session_state["demo_qr_name"]

        if active_bytes is not None:
            pcol1, pcol2 = st.columns([1, 2.2], gap="medium")
            with pcol1:
                st.markdown(
                    "<div style='color: #E8ECF3; font-size: 13.5px; font-weight: 700; margin-bottom: 6px;'>QR Image Preview</div>",
                    unsafe_allow_html=True,
                )
                try:
                    st.image(active_bytes, caption=f"{active_filename} ({len(active_bytes)/1024:.1f} KB)", width=220)
                except Exception:
                    st.warning("Preview unavailable for malformed file.")
            with pcol2:
                st.markdown(
                    """
                    <div class="sp-card" style="margin-bottom: 12px;">
                        <div style="color: #A8F044; font-size: 13px; font-weight: 700;">STATIC SANDBOX GUARANTEE</div>
                        <p style="color: #9AA4B2; font-size: 13px; margin: 6px 0 0 0;">
                            Clicking <strong>Analyze QR Code</strong> below extracts the encoded payload strictly as text.
                            SecurePay never opens external URLs or initiates UPI transactions.
                        </p>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
                analyze_qr_btn = st.button(
                    "Analyze QR Code", key="btn_exec_qr", type="primary", use_container_width=True
                )
                if st.button("Clear Loaded QR", key="btn_clear_qr", use_container_width=True):
                    st.session_state["demo_qr_bytes"] = None
                    st.rerun()

            if analyze_qr_btn:
                with st.spinner("Decoding QR image and inspecting payment parameters..."):
                    qr_result = analyze_qr_image_bytes(active_bytes, filename=active_filename)

                if not qr_result["success"]:
                    st.error(f"**Decoding Error:** {qr_result['error']}")
                    for tip in qr_result.get("troubleshooting_tips", []):
                        st.markdown(f"- {tip}")
                else:
                    inspection = qr_result["inspection"]
                    report = evaluate_risk("QR", inspection["indicators"], inspection)
                    top_code = _top_indicator_code(report["indicators"])
                    saved = save_scan_record(
                        input_type="QR",
                        risk_score=report["risk_score"],
                        risk_category=report["risk_category"],
                        indicator_count=report["scored_indicator_count"],
                        top_indicator_code=top_code,
                        enabled=st.session_state["history_opt_in"],
                    )
                    latest_id = get_latest_scan_id() if saved else None

                    st.markdown("#### Decoded Payment Payload")
                    st.code(qr_result["decoded_text"], language="text")

                    if inspection.get("upi_details"):
                        upd = inspection["upi_details"]
                        d1, d2, d3, d4 = st.columns(4, gap="small")
                        for col_obj, lbl, val in [
                            (d1, "Recipient VPA (pa)", upd["payee_vpa"] or "MISSING"),
                            (d2, "Claimed Name (pn)", upd["payee_name"] or "(None)"),
                            (
                                d3,
                                "Amount (am)",
                                f"{upd['currency']} {upd['amount']}" if upd["amount"] else "Open / User-Entered",
                            ),
                            (d4, "Transaction Note (tn)", upd["transaction_note"] or "(None)"),
                        ]:
                            with col_obj:
                                st.markdown(
                                    f"""
                                    <div class="sp-card" style="padding: 12px 14px;">
                                        <div style="color: #9AA4B2; font-size: 11.5px;">{html.escape(lbl)}</div>
                                        <div style="color: #E8ECF3; font-size: 14px; font-weight: 700; margin-top: 4px; word-break: break-all;">
                                            {html.escape(str(val))}
                                        </div>
                                    </div>
                                    """,
                                    unsafe_allow_html=True,
                                )

                    st.markdown(
                        f"""
                        <div style="background-color: rgba(245, 196, 81, 0.12); border: 1px solid #F5C451;
                                    border-radius: 10px; padding: 12px 16px; margin: 12px 0; font-size: 13px; color: #E8ECF3;">
                            <strong style="color: #F5C451;">⚠️ Unverified Recipient Identity Warning:</strong>
                            {html.escape(inspection['identity_warning'])}
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )
                    render_risk_report_card(report, scan_id=latest_id, reset_key="qr")

    # ========================================================================
    # VIEW 3: LINK ANALYZER PAGE
    # ========================================================================
    elif current_view == "Link Analyzer":
        st.markdown(
            """
            <div style="margin-bottom: 14px;">
                <h1 style="font-size: 28px; font-weight: 800; margin: 0; color: #E8ECF3;">
                    🔗 Payment Link &amp; URL Analyzer
                </h1>
                <p style="color: #9AA4B2; font-size: 14.5px; margin: 4px 0 0 0;">
                    Statically dissect URLs for domain spoofing, URL shorteners, punycode, raw IP hosts, and SSRF risks without visiting the target site.
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )

        lp1, lp2, lp3, lp4 = st.columns(4, gap="small")
        with lp1:
            if st.button("Phishing Lookalike URL", key="url_pre_1", use_container_width=True):
                st.session_state["url_input_text"] = (
                    "http://sbi-kyc-update.verify-account.xyz:8080/refund?redirect=http://evil.top"
                )
        with lp2:
            if st.button("Shortener + @ Credential Trick", key="url_pre_2", use_container_width=True):
                st.session_state["url_input_text"] = "https://onlinesbi.sbi@bit.ly/3UrgentKYCClaim"
        with lp3:
            if st.button("Raw IP Host Link", key="url_pre_3", use_container_width=True):
                st.session_state["url_input_text"] = "http://103.45.67.89/paytm-cashback-claim"
        with lp4:
            if st.button("Official Bank HTTPS URL", key="url_pre_4", use_container_width=True):
                st.session_state["url_input_text"] = "https://www.onlinesbi.sbi/personal/"

        url_input = st.text_area(
            "Enter or Paste Suspicious Payment Link:",
            value=st.session_state["url_input_text"],
            placeholder="https://paytm-kyc-verify.top/claim-refund",
            height=95,
        )
        st.session_state["url_input_text"] = url_input

        ub1, ub2 = st.columns([2.4, 1], gap="small")
        with ub1:
            analyze_link_btn = st.button(
                "Analyze Link", key="btn_exec_url", type="primary", use_container_width=True
            )
        with ub2:
            if st.button("Clear Link", key="btn_clear_url", use_container_width=True):
                st.session_state["url_input_text"] = ""
                st.rerun()

        if analyze_link_btn:
            if not url_input.strip():
                st.error("Please paste a URL to analyze.")
            else:
                with st.spinner("Dissecting domain components and evaluating phishing rules..."):
                    url_res = analyze_payment_url(url_input)

                if not url_res["valid_input"]:
                    st.error(f"**Invalid URL:** {url_res['error']}")
                else:
                    report = evaluate_risk("URL", url_res["indicators"], url_res)
                    top_code = _top_indicator_code(report["indicators"])
                    saved = save_scan_record(
                        input_type="URL",
                        risk_score=report["risk_score"],
                        risk_category=report["risk_category"],
                        indicator_count=report["scored_indicator_count"],
                        top_indicator_code=top_code,
                        enabled=st.session_state["history_opt_in"],
                    )
                    latest_id = get_latest_scan_id() if saved else None

                    comp = url_res["components"]
                    st.markdown("#### URL & Domain Component Breakdown")
                    uc1, uc2, uc3, uc4 = st.columns(4, gap="small")
                    for col_obj, lbl, val in [
                        (uc1, "Registrable Domain", comp["registrable_domain"]),
                        (uc2, "Subdomain Prefix", comp["subdomain"]),
                        (
                            uc3,
                            "Protocol / TLS",
                            f"{comp['scheme']} ({'HTTPS' if comp['is_https'] else 'Unencrypted HTTP'})",
                        ),
                        (uc4, "Port & Path", f":{comp['port']} {comp['path'][:24]}"),
                    ]:
                        with col_obj:
                            st.markdown(
                                f"""
                                <div class="sp-card" style="padding: 12px 14px; margin-bottom: 12px;">
                                    <div style="color: #9AA4B2; font-size: 11.5px;">{html.escape(lbl)}</div>
                                    <div style="color: #E8ECF3; font-size: 14px; font-weight: 700; margin-top: 4px; word-break: break-all;">
                                        {html.escape(str(val))}
                                    </div>
                                </div>
                                """,
                                unsafe_allow_html=True,
                            )

                    st.caption(
                        f"🔒 {url_res['https_notice']} | Reputation Status: `{url_res['reputation']['status_message']}`"
                    )
                    render_risk_report_card(report, scan_id=latest_id, reset_key="url")

    # ========================================================================
    # VIEW 4: SMS ANALYZER PAGE
    # ========================================================================
    elif current_view == "SMS Analyzer":
        st.markdown(
            """
            <div style="margin-bottom: 14px;">
                <h1 style="font-size: 28px; font-weight: 800; margin: 0; color: #E8ECF3;">
                    💬 SMS &amp; Payment Message Analyzer
                </h1>
                <p style="color: #9AA4B2; font-size: 14.5px; margin: 4px 0 0 0;">
                    Detect OTP/UPI PIN solicitation, remote-access software traps (AnyDesk), fake KYC suspension threats, and embedded phishing links.
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )

        sp1, sp2, sp3, sp4 = st.columns(4, gap="small")
        with sp1:
            if st.button("KYC Block + OTP Harvest", key="sms_pre_1", use_container_width=True):
                st.session_state["sms_input_text"] = (
                    "Dear Customer, your SBI YONO account has been suspended today due to pending PAN KYC. "
                    "Click http://sbi-kyc-verify.xyz/login and share your 6-digit OTP immediately to unblock."
                )
        with sp2:
            if st.button("Scan QR for Cashback Trap", key="sms_pre_2", use_container_width=True):
                st.session_state["sms_input_text"] = (
                    "Congratulations! You have won Rs. 4,999 festival cashback reward on Google Pay. "
                    "Scan the attached QR code and enter your UPI PIN to receive money into your account."
                )
        with sp3:
            if st.button("Electricity + AnyDesk Scam", key="sms_pre_3", use_container_width=True):
                st.session_state["sms_input_text"] = (
                    "URGENT: Your electricity power supply will be disconnected tonight at 9:30 PM. "
                    "Download AnyDesk app and call electricity officer at +91 9876543210 immediately."
                )
        with sp4:
            if st.button("Legitimate Bank Debit Alert", key="sms_pre_4", use_container_width=True):
                st.session_state["sms_input_text"] = (
                    "Rs. 320.00 debited from A/c XX4512 on 28-Oct-26 to VPA metro.recharge@axisbank "
                    "(UPI Ref No 630188776655). Avl Bal Rs. 14,500.00. Never share your OTP or UPI PIN with anyone."
                )

        sms_input = st.text_area(
            "Paste SMS or Payment Message to Inspect:",
            value=st.session_state["sms_input_text"],
            placeholder="Paste the complete suspicious SMS message here...",
            height=135,
        )
        st.session_state["sms_input_text"] = sms_input
        st.caption(
            f"Character Count: **{len(sms_input)} / 5,000** | Words: **{len(sms_input.split()) if sms_input.strip() else 0}**"
        )

        sb1, sb2 = st.columns([2.4, 1], gap="small")
        with sb1:
            analyze_sms_btn = st.button(
                "Analyze Message", key="btn_exec_sms", type="primary", use_container_width=True
            )
        with sb2:
            if st.button("Clear Message", key="btn_clear_sms", use_container_width=True):
                st.session_state["sms_input_text"] = ""
                st.rerun()

        if analyze_sms_btn:
            if not sms_input.strip():
                st.error("Please enter or paste an SMS message to analyze.")
            else:
                with st.spinner("Evaluating social engineering patterns and embedded links..."):
                    sms_res = analyze_sms_message(sms_input)

                report = evaluate_risk("SMS", sms_res["indicators"], sms_res)
                top_code = _top_indicator_code(report["indicators"])
                saved = save_scan_record(
                    input_type="SMS",
                    risk_score=report["risk_score"],
                    risk_category=report["risk_category"],
                    indicator_count=report["scored_indicator_count"],
                    top_indicator_code=top_code,
                    enabled=st.session_state["history_opt_in"],
                )
                latest_id = get_latest_scan_id() if saved else None

                if sms_res.get("is_likely_transactional_notice"):
                    st.success(
                        "✓ Standard Transactional Alert Structure: Matches a normal bank debit/credit notice with zero scam indicators."
                    )
                if sms_res.get("has_protective_disclaimer"):
                    st.info(
                        "🛡️ Protective Disclaimer Recognized: 'Never share your OTP/PIN' was accurately excluded from false-positive flagging."
                    )

                render_highlighted_sms_box(sms_input, sms_res.get("highlighted_phrases", []))
                render_risk_report_card(report, scan_id=latest_id, reset_key="sms")

    # ========================================================================
    # VIEW 5: SCAN REPORTS (Direct View from Top Nav or Right Sidebar)
    # ========================================================================
    elif current_view == "Scan Reports":
        render_scan_reports_section(active_cats)

    # ========================================================================
    # VIEW 6: SETTINGS (Direct View from Top Nav or Right Sidebar)
    # ========================================================================
    elif current_view == "Settings":
        render_settings_section()

    # ========================================================================
    # VIEW 7: FEATURES (From Top Navigation Bar)
    # ========================================================================
    elif current_view == "Features":
        st.markdown("### 🛡️ SecurePay Defensive Detection Capabilities")
        fc1, fc2 = st.columns(2, gap="medium")
        with fc1:
            st.markdown(
                """
                <div class="sp-card" style="margin-bottom: 12px;">
                    <h4 style="color: #A8F044; margin: 0 0 6px 0;">1. NPCI UPI QR Code Dissection</h4>
                    <p style="color: #9AA4B2; font-size: 13.5px; margin: 0;">
                        Validates file headers via Pillow, decodes QR payloads across 5 contrast/upscaling passes,
                        inspects <code>upi://pay</code> fields, and flags "Scan to Receive Refund" traps and display-name spoofing.
                    </p>
                </div>
                <div class="sp-card">
                    <h4 style="color: #C3E99B; margin: 0 0 6px 0;">2. Static Phishing Link &amp; SSRF Guard</h4>
                    <p style="color: #9AA4B2; font-size: 13.5px; margin: 0;">
                        Detects typosquatted Indian banking domains, homoglyphs, punycode (<code>xn--</code>),
                        <code>@</code> credential tricks, URL shorteners, and private/metadata SSRF targets without visiting the link.
                    </p>
                </div>
                """,
                unsafe_allow_html=True,
            )
        with fc2:
            st.markdown(
                """
                <div class="sp-card" style="margin-bottom: 12px;">
                    <h4 style="color: #FF914D; margin: 0 0 6px 0;">3. Context-Aware SMS Threat Engine</h4>
                    <p style="color: #9AA4B2; font-size: 13.5px; margin: 0;">
                        Separates genuine bank security disclaimers from malicious OTP/PIN harvesting, AnyDesk remote-access traps,
                        urgent KYC disconnection coercion, and fake helpline numbers.
                    </p>
                </div>
                <div class="sp-card">
                    <h4 style="color: #F5C451; margin: 0 0 6px 0;">4. Transparent Scoring &amp; FP Review</h4>
                    <p style="color: #9AA4B2; font-size: 13.5px; margin: 0;">
                        Deduplicates overlapping concept families, maps scores to 0–100 heuristic ranges,
                        and provides a dedicated False Positive Review workflow in the right sidebar.
                    </p>
                </div>
                """,
                unsafe_allow_html=True,
            )

    # ========================================================================
    # VIEW 8: ABOUT & SAFETY GUIDE (From Top Navigation Bar)
    # ========================================================================
    elif current_view == "About":
        st.markdown("### ℹ️ About SecurePay & Digital Payment Safety Guide")
        st.markdown(
            """
            <div class="sp-card" style="margin-bottom: 14px;">
                <h4 style="color: #A8F044; margin-top: 0;">Core UPI Safety Rules</h4>
                <ul style="color: #E8ECF3; font-size: 13.5px; line-height: 1.75;">
                    <li><strong>Scanning a QR Code Only Sends Money Out:</strong> You never need to scan a QR code or enter a UPI PIN to receive a refund, cashback, or buyer payment.</li>
                    <li><strong>QR Display Names (<code>pn</code>) Are Unverified:</strong> Anyone can encode <code>pn=SBI Official</code> inside a QR code. Always verify the banking name shown on the final PIN screen.</li>
                    <li><strong>HTTPS Does Not Equal Legitimacy:</strong> Phishing sites routinely use free TLS certificates. Always inspect the registrable domain.</li>
                    <li><strong>National Cyber Crime Helpline (India):</strong> If financial fraud occurs, dial <strong>1930</strong> immediately or report at <a href="https://cybercrime.gov.in" style="color: #A8F044;">cybercrime.gov.in</a>.</li>
                </ul>
            </div>
            """,
            unsafe_allow_html=True,
        )