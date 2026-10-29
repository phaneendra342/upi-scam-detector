"""
modules/report_generator.py
SecurePay Fraud Detection — Reusable Risk Result & Evidence Component.

Design System Alignment:
- Cards: #131821 | Borders: #39414D
- Primary Text: #E8ECF3 | Secondary Text: #9AA4B2
- Low Risk: #A8F044 | Medium Risk: #F5C451 | High Risk: #FF914D | Critical Risk: #FF5252
"""

from __future__ import annotations

import html
import re
from typing import Any, Dict, List, Optional

import streamlit as st

from modules.storage import map_indicator_to_fraud_category, update_review_status

SECUREPAY_CATEGORY_COLORS = {
    "Low": {
        "color": "#A8F044",
        "bg": "rgba(168, 240, 68, 0.12)",
        "label": "LOW RISK",
        "symbol": "● LOW [0–24]",
    },
    "Medium": {
        "color": "#F5C451",
        "bg": "rgba(245, 196, 81, 0.14)",
        "label": "MEDIUM RISK",
        "symbol": "▲ MEDIUM [25–49]",
    },
    "High": {
        "color": "#FF914D",
        "bg": "rgba(255, 145, 77, 0.14)",
        "label": "HIGH RISK",
        "symbol": "◆ HIGH [50–74]",
    },
    "Critical": {
        "color": "#FF5252",
        "bg": "rgba(255, 82, 82, 0.15)",
        "label": "CRITICAL RISK",
        "symbol": "■ CRITICAL [75–100]",
    },
}

SEVERITY_BADGE_MAP = {
    "CRITICAL": {"color": "#FF5252", "bg": "rgba(255, 82, 82, 0.14)", "tag": "■ CRITICAL"},
    "HIGH": {"color": "#FF914D", "bg": "rgba(255, 145, 77, 0.14)", "tag": "◆ HIGH"},
    "MEDIUM": {"color": "#F5C451", "bg": "rgba(245, 196, 81, 0.14)", "tag": "▲ MEDIUM"},
    "LOW": {"color": "#A8F044", "bg": "rgba(168, 240, 68, 0.12)", "tag": "● LOW"},
    "INFO": {"color": "#C3E99B", "bg": "rgba(195, 233, 155, 0.12)", "tag": "ℹ INFO"},
}


def render_highlighted_sms_box(raw_sms: str, phrases: List[str]) -> None:
    """
    Safely highlight detected suspicious phrases and embedded links inside an SMS
    using HTML escaping before wrapping matched spans.
    """
    if not raw_sms:
        return

    escaped_sms = html.escape(raw_sms)
    sorted_phrases = sorted(
        [p.strip() for p in phrases if p and p.strip()],
        key=len,
        reverse=True,
    )

    for phrase in sorted_phrases:
        escaped_phrase = html.escape(phrase)
        if not escaped_phrase:
            continue
        pattern = re.compile(re.escape(escaped_phrase), re.IGNORECASE)
        escaped_sms = pattern.sub(
            lambda m: (
                f'<mark style="background-color: rgba(255, 82, 82, 0.22); '
                f'color: #E8ECF3; border: 1px solid #FF5252; border-radius: 5px; '
                f'padding: 1px 6px; font-weight: 600;">{m.group(0)}</mark>'
            ),
            escaped_sms,
        )

    st.markdown(
        f"""
        <div style="background-color: #131821; border: 1px solid #39414D; border-left: 4px solid #A8F044;
                    border-radius: 12px; padding: 16px 18px; margin-bottom: 14px;">
            <div style="color: #9AA4B2; font-size: 12px; font-weight: 600; text-transform: uppercase;
                        letter-spacing: 0.8px; margin-bottom: 8px;">
                Highlighted Threat &amp; Link Inspection
            </div>
            <div style="font-family: 'Inter', monospace; font-size: 14px; line-height: 1.65;
                        color: #E8ECF3; white-space: pre-wrap;">{escaped_sms}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_risk_report_card(
    report: Dict[str, Any],
    scan_id: Optional[int] = None,
    reset_key: str = "scan",
) -> None:
    """
    Render the SecurePay Risk Results Component:
    - Risk score (0-100) with Low/Medium/High/Critical label and visual meter
    - Detected indicators with explanations, fraud category tags, and evidence
    - Recommended actions & expandable technical details
    - False-Positive Review action button connected to local SQLite
    """
    score = int(report.get("risk_score", 0))
    category = str(report.get("risk_category", "Low"))
    theme = SECUREPAY_CATEGORY_COLORS.get(category, SECUREPAY_CATEGORY_COLORS["Low"])
    color = theme["color"]

    headline = html.escape(str(report.get("headline", "")))
    input_type = html.escape(str(report.get("input_type", "SCAN")))
    indicators: List[Dict[str, Any]] = report.get("indicators", [])
    reasons: List[str] = report.get("reasons", [])
    recommendations: List[str] = report.get("recommendations", [])
    confidence = html.escape(str(report.get("confidence_explanation", "")))
    disclaimer = html.escape(str(report.get("disclaimer", "")))

    top_code = str(indicators[0].get("code", "NONE")) if indicators else "NONE"
    primary_fraud_cat = map_indicator_to_fraud_category(top_code, input_type)

    # ------------------------------------------------------------------------
    # 1. Hero Score & Heuristic Gauge Card
    # ------------------------------------------------------------------------
    st.markdown(
        f"""
        <div style="background-color: #131821; border: 1px solid #39414D;
                    border-top: 3px solid {color}; border-radius: 14px;
                    padding: 22px 24px; margin-bottom: 16px;
                    box-shadow: 0 8px 24px rgba(0, 0, 0, 0.35);">
            <div style="display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; gap: 16px;">
                <div style="display: flex; align-items: center; gap: 18px;">
                    <div style="background-color: {theme['bg']}; border: 1.5px solid {color};
                                color: {color}; font-weight: 800; font-size: 32px;
                                min-width: 112px; text-align: center; padding: 14px 12px;
                                border-radius: 12px;">
                        {score}<span style="font-size: 15px; color: #9AA4B2; font-weight: 600;">/100</span>
                    </div>
                    <div>
                        <div style="display: flex; flex-wrap: wrap; align-items: center; gap: 8px; margin-bottom: 4px;">
                            <span style="background-color: {theme['bg']}; color: {color};
                                         border: 1px solid {color}; padding: 3px 10px;
                                         border-radius: 999px; font-size: 11.5px; font-weight: 700;">
                                {theme['symbol']}
                            </span>
                            <span style="background-color: #080E18; color: #C3E99B;
                                         border: 1px solid #39414D; padding: 3px 10px;
                                         border-radius: 999px; font-size: 11.5px; font-weight: 600;">
                                Category: {html.escape(primary_fraud_cat)}
                            </span>
                        </div>
                        <div style="color: #E8ECF3; font-size: 20px; font-weight: 700; margin-top: 4px;">
                            {theme['label']} &mdash; {input_type} Assessment
                        </div>
                        <div style="color: #9AA4B2; font-size: 13.5px; margin-top: 3px;">
                            {headline}
                        </div>
                    </div>
                </div>
            </div>
            <!-- Segmented Heuristic Meter -->
            <div style="margin-top: 18px;">
                <div style="display: flex; justify-content: space-between; font-size: 11.5px; color: #9AA4B2; margin-bottom: 6px;">
                    <span>0–24 Low (#A8F044)</span>
                    <span>25–49 Medium (#F5C451)</span>
                    <span>50–74 High (#FF914D)</span>
                    <span>75–100 Critical (#FF5252)</span>
                </div>
                <div style="width: 100%; background-color: #080E18; height: 10px; border-radius: 999px;
                            overflow: hidden; border: 1px solid #39414D;">
                    <div style="width: {max(2, score)}%; background-color: {color}; height: 100%;
                                border-radius: 999px; transition: width 0.3s ease;"></div>
                </div>
                <div style="color: #9AA4B2; font-size: 11.5px; margin-top: 8px;">
                    ℹ️ <strong>Heuristic Scoring Note:</strong> This 0–100 score is a rule-based heuristic weight, not a statistical probability of fraud. A Low score (including 0) does not guarantee that a recipient or link is safe.
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # False-Positive Review Action Bar (if saved to local history)
    if scan_id is not None:
        rcol1, rcol2 = st.columns([2.6, 1.4])
        with rcol1:
            st.caption(
                f"Scan Record `#{scan_id}` logged under **{primary_fraud_cat}**. "
                "Suspect an over-triggered rule? Flag this finding for the False Positive Review queue in the right sidebar."
            )
        with rcol2:
            if st.button(
                "🚩 Flag as 'Needs Review'",
                key=f"flag_fp_{reset_key}_{scan_id}",
                use_container_width=True,
            ):
                update_review_status(scan_id, "Needs Review")
                st.toast(f"Scan #{scan_id} added to False Positive Review queue.", icon="🚩")
                st.rerun()

    # ------------------------------------------------------------------------
    # 2. Detected Threat Indicators & Supporting Evidence
    # ------------------------------------------------------------------------
    st.markdown("#### Detected Indicators & Supporting Evidence")
    if not indicators:
        st.markdown(
            """
            <div style="background-color: #131821; border: 1px solid #39414D; border-left: 4px solid #A8F044;
                        border-radius: 12px; padding: 16px 18px; color: #E8ECF3; margin-bottom: 14px;">
                <strong style="color: #A8F044;">● [LOW RISK / NO HEURISTIC RULES TRIGGERED]</strong><br>
                <span style="color: #9AA4B2; font-size: 13.5px;">
                    No known phishing syntax, domain spoofing, or coercive social-engineering indicators matched this input.
                    Always verify the recipient's identity and banking name inside your UPI app before entering your PIN.
                </span>
            </div>
            """,
            unsafe_allow_html=True,
        )
    else:
        for ind in indicators:
            sev = str(ind.get("severity", "INFO")).upper()
            meta = SEVERITY_BADGE_MAP.get(sev, SEVERITY_BADGE_MAP["INFO"])
            title = html.escape(str(ind.get("title", "Indicator")))
            code = html.escape(str(ind.get("code", "RULE")))
            desc = html.escape(str(ind.get("description", "")))
            ev = html.escape(str(ind.get("evidence", "")))
            eff_w = int(ind.get("effective_weight", ind.get("weight", 0)))
            dedup_note = ind.get("deduplicated_note")
            ind_cat = map_indicator_to_fraud_category(code, input_type)

            weight_label = f"+{eff_w} pts" if eff_w > 0 else "0 pts (Info / Deduplicated)"

            st.markdown(
                f"""
                <div style="background-color: #131821; border: 1px solid #39414D;
                            border-left: 4px solid {meta['color']}; border-radius: 12px;
                            padding: 15px 18px; margin-bottom: 10px;">
                    <div style="display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; gap: 8px;">
                        <div style="font-weight: 700; font-size: 14.5px; color: #E8ECF3;">
                            <span style="background-color: {meta['bg']}; color: {meta['color']};
                                         padding: 2px 8px; border-radius: 6px; font-size: 11px;
                                         margin-right: 8px; border: 1px solid {meta['color']};">
                                {meta['tag']}
                            </span>
                            {title}
                        </div>
                        <div style="color: #9AA4B2; font-size: 12px; font-family: monospace;">
                            {html.escape(ind_cat)} &bull; <code>{code}</code> &bull;
                            <strong style="color: #A8F044;">{weight_label}</strong>
                        </div>
                    </div>
                    <div style="color: #9AA4B2; font-size: 13.5px; margin-top: 8px; line-height: 1.55;">
                        {desc}
                    </div>
                    <div style="background-color: #080E18; border: 1px solid #39414D; border-radius: 8px;
                                padding: 8px 12px; margin-top: 8px; font-family: monospace; font-size: 12px; color: #C3E99B;">
                        <strong style="color: #A8F044;">Evidence:</strong> {ev}
                    </div>
                    {f'<div style="color: #9AA4B2; font-size: 11.5px; margin-top: 6px;">ℹ️ {html.escape(str(dedup_note))}</div>' if dedup_note else ''}
                </div>
                """,
                unsafe_allow_html=True,
            )

    # ------------------------------------------------------------------------
    # 3. Recommended Safety Actions & Assessment Reasons
    # ------------------------------------------------------------------------
    col_rec, col_why = st.columns([1.15, 1])
    with col_rec:
        st.markdown("#### Recommended Safety Actions")
        for idx, rec in enumerate(recommendations, start=1):
            st.markdown(
                f"""
                <div style="background-color: #131821; border: 1px solid #39414D; border-left: 3px solid #A8F044;
                            border-radius: 10px; padding: 11px 14px; margin-bottom: 8px; font-size: 13.5px; color: #E8ECF3;">
                    <strong style="color: #A8F044;">Action {idx}:</strong> {html.escape(rec)}
                </div>
                """,
                unsafe_allow_html=True,
            )

    with col_why:
        st.markdown("#### Assessment Summary")
        for reason in reasons:
            st.markdown(
                f"""
                <div style="background-color: #131821; border: 1px solid #39414D;
                            border-radius: 10px; padding: 11px 14px; margin-bottom: 8px; font-size: 13px; color: #9AA4B2;">
                    &bull; {html.escape(reason)}
                </div>
                """,
                unsafe_allow_html=True,
            )

    # ------------------------------------------------------------------------
    # 4. Expandable Technical Details
    # ------------------------------------------------------------------------
    with st.expander("⚙️ Expand Technical Scoring Details & Heuristic Limitations"):
        st.markdown(
            f"""
            * **Base Weighted Rule Sum:** `{report.get('base_score', 0)}` pts
            * **Multi-Vector Synergy Bonus:** `+{report.get('synergy_bonus', 0)}` pts *(added when 2+ HIGH/CRITICAL rules co-occur)*
            * **Final Capped Risk Score:** `{score} / 100` (`{category}`)
            * **Confidence & Evidence Quality:** {confidence}
            * **Automated Detection Advisory:** {disclaimer}
            """
        )