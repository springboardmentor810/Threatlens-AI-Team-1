"""
PDF Report Generator for ThreatLens AI.

Generates professional security analysis PDF reports for:
1. Individual threat / file scan detections.
2. Executive threat monitoring summary reports.
"""

import io
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable,
    KeepTogether,
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch


def _get_styles():
    styles = getSampleStyleSheet()

    # Custom color palette
    primary_color = colors.HexColor("#0f172a")     # Dark slate
    accent_color = colors.HexColor("#0284c7")      # Cyan / Blue
    text_dark = colors.HexColor("#1e293b")
    text_muted = colors.HexColor("#64748b")

    styles.add(ParagraphStyle(
        name="ReportTitle",
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=primary_color,
        spaceAfter=6,
    ))

    styles.add(ParagraphStyle(
        name="ReportSubtitle",
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=text_muted,
        spaceAfter=12,
    ))

    styles.add(ParagraphStyle(
        name="SectionHeader",
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=16,
        textColor=accent_color,
        spaceBefore=10,
        spaceAfter=6,
    ))

    styles.add(ParagraphStyle(
        name="TableCell",
        fontName="Helvetica",
        fontSize=9,
        leading=12,
        textColor=text_dark,
    ))

    styles.add(ParagraphStyle(
        name="TableCellBold",
        fontName="Helvetica-Bold",
        fontSize=9,
        leading=12,
        textColor=text_dark,
    ))

    styles.add(ParagraphStyle(
        name="TableCellMuted",
        fontName="Helvetica",
        fontSize=9,
        leading=12,
        textColor=text_muted,
    ))

    styles.add(ParagraphStyle(
        name="CodeText",
        fontName="Courier",
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#0f172a"),
    ))

    return styles


def _get_risk_color(risk_level: Optional[str]) -> colors.Color:
    lvl = (risk_level or "").lower()
    if lvl == "critical":
        return colors.HexColor("#dc2626")  # Red
    elif lvl == "high":
        return colors.HexColor("#ea580c")  # Orange
    elif lvl == "medium":
        return colors.HexColor("#d97706")  # Amber
    elif lvl == "low":
        return colors.HexColor("#16a34a")  # Green
    return colors.HexColor("#0284c7")       # Cyan / Blue / Safe


def generate_threat_pdf(threat_data: Dict[str, Any], timeline: Optional[List[Dict[str, Any]]] = None) -> bytes:
    """
    Generate an individual threat scan report PDF.
    
    Args:
        threat_data: Dict representation of a ThreatLog record.
        timeline: Optional list of timeline events.
        
    Returns:
        bytes: The binary PDF data.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36,
    )

    styles = _get_styles()
    story = []

    # 1. Header Banner
    story.append(Paragraph("ThreatLens AI — Malware Analysis Report", styles["ReportTitle"]))
    generated_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    report_id = threat_data.get("id", "N/A")
    story.append(Paragraph(f"Report ID: {report_id}  |  Generated: {generated_time}", styles["ReportSubtitle"]))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0284c7"), spaceAfter=14))

    # 2. Executive Assessment Summary Table
    risk_level = (threat_data.get("risk_level") or "MINIMAL").upper()
    risk_score = threat_data.get("risk_score", 0)
    prediction = threat_data.get("prediction", "Unknown")
    confidence = threat_data.get("confidence", 0.0)
    detection_engine = threat_data.get("detection_engine") or "ThreatLens AI"

    verdict_color = _get_risk_color(risk_level)

    summary_data = [
        [
            Paragraph("<b>Target Filename:</b>", styles["TableCellBold"]),
            Paragraph(str(threat_data.get("filename", "N/A")), styles["TableCell"]),
            Paragraph("<b>Verdict / Prediction:</b>", styles["TableCellBold"]),
            Paragraph(f"<font color='{verdict_color.hexval()}'><b>{prediction}</b></font>", styles["TableCellBold"]),
        ],
        [
            Paragraph("<b>Risk Score:</b>", styles["TableCellBold"]),
            Paragraph(f"<b>{risk_score} / 100</b>", styles["TableCellBold"]),
            Paragraph("<b>Risk Level:</b>", styles["TableCellBold"]),
            Paragraph(f"<font color='{verdict_color.hexval()}'><b>{risk_level}</b></font>", styles["TableCellBold"]),
        ],
        [
            Paragraph("<b>Confidence:</b>", styles["TableCellBold"]),
            Paragraph(f"{confidence}%", styles["TableCell"]),
            Paragraph("<b>Detection Engine:</b>", styles["TableCellBold"]),
            Paragraph(str(detection_engine), styles["TableCell"]),
        ],
        [
            Paragraph("<b>Status:</b>", styles["TableCellBold"]),
            Paragraph(str(threat_data.get("status", "detected")).capitalize(), styles["TableCell"]),
            Paragraph("<b>Scan Timestamp:</b>", styles["TableCellBold"]),
            Paragraph(str(threat_data.get("detected_at") or "N/A"), styles["TableCell"]),
        ],
    ]

    summary_table = Table(summary_data, colWidths=[1.4 * inch, 2.1 * inch, 1.5 * inch, 2.4 * inch])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 14))

    # 3. File Identification & Cryptographic Hashes
    story.append(Paragraph("File Metadata & Hashes", styles["SectionHeader"]))
    file_size_bytes = threat_data.get("file_size")
    size_str = f"{file_size_bytes:,} bytes" if isinstance(file_size_bytes, int) else "N/A"
    
    hashes_data = [
        [Paragraph("<b>File Size:</b>", styles["TableCellBold"]), Paragraph(size_str, styles["TableCell"])],
        [Paragraph("<b>File Type / Extension:</b>", styles["TableCellBold"]), Paragraph(str(threat_data.get("file_type") or "N/A"), styles["TableCell"])],
        [Paragraph("<b>SHA-256 Hash:</b>", styles["TableCellBold"]), Paragraph(str(threat_data.get("file_hash_sha256") or "N/A"), styles["CodeText"])],
        [Paragraph("<b>MD5 Hash:</b>", styles["TableCellBold"]), Paragraph(str(threat_data.get("file_hash_md5") or "N/A"), styles["CodeText"])],
    ]
    hashes_table = Table(hashes_data, colWidths=[1.6 * inch, 5.8 * inch])
    hashes_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f1f5f9")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(hashes_table)
    story.append(Spacer(1, 14))

    # 4. AI Model & Static Analysis Details
    story.append(Paragraph("AI Ensemble & Static Analysis Details", styles["SectionHeader"]))

    # Extract static analysis report & AI details if present
    static_report = threat_data.get("static_analysis_results") or {}
    ai_analysis = static_report.get("ai_analysis") or {}
    
    ai_available = ai_analysis.get("available", False)
    ai_status = ai_analysis.get("status", "Executed" if ai_available else "Not Applicable")
    ai_reason = ai_analysis.get("reason", "EMBER features apply to PE binaries only.")

    ai_rows = []
    if ai_available:
        ai_rows.append([Paragraph("<b>AI Status:</b>", styles["TableCellBold"]), Paragraph("<font color='#16a34a'><b>Executed</b></font>", styles["TableCell"])])
        ai_rows.append([Paragraph("<b>Model Architecture:</b>", styles["TableCellBold"]), Paragraph(str(ai_analysis.get("model", "Extra Trees + Tuned LightGBM")), styles["TableCell"])])
        ai_rows.append([Paragraph("<b>Ensemble Verdict:</b>", styles["TableCellBold"]), Paragraph(f"<b>{ai_analysis.get('verdict', 'N/A')}</b>", styles["TableCellBold"])])
        malware_prob = ai_analysis.get("malware_probability")
        prob_str = f"{malware_prob * 100:.2f}%" if malware_prob is not None else "N/A"
        ai_rows.append([Paragraph("<b>Malware Probability:</b>", styles["TableCellBold"]), Paragraph(prob_str, styles["TableCell"])])
        model_probs = ai_analysis.get("model_probabilities") or {}
        if model_probs:
            prob_breakdown = f"Extra Trees: {model_probs.get('extra_trees', 'N/A')} | LightGBM: {model_probs.get('lightgbm', 'N/A')}"
            ai_rows.append([Paragraph("<b>Individual Model Probs:</b>", styles["TableCellBold"]), Paragraph(prob_breakdown, styles["TableCell"])])
    else:
        ai_rows.append([Paragraph("<b>AI Model Status:</b>", styles["TableCellBold"]), Paragraph(f"<b>{ai_status}</b>", styles["TableCellBold"])])
        ai_rows.append([Paragraph("<b>AI Explanation:</b>", styles["TableCellBold"]), Paragraph(str(ai_reason), styles["TableCell"])])

    # YARA matches
    yara_matches = threat_data.get("yara_matches") or []
    yara_str = ", ".join(yara_matches) if yara_matches else "None detected"
    ai_rows.append([Paragraph("<b>YARA Rule Matches:</b>", styles["TableCellBold"]), Paragraph(f"<b>{yara_str}</b>", styles["TableCell"])])

    # Suspicious indicators
    indicators = threat_data.get("suspicious_indicators") or {}
    urls = indicators.get("urls") or []
    ips = indicators.get("ip_addresses") or []
    ind_str = []
    if urls:
        ind_str.append(f"{len(urls)} URL(s): " + ", ".join(urls[:3]))
    if ips:
        ind_str.append(f"{len(ips)} IP(s): " + ", ".join(ips[:3]))
    ai_rows.append([Paragraph("<b>Indicators (URLs / IPs):</b>", styles["TableCellBold"]), Paragraph("; ".join(ind_str) if ind_str else "None detected", styles["TableCell"])])

    ai_table = Table(ai_rows, colWidths=[1.8 * inch, 5.6 * inch])
    ai_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f1f5f9")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(ai_table)
    story.append(Spacer(1, 14))

    # 5. Analysis Description & Recommended Actions
    story.append(Paragraph("Description & Recommended Action", styles["SectionHeader"]))
    desc_text = threat_data.get("description") or "No description provided."
    action_text = threat_data.get("recommended_action") or "Review detection findings."

    desc_rows = [
        [Paragraph("<b>Analysis Narrative:</b>", styles["TableCellBold"]), Paragraph(desc_text, styles["TableCell"])],
        [Paragraph("<b>Recommended Action:</b>", styles["TableCellBold"]), Paragraph(f"<b>{action_text}</b>", styles["TableCell"])],
    ]
    desc_table = Table(desc_rows, colWidths=[1.8 * inch, 5.6 * inch])
    desc_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f8fafc")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(desc_table)
    story.append(Spacer(1, 14))

    # 6. Detection Timeline (if available)
    if timeline:
        story.append(Paragraph("Detection & Activity Timeline", styles["SectionHeader"]))
        tl_rows = [
            [
                Paragraph("<b>Timestamp</b>", styles["TableCellBold"]),
                Paragraph("<b>Event Type</b>", styles["TableCellBold"]),
                Paragraph("<b>Description</b>", styles["TableCellBold"]),
            ]
        ]
        for evt in timeline:
            tl_rows.append([
                Paragraph(str(evt.get("created_at") or evt.get("time") or "N/A"), styles["TableCellMuted"]),
                Paragraph(str(evt.get("event_type") or "event").capitalize(), styles["TableCellBold"]),
                Paragraph(str(evt.get("description") or evt.get("event") or "N/A"), styles["TableCell"]),
            ])
        tl_table = Table(tl_rows, colWidths=[1.8 * inch, 1.4 * inch, 4.2 * inch])
        tl_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(KeepTogether(tl_table))

    # Build PDF
    doc.build(story)
    return buffer.getvalue()


def generate_summary_pdf(summary_report: Dict[str, Any]) -> bytes:
    """
    Generate an executive threat monitoring summary report PDF.
    
    Args:
        summary_report: Dict representation of a ThreatReportResponse.
        
    Returns:
        bytes: The binary PDF data.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36,
    )

    styles = _get_styles()
    story = []

    # Title
    story.append(Paragraph("ThreatLens AI — Threat Monitoring Executive Summary", styles["ReportTitle"]))
    generated_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    story.append(Paragraph(f"Generated: {generated_time}", styles["ReportSubtitle"]))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0284c7"), spaceAfter=14))

    summary = summary_report.get("summary") or {}

    stats_data = [
        [
            Paragraph("<b>Total Scans</b>", styles["TableCellBold"]),
            Paragraph("<b>Malware Detections</b>", styles["TableCellBold"]),
            Paragraph("<b>Benign Files</b>", styles["TableCellBold"]),
            Paragraph("<b>Critical Threats</b>", styles["TableCellBold"]),
        ],
        [
            Paragraph(f"<b>{summary.get('total_files', 0)}</b>", styles["TableCellBold"]),
            Paragraph(f"<font color='#dc2626'><b>{summary.get('malware_files', 0)} ({summary.get('malware_percentage', 0)}%)</b></font>", styles["TableCellBold"]),
            Paragraph(f"<font color='#16a34a'><b>{summary.get('benign_files', 0)} ({summary.get('benign_percentage', 0)}%)</b></font>", styles["TableCellBold"]),
            Paragraph(f"<font color='#dc2626'><b>{summary.get('critical_threats', 0)}</b></font>", styles["TableCellBold"]),
        ],
    ]
    stats_table = Table(stats_data, colWidths=[1.85 * inch, 1.85 * inch, 1.85 * inch, 1.85 * inch])
    stats_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
        ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#f8fafc")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(stats_table)
    story.append(Spacer(1, 16))

    # Risk Distribution Table
    story.append(Paragraph("Threat Risk Level Breakdown", styles["SectionHeader"]))
    risk_data = [
        [
            Paragraph("<b>Critical</b>", styles["TableCellBold"]),
            Paragraph("<b>High</b>", styles["TableCellBold"]),
            Paragraph("<b>Medium</b>", styles["TableCellBold"]),
            Paragraph("<b>Low</b>", styles["TableCellBold"]),
            Paragraph("<b>Active Threats</b>", styles["TableCellBold"]),
            Paragraph("<b>Resolved</b>", styles["TableCellBold"]),
        ],
        [
            Paragraph(str(summary.get("critical_threats", 0)), styles["TableCellBold"]),
            Paragraph(str(summary.get("high_risk_threats", 0)), styles["TableCellBold"]),
            Paragraph(str(summary.get("medium_risk_threats", 0)), styles["TableCellBold"]),
            Paragraph(str(summary.get("low_risk_threats", 0)), styles["TableCellBold"]),
            Paragraph(str(summary.get("active_threats", 0)), styles["TableCellBold"]),
            Paragraph(str(summary.get("resolved_threats", 0)), styles["TableCellBold"]),
        ],
    ]
    risk_table = Table(risk_data, colWidths=[1.23 * inch] * 6)
    risk_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(risk_table)
    story.append(Spacer(1, 16))

    # Recent Critical Threats
    recent_critical = summary_report.get("recent_critical") or []
    if recent_critical:
        story.append(Paragraph("Recent Critical & High Risk Detections", styles["SectionHeader"]))
        rc_rows = [
            [
                Paragraph("<b>Filename</b>", styles["TableCellBold"]),
                Paragraph("<b>Prediction</b>", styles["TableCellBold"]),
                Paragraph("<b>Risk Score</b>", styles["TableCellBold"]),
                Paragraph("<b>Status</b>", styles["TableCellBold"]),
                Paragraph("<b>Timestamp</b>", styles["TableCellBold"]),
            ]
        ]
        for item in recent_critical:
            rc_rows.append([
                Paragraph(str(item.get("filename", "N/A")), styles["TableCell"]),
                Paragraph(str(item.get("prediction", "N/A")), styles["TableCellBold"]),
                Paragraph(f"{item.get('risk_score', 0)}/100", styles["TableCellBold"]),
                Paragraph(str(item.get("status", "N/A")), styles["TableCell"]),
                Paragraph(str(item.get("detected_at") or "N/A")[:19], styles["TableCellMuted"]),
            ])
        rc_table = Table(rc_rows, colWidths=[2.2 * inch, 1.4 * inch, 1.0 * inch, 1.1 * inch, 1.7 * inch])
        rc_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(rc_table)

    doc.build(story)
    return buffer.getvalue()
