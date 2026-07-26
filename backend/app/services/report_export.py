import io
import json

from backend.app.models.report import Report


def export_json(report: Report) -> bytes:

    payload = {
        "id": report.id,
        "title": report.title,
        "status": report.status.value,
        "investigation_ids": report.investigation_ids,
        "executive_summary": report.executive_summary,
        "technical_summary": report.technical_summary,
        "investigation_summary": report.investigation_summary,
        "threat_analysis": report.threat_analysis,
        "risk_explanation": report.risk_explanation,
        "risk_score": report.risk_score,
        "risk_level": report.risk_level.value if report.risk_level else None,
        "indicators_of_compromise": report.indicators_of_compromise,
        "evidence_timeline": report.evidence_timeline,
        "evidence_correlation": report.evidence_correlation,
        "ai_recommendations": report.ai_recommendations,
        "mitre_attack_mapping": report.mitre_attack_mapping,
        "investigation_metadata": report.investigation_metadata,
        "ai_engine_used": report.ai_engine_used.value if report.ai_engine_used else None,
        "confidence_score": report.confidence_score,
        "created_at": report.created_at.isoformat(),
        "updated_at": report.updated_at.isoformat(),
    }

    return json.dumps(payload, indent=2, default=str).encode("utf-8")


def export_markdown(report: Report) -> bytes:

    lines: list[str] = [
        f"# {report.title}",
        "",
        f"**Report ID:** `{report.id}`  ",
        f"**Status:** {report.status.value}  ",
        f"**Generated:** {report.created_at.isoformat()}  ",
    ]

    if report.risk_level:
        lines.append(
            f"**Overall Risk:** {report.risk_level.value.upper()} "
            f"({report.risk_score:.1f}/100)  "
        )

    if report.ai_engine_used:
        lines.append(
            f"**AI Engine:** {report.ai_engine_used.value} "
            f"(confidence: {report.confidence_score or 0:.1f}%)  "
        )

    lines.append("")

    def section(title: str, content: str | None) -> None:

        if not content:
            return

        lines.append(f"## {title}")
        lines.append("")
        lines.append(content)
        lines.append("")

    section("Executive Summary", report.executive_summary)
    section("Technical Summary", report.technical_summary)
    section("Investigation Summary", report.investigation_summary)
    section("Threat Analysis", report.threat_analysis)
    section("Risk Explanation", report.risk_explanation)

    if report.indicators_of_compromise:

        lines.append("## Indicators of Compromise")
        lines.append("")
        lines.append("| Type | Value | Risk Level | Risk Score |")
        lines.append("|---|---|---|---|")

        for ioc in report.indicators_of_compromise:

            lines.append(
                f"| {ioc.get('type', '')} | `{ioc.get('value', '')}` | "
                f"{ioc.get('risk_level') or 'n/a'} | "
                f"{ioc.get('risk_score') if ioc.get('risk_score') is not None else 'n/a'} |"
            )

        lines.append("")

    if report.mitre_attack_mapping:

        lines.append("## MITRE ATT&CK Mapping")
        lines.append("")
        lines.append("| Technique ID | Technique | Tactic |")
        lines.append("|---|---|---|")

        for technique in report.mitre_attack_mapping:

            lines.append(
                f"| {technique.get('technique_id', '')} | "
                f"{technique.get('technique_name', '')} | "
                f"{technique.get('tactic', '')} |"
            )

        lines.append("")

    if report.evidence_timeline:

        lines.append("## Evidence Timeline")
        lines.append("")

        for event in report.evidence_timeline:

            lines.append(f"- **{event.get('timestamp', '')}** - {event.get('event', '')}")

        lines.append("")

    if report.ai_recommendations:

        lines.append("## AI Recommendations")
        lines.append("")

        for recommendation in report.ai_recommendations:
            lines.append(f"- {recommendation}")

        lines.append("")

    return "\n".join(lines).encode("utf-8")


def export_pdf(report: Report) -> bytes:
    """
    Renders the report to PDF using ReportLab. Kept structurally
    parallel to export_markdown() (same section order) so the two
    formats never drift apart in content, only presentation.
    """

    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import LETTER
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import Paragraph
    from reportlab.platypus import SimpleDocTemplate
    from reportlab.platypus import Spacer
    from reportlab.platypus import Table
    from reportlab.platypus import TableStyle

    buffer = io.BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=LETTER,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
        leftMargin=0.75 * inch,
        rightMargin=0.75 * inch,
        title=report.title,
    )

    styles = getSampleStyleSheet()

    heading_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        spaceBefore=14,
        spaceAfter=6,
        textColor=colors.HexColor("#1a1a2e"),
    )

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        textColor=colors.HexColor("#1a1a2e"),
    )

    body_style = ParagraphStyle(
        "Body",
        parent=styles["BodyText"],
        alignment=TA_LEFT,
        spaceAfter=8,
    )

    risk_colors = {
        "low": colors.HexColor("#2e7d32"),
        "medium": colors.HexColor("#f9a825"),
        "high": colors.HexColor("#ef6c00"),
        "critical": colors.HexColor("#c62828"),
    }

    story = [
        Paragraph(_escape(report.title), title_style),
        Spacer(1, 6),
        Paragraph(f"Report ID: {report.id}", styles["Normal"]),
        Paragraph(f"Generated: {report.created_at.isoformat()}", styles["Normal"]),
    ]

    if report.risk_level:

        risk_style = ParagraphStyle(
            "RiskBadge",
            parent=styles["Normal"],
            textColor=risk_colors.get(report.risk_level.value, colors.black),
        )

        story.append(
            Paragraph(
                f"Overall Risk: <b>{report.risk_level.value.upper()}</b> "
                f"({report.risk_score:.1f}/100)",
                risk_style,
            )
        )

    if report.ai_engine_used:
        story.append(
            Paragraph(
                f"AI Engine: {report.ai_engine_used.value} "
                f"(confidence: {report.confidence_score or 0:.1f}%)",
                styles["Normal"],
            )
        )

    def add_section(title: str, content: str | None) -> None:

        if not content:
            return

        story.append(Paragraph(title, heading_style))

        for paragraph in content.split("\n"):
            if paragraph.strip():
                story.append(Paragraph(_escape(paragraph), body_style))

    add_section("Executive Summary", report.executive_summary)
    add_section("Technical Summary", report.technical_summary)
    add_section("Investigation Summary", report.investigation_summary)
    add_section("Threat Analysis", report.threat_analysis)
    add_section("Risk Explanation", report.risk_explanation)

    if report.indicators_of_compromise:

        story.append(Paragraph("Indicators of Compromise", heading_style))

        table_data = [["Type", "Value", "Risk Level", "Score"]]

        for ioc in report.indicators_of_compromise:

            table_data.append(
                [
                    str(ioc.get("type", "")),
                    str(ioc.get("value", "")),
                    str(ioc.get("risk_level") or "n/a"),
                    (
                        f"{ioc.get('risk_score'):.1f}"
                        if ioc.get("risk_score") is not None
                        else "n/a"
                    ),
                ]
            )

        ioc_table = Table(table_data, repeatRows=1)
        ioc_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ]
            )
        )
        story.append(ioc_table)
        story.append(Spacer(1, 10))

    if report.mitre_attack_mapping:

        story.append(Paragraph("MITRE ATT&CK Mapping", heading_style))

        mitre_data = [["Technique ID", "Technique", "Tactic"]]

        for technique in report.mitre_attack_mapping:

            mitre_data.append(
                [
                    str(technique.get("technique_id", "")),
                    str(technique.get("technique_name", "")),
                    str(technique.get("tactic", "")),
                ]
            )

        mitre_table = Table(mitre_data, repeatRows=1)
        mitre_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ]
            )
        )
        story.append(mitre_table)
        story.append(Spacer(1, 10))

    if report.ai_recommendations:

        story.append(Paragraph("AI Recommendations", heading_style))

        for recommendation in report.ai_recommendations:
            story.append(Paragraph(f"&bull; {_escape(recommendation)}", body_style))

    document.build(story)

    return buffer.getvalue()


def _escape(text: str) -> str:
    """Minimal HTML escaping for ReportLab's Paragraph mini-markup."""

    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )
