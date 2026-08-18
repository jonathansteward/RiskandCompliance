"""Daily elevated-risk report: pulls current risk data live from
ServiceNow, diffs against native audit history to show what changed since
the last run, renders a structured PDF, and delivers it via Slack (summary
with clickable links) and email (summary + PDF attached).
"""
import os
from datetime import datetime, timedelta, timezone

import requests
from reportlab.lib import colors
from reportlab.lib.pagesizes import landscape, letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

from risk.fair_model import RULE_CONTROLS

REPORT_RATINGS = {"Medium High", "High"}
REPORT_PATH = "daily_risk_report.pdf"


def _servicenow_link(sn_i, sys_id):
    return f"https://{sn_i}.service-now.com/sn_risk_risk.do?sys_id={sys_id}"


def get_elevated_risks(sn_i, sn_u, sn_p, sn_t):
    """Every currently non-compliant, Medium High/High risk finding.

    Cross-references two plain, Python-controlled fields directly - u_status
    on the control-mapping table, u_risk_rating on the risk record - rather
    than relying on sn_risk_risk's native `active` field, which turned out
    to be governed by a risk lifecycle workflow that resists direct API
    writes (see SOP.md). Entirely sidesteps that, at the cost of one extra
    query per control.
    """
    headers = {"Accept": "application/json"}
    status_url = f"https://{sn_i}.service-now.com/api/now/table/{sn_t}"
    risk_url = f"https://{sn_i}.service-now.com/api/now/table/sn_risk_risk"

    elevated = []
    for rule_name, controls in RULE_CONTROLS.items():
        status_response = requests.get(
            f"{status_url}?sysparm_query=u_aws_config_rule_name={rule_name}&sysparm_fields=u_status",
            auth=(sn_u, sn_p), headers=headers,
        )
        results = status_response.json().get("result", [])
        if not results or results[0].get("u_status") != "NON_COMPLIANT":
            continue

        for control in controls:
            risk_response = requests.get(
                f"{risk_url}?sysparm_query=u_compliance_control={control['sys_id']}&sysparm_limit=1",
                auth=(sn_u, sn_p), headers=headers,
            )
            risk_results = risk_response.json().get("result", [])
            if not risk_results:
                continue

            record = risk_results[0]
            rating = record.get("u_risk_rating")
            if rating not in REPORT_RATINGS:
                continue

            elevated.append({
                "rule_name": rule_name,
                "control_name": control["name"],
                "rating": rating,
                "inherent_ale": float(record.get("inherent_ale") or 0),
                "owner_email": record.get("u_risk_owner_email", ""),
                "number": record.get("number"),
                "sys_id": record.get("sys_id"),
                "link": _servicenow_link(sn_i, record.get("sys_id")),
            })

    return elevated


def get_changes_since_last_run(sn_i, sn_u, sn_p, elevated_risks, hours=24):
    """Split elevated risks into changed-since-last-run vs. persisting,
    using sys_audit - ServiceNow's native field-change history, enabled on
    u_risk_rating specifically for this. No separate local state file to
    keep in sync; the platform's own audit trail is the source of truth.
    """
    headers = {"Accept": "application/json"}
    audit_url = f"https://{sn_i}.service-now.com/api/now/table/sys_audit"
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")

    changed, unchanged = [], []
    for risk in elevated_risks:
        query = (
            f"documentkey={risk['sys_id']}^fieldname=u_risk_rating"
            f"^sys_created_on>={cutoff}^ORDERBYsys_created_on"
        )
        response = requests.get(
            f"{audit_url}?sysparm_query={query}&sysparm_fields=oldvalue,newvalue",
            auth=(sn_u, sn_p), headers=headers,
        )
        entries = response.json().get("result", [])

        if entries:
            previous = entries[0].get("oldvalue") or "(new)"
            changed.append({**risk, "previous_rating": previous})
        else:
            unchanged.append(risk)

    return changed, unchanged


def _get_risk_record_sys_id(sn_i, sn_u, sn_p, control_sys_id):
    url = f"https://{sn_i}.service-now.com/api/now/table/sn_risk_risk"
    headers = {"Accept": "application/json"}
    response = requests.get(
        f"{url}?sysparm_query=u_compliance_control={control_sys_id}&sysparm_limit=1&sysparm_fields=sys_id",
        auth=(sn_u, sn_p), headers=headers,
    )
    results = response.json().get("result", [])
    return results[0]["sys_id"] if results else None


def get_change_history(sn_i, sn_u, sn_p, days=90):
    """Full rating/exposure change history across every tracked control,
    not just today's window - the trend view. Deliberately thin right now
    since sys_audit was only enabled today; fills in naturally as the
    pipeline runs daily going forward, rather than fabricating history
    that doesn't exist yet.
    """
    headers = {"Accept": "application/json"}
    audit_url = f"https://{sn_i}.service-now.com/api/now/table/sys_audit"
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")

    label_by_sys_id = {}
    for rule_name, controls in RULE_CONTROLS.items():
        for control in controls:
            risk_sys_id = _get_risk_record_sys_id(sn_i, sn_u, sn_p, control["sys_id"])
            if risk_sys_id:
                label_by_sys_id[risk_sys_id] = f"{rule_name} ({control['name']})"

    if not label_by_sys_id:
        return []

    query = (
        f"documentkeyIN{','.join(label_by_sys_id.keys())}"
        f"^fieldnameINu_risk_rating,inherent_ale"
        f"^sys_created_on>={cutoff}"
        f"^ORDERBYsys_created_on"
    )
    response = requests.get(
        f"{audit_url}?sysparm_query={query}"
        f"&sysparm_fields=documentkey,fieldname,oldvalue,newvalue,sys_created_on",
        auth=(sn_u, sn_p), headers=headers,
    )

    history = []
    for entry in response.json().get("result", []):
        is_exposure = entry.get("fieldname") == "inherent_ale"
        new_value = entry.get("newvalue") or ""
        old_value = entry.get("oldvalue") or "(new)"
        if is_exposure:
            try:
                new_value = f"${float(new_value):,.0f}"
                old_value = f"${float(old_value):,.0f}" if old_value != "(new)" else old_value
            except ValueError:
                pass

        history.append({
            "date": (entry.get("sys_created_on") or "")[:10],
            "control_label": label_by_sys_id.get(entry.get("documentkey"), "(unknown)"),
            "field": "Annual Exposure" if is_exposure else "Rating",
            "old_value": old_value,
            "new_value": new_value,
        })

    return history


_PAGE_SIZE = landscape(letter)
_MARGIN = 0.6 * inch
_RATING_COLORS = {"High": colors.HexColor("#b91c1c"), "Medium High": colors.HexColor("#c2410c")}


def _footer(canvas, doc):
    """Page number + generation timestamp + confidentiality note, drawn on
    every page - the one piece that needs the canvas directly rather than
    a platypus flowable, since it's fixed to the page, not the flow."""
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#6b7280"))
    text = (
        f"Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}  "
        f"·  Confidential  ·  Page {doc.page}"
    )
    canvas.drawCentredString(_PAGE_SIZE[0] / 2, 0.4 * inch, text)
    canvas.restoreState()


def build_pdf_report(changed, unchanged, history=None, output_path=REPORT_PATH):
    """Render the structured PDF: a colored header band, a summary line,
    then one table each for what changed since the last run and what's
    persisting - every cell wrapped in a Paragraph so long content wraps
    within its column instead of overflowing into the next one.
    """
    styles = getSampleStyleSheet()
    normal = ParagraphStyle("normal", parent=styles["Normal"], fontSize=9, leading=12)
    cell = ParagraphStyle("cell", parent=normal, fontSize=8.5, leading=11)
    header_cell = ParagraphStyle(
        "header_cell", parent=cell, textColor=colors.white, fontName="Helvetica-Bold"
    )
    link_style = ParagraphStyle("link", parent=cell, textColor=colors.HexColor("#1a73e8"))
    title_style = ParagraphStyle(
        "title", parent=styles["Title"], textColor=colors.white, alignment=0, fontSize=20
    )
    caption_style = ParagraphStyle(
        "caption", parent=normal, textColor=colors.HexColor("#e5e7eb"), fontSize=10
    )
    disclaimer_style = ParagraphStyle(
        "disclaimer", parent=normal, textColor=colors.HexColor("#6b7280"), fontSize=8, leading=11
    )

    doc = SimpleDocTemplate(
        output_path, pagesize=_PAGE_SIZE,
        topMargin=0, bottomMargin=0.75 * inch, leftMargin=_MARGIN, rightMargin=_MARGIN,
    )
    content_width = _PAGE_SIZE[0] - 2 * _MARGIN

    # Header band: full-bleed dark bar with title + date + at-a-glance counts
    total = len(changed) + len(unchanged)
    summary_text = (
        f"{total} elevated finding{'s' if total != 1 else ''} today "
        f"&mdash; {len(changed)} new/changed &middot; {len(unchanged)} persisting"
    )
    header_table = Table(
        [[Paragraph("Daily Elevated Risk Report", title_style)],
         [Paragraph(datetime.now(timezone.utc).strftime("%B %d, %Y"), caption_style)],
         [Paragraph(summary_text, caption_style)]],
        colWidths=[_PAGE_SIZE[0]],
    )
    header_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#111827")),
        ("LEFTPADDING", (0, 0), (-1, -1), _MARGIN),
        ("RIGHTPADDING", (0, 0), (-1, -1), _MARGIN),
        ("TOPPADDING", (0, 0), (0, 0), 22),
        ("BOTTOMPADDING", (0, 0), (0, 0), 4),
        ("TOPPADDING", (0, 1), (0, 2), 2),
        ("BOTTOMPADDING", (0, 2), (0, 2), 20),
    ]))

    elements = [
        header_table,
        Spacer(1, 0.25 * inch),
        Paragraph(
            "Non-compliant AWS controls currently rated Medium High or High, based on a "
            "FAIR-informed Monte Carlo risk model. Loss ranges are illustrative, reasoned "
            "from published industry breach-cost benchmarks, not this organization's own "
            "incident history.",
            disclaimer_style,
        ),
        Spacer(1, 0.3 * inch),
    ]

    col_widths = [
        content_width * 0.27,  # Control
        content_width * 0.16,  # Rating
        content_width * 0.13,  # Annual Exposure
        content_width * 0.20,  # Owner
        content_width * 0.14,  # Record
    ]

    def section(title, risks, empty_message):
        elements.append(Paragraph(title, styles["Heading2"]))
        elements.append(Spacer(1, 0.05 * inch))
        if not risks:
            elements.append(Paragraph(empty_message, normal))
            elements.append(Spacer(1, 0.3 * inch))
            return

        header = [Paragraph(h, header_cell) for h in
                   ["Control", "Rating", "Annual Exposure", "Owner", "Record"]]
        data = [header]
        for risk in risks:
            rating_text = risk["rating"]
            if "previous_rating" in risk:
                rating_text = f"{risk['previous_rating']} &rarr; {risk['rating']}"
            rating_style = ParagraphStyle(
                "rating", parent=cell, textColor=_RATING_COLORS.get(risk["rating"], colors.black),
                fontName="Helvetica-Bold",
            )
            data.append([
                Paragraph(f"<b>{risk['rule_name']}</b><br/>{risk['control_name']}", cell),
                Paragraph(rating_text, rating_style),
                Paragraph(f"${risk['inherent_ale']:,.0f}/yr", cell),
                Paragraph(risk["owner_email"], cell),
                Paragraph(f'<link href="{risk["link"]}">{risk["number"]}</link>', link_style),
            ])

        table = Table(data, colWidths=col_widths, repeatRows=1)
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d1d5db")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f9fafb")]),
        ]))
        elements.append(table)
        elements.append(Spacer(1, 0.35 * inch))

    section("New / Changed Since Last Run", changed, "No rating changes since the last run.")
    section("Persisting Risks (Unchanged)", unchanged, "No unchanged elevated risks.")

    # Trend section: every recorded change across all tracked controls, not
    # just today's window. Deliberately thin right now - change history was
    # only enabled today - and fills in naturally as the pipeline runs.
    elements.append(Paragraph("Change History (Trend)", styles["Heading2"]))
    elements.append(Spacer(1, 0.05 * inch))
    elements.append(Paragraph(
        "Every recorded rating/exposure change across all tracked controls, oldest first. "
        "Native change tracking was enabled for this report; expect this section to grow "
        "day over day rather than show meaningful trends from a single day's data.",
        disclaimer_style,
    ))
    elements.append(Spacer(1, 0.1 * inch))

    if not history:
        elements.append(Paragraph("No change history recorded yet.", normal))
    else:
        trend_widths = [
            content_width * 0.12,  # Date
            content_width * 0.34,  # Control
            content_width * 0.16,  # Field
            content_width * 0.38,  # Old -> New
        ]
        header = [Paragraph(h, header_cell) for h in ["Date", "Control", "Field", "Change"]]
        data = [header]
        for entry in history:
            data.append([
                Paragraph(entry["date"], cell),
                Paragraph(entry["control_label"], cell),
                Paragraph(entry["field"], cell),
                Paragraph(f"{entry['old_value']} &rarr; {entry['new_value']}", cell),
            ])

        trend_table = Table(data, colWidths=trend_widths, repeatRows=1)
        trend_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d1d5db")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f9fafb")]),
        ]))
        elements.append(trend_table)

    doc.build(elements, onFirstPage=_footer, onLaterPages=_footer)
    return output_path


def send_daily_report(sn_i, sn_u, sn_p, sn_t, webhook_url, from_email, to_email, owner_email,
                       smtp_server, smtp_port, app_password):
    """Full daily pipeline: pull elevated risks from ServiceNow, diff
    against audit history, build the PDF, and deliver via Slack + email.
    No-ops cleanly if there's nothing Medium High/High to report.
    """
    from notifications.notify import build_risk_digest, send_risk_digest_slack, send_risk_report_email

    elevated = get_elevated_risks(sn_i, sn_u, sn_p, sn_t)
    if not elevated:
        print("No non-compliant Medium High/High risks today - no report sent.")
        return

    changed, unchanged = get_changes_since_last_run(sn_i, sn_u, sn_p, elevated)
    history = get_change_history(sn_i, sn_u, sn_p)
    build_pdf_report(changed, unchanged, history, REPORT_PATH)

    if webhook_url:
        send_risk_digest_slack(webhook_url, changed, unchanged)

    if all([from_email, to_email, smtp_server, smtp_port, app_password]):
        summary = build_risk_digest(changed, unchanged)
        recipients = sorted({to_email, owner_email})
        send_risk_report_email(
            from_email, recipients, smtp_server, smtp_port, app_password, REPORT_PATH, summary,
        )


if __name__ == "__main__":
    # Manual test harness: python -m risk.report
    from dotenv import load_dotenv

    load_dotenv()

    send_daily_report(
        sn_i=os.getenv("SN_I"),
        sn_u=os.getenv("SN_U"),
        sn_p=os.getenv("SN_P"),
        sn_t=os.getenv("SN_T"),
        webhook_url=os.getenv("SLACK_WEBHOOK_URL"),
        from_email=os.getenv("EMAIL_FROM"),
        to_email=os.getenv("EMAIL_TO"),
        owner_email="priya.natarajan@example.com",
        smtp_server=os.getenv("SMTP_SERVER"),
        smtp_port=os.getenv("SMTP_PORT"),
        app_password=os.getenv("EMAIL_APP_PASSWORD"),
    )
