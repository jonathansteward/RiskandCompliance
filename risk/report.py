"""Daily elevated-risk report: pulls current risk data live from
ServiceNow, diffs against native audit history to show what changed since
the last run, renders a structured PDF, and delivers it via Slack (summary
with clickable links) and email (summary + PDF attached).
"""
import os
from datetime import datetime, timedelta, timezone

import requests
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
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


def build_pdf_report(changed, unchanged, output_path=REPORT_PATH):
    """Render the structured PDF: title/methodology note, then a table for
    what changed since the last run and a table for what's persisting.
    """
    styles = getSampleStyleSheet()
    normal = styles["Normal"]
    link_style = ParagraphStyle("link", parent=normal, textColor=colors.HexColor("#1a73e8"))

    doc = SimpleDocTemplate(output_path, pagesize=letter, topMargin=0.75 * inch, bottomMargin=0.75 * inch)
    elements = [
        Paragraph("Daily Elevated Risk Report", styles["Title"]),
        Paragraph(datetime.now(timezone.utc).strftime("%B %d, %Y"), normal),
        Spacer(1, 0.15 * inch),
        Paragraph(
            "Non-compliant AWS controls currently rated Medium High or High, based on a "
            "FAIR-informed Monte Carlo risk model. Loss ranges are illustrative, reasoned "
            "from published industry breach-cost benchmarks, not this organization's own "
            "incident history.",
            normal,
        ),
        Spacer(1, 0.3 * inch),
    ]

    def section(title, risks, empty_message):
        elements.append(Paragraph(title, styles["Heading2"]))
        if not risks:
            elements.append(Paragraph(empty_message, normal))
            elements.append(Spacer(1, 0.25 * inch))
            return

        header = ["Control", "Rating", "Annual Exposure", "Owner", "Record"]
        data = [header]
        for risk in risks:
            rating_cell = risk["rating"]
            if "previous_rating" in risk:
                rating_cell = f"{risk['previous_rating']} -> {risk['rating']}"
            data.append([
                Paragraph(f"{risk['rule_name']}<br/>({risk['control_name']})", normal),
                rating_cell,
                f"${risk['inherent_ale']:,.0f}",
                risk["owner_email"],
                Paragraph(f'<link href="{risk["link"]}">{risk["number"]}</link>', link_style),
            ])

        table = Table(data, colWidths=[1.9 * inch, 1.1 * inch, 1.1 * inch, 1.6 * inch, 0.8 * inch])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d1d5db")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f9fafb")]),
        ]))
        elements.append(table)
        elements.append(Spacer(1, 0.3 * inch))

    section("New / Changed Since Last Run", changed, "No rating changes since the last run.")
    section("Persisting Risks (Unchanged)", unchanged, "No unchanged elevated risks.")

    doc.build(elements)
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
    build_pdf_report(changed, unchanged, REPORT_PATH)

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
