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

from risk.fair_model import RULE_CONTROLS, RULE_MAPPING_SYS_IDS

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
                # Carries the risk narrative + the denormalized "Current
                # gap" text (see push_risk_to_servicenow) - the actual
                # substance an executive summary needs, not just numbers.
                "description": record.get("description", ""),
            })

    return elevated


def get_other_noncompliant(sn_i, sn_u, sn_p, sn_t, already_shown_numbers):
    """Every other currently non-compliant rule not already covered by the
    elevated (Medium High/High) findings above - either risk-scored but
    rated lower, or not control-mapped/risk-scored at all (e.g. rules
    RULE_CONTROLS doesn't cover yet, like subnet-auto-assign-public-ip-disabled).

    Non-compliant controls shouldn't disappear from the report just
    because they're not elevated - they belong in their own, lower-
    priority section rather than being silently dropped.
    """
    headers = {"Accept": "application/json"}
    status_url = f"https://{sn_i}.service-now.com/api/now/table/{sn_t}"
    risk_url = f"https://{sn_i}.service-now.com/api/now/table/sn_risk_risk"

    response = requests.get(
        f"{status_url}?sysparm_fields=u_aws_config_rule_name,u_status,u_compliance_control",
        auth=(sn_u, sn_p), headers=headers,
    )

    others = []
    for row in response.json().get("result", []):
        if row.get("u_status") != "NON_COMPLIANT":
            continue

        rule_name = row.get("u_aws_config_rule_name")
        control_sys_id = row.get("u_compliance_control")
        if isinstance(control_sys_id, dict):
            control_sys_id = control_sys_id.get("value")

        entry = {
            "rule_name": rule_name, "control_name": None, "rating": "Not risk-scored",
            "inherent_ale": None, "number": None, "link": None,
        }

        if control_sys_id:
            risk_response = requests.get(
                f"{risk_url}?sysparm_query=u_compliance_control={control_sys_id}&sysparm_limit=1",
                auth=(sn_u, sn_p), headers=headers,
            )
            risk_results = risk_response.json().get("result", [])
            if risk_results:
                record = risk_results[0]
                if record.get("number") in already_shown_numbers:
                    continue  # already covered in the elevated section
                entry["rating"] = record.get("u_risk_rating") or "Not rated"
                entry["inherent_ale"] = float(record.get("inherent_ale") or 0)
                entry["number"] = record.get("number")
                entry["link"] = _servicenow_link(sn_i, record.get("sys_id"))

        others.append(entry)

    return others


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
        return {}

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

    def _format_exposure(value):
        if not value:
            return "(new)"
        try:
            return f"${float(value):,.0f}"
        except ValueError:
            return value

    # Merge the rating change and the exposure change from the same update
    # into one row - they come from the same PATCH, so sys_created_on
    # matches to the second, and showing them as two disconnected rows
    # (as the first version of this did) makes a single event look like
    # two unrelated ones.
    moments = {}
    for entry in response.json().get("result", []):
        key = (entry.get("documentkey"), entry.get("sys_created_on"))
        moment = moments.setdefault(key, {
            # Full date+time, not just the date - more than one run can
            # (and did, while building this) land on the same calendar day.
            "date": entry.get("sys_created_on") or "",
            "control_label": label_by_sys_id.get(entry.get("documentkey"), "(unknown)"),
            "rating": None,
            "exposure": None,
            "sort_key": entry.get("sys_created_on") or "",
        })
        if entry.get("fieldname") == "u_risk_rating":
            moment["rating"] = (entry.get("oldvalue") or "(new)", entry.get("newvalue") or "")
        else:
            moment["exposure"] = (_format_exposure(entry.get("oldvalue")), _format_exposure(entry.get("newvalue")))

    # Group by control so each control's own story reads as one sequence,
    # rather than interleaving every control's changes into one timeline.
    by_control = {}
    for moment in moments.values():
        by_control.setdefault(moment["control_label"], []).append(moment)
    for control_moments in by_control.values():
        control_moments.sort(key=lambda m: m["sort_key"], reverse=True)

    return by_control


def generate_executive_summary(claude_client, changed, unchanged):
    """Ask Claude to synthesize today's elevated-risk picture into a short
    executive summary grounded in each finding's actual evidence gap, not
    just a table of numbers.

    Single forced tool call, same structured-output pattern as
    agent/remediation.py - every input is already assembled (rating,
    exposure, the denormalized gap text), so there's no case-by-case
    decision an autonomous multi-step agent would be making here either.
    Returns None if there's nothing to summarize or no Claude client.
    """
    if not claude_client or (not changed and not unchanged):
        return None

    findings_text = []
    for risk in changed + unchanged:
        status = "NEW/CHANGED" if "previous_rating" in risk else "PERSISTING"
        findings_text.append(
            f"[{status}] {risk['rule_name']} ({risk['control_name']}) - "
            f"{risk['rating']}, ${risk['inherent_ale']:,.0f}/yr\n{risk.get('description', '')}"
        )

    prompt = (
        "You are drafting the executive summary for a daily risk report going to a risk "
        "owner and engineering leadership. Given the elevated (Medium High/High) findings "
        "below, write a 3-5 sentence summary of what's driving today's elevated risk "
        "picture and why it matters. Be specific about the actual gaps described - do not "
        "invent facts not present in the findings, and do not just restate the numbers.\n\n"
        + "\n\n".join(findings_text)
    )

    tool = {
        "name": "submit_executive_summary",
        "description": "Submit the executive summary for the daily risk report.",
        "input_schema": {
            "type": "object",
            "properties": {
                "summary": {
                    "type": "string",
                    "description": "3-5 sentence executive summary, specific to the findings given.",
                },
            },
            "required": ["summary"],
        },
    }

    response = claude_client.messages.create(
        model="claude-sonnet-5",
        max_tokens=512,
        tools=[tool],
        tool_choice={"type": "tool", "name": "submit_executive_summary"},
        messages=[{"role": "user", "content": prompt}],
    )

    if response.stop_reason == "max_tokens":
        print("Executive summary generation was cut off (max_tokens) - skipping.")
        return None

    tool_use_block = next(block for block in response.content if block.type == "tool_use")
    return tool_use_block.input["summary"]


def generate_noncompliance_summaries(claude_client, findings):
    """One Claude call covering every elevated finding - not one call per
    control - returning a distinct non-compliance summary per record,
    parsed back into a dict keyed by record number.

    Same single-forced-tool-call pattern as generate_executive_summary();
    the difference is the output is an array (one item per control) that
    gets matched back to its row, instead of one blended paragraph.
    """
    if not claude_client or not findings:
        return {}

    findings_text = [
        f"Record {f['number']}: {f['rule_name']} ({f['control_name']})\n{f.get('description', '')}"
        for f in findings
    ]

    prompt = (
        "For each finding below, write a distinct 2-3 sentence summary of why that "
        "specific control is non-compliant, grounded only in the information given for "
        "that record. Return exactly one summary per record number listed - do not merge "
        "or skip any.\n\n" + "\n\n".join(findings_text)
    )

    tool = {
        "name": "submit_noncompliance_summaries",
        "description": "Submit one non-compliance summary per finding record.",
        "input_schema": {
            "type": "object",
            "properties": {
                "summaries": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "record_number": {"type": "string"},
                            "summary": {"type": "string"},
                        },
                        "required": ["record_number", "summary"],
                    },
                },
            },
            "required": ["summaries"],
        },
    }

    response = claude_client.messages.create(
        model="claude-sonnet-5",
        max_tokens=1536,
        tools=[tool],
        tool_choice={"type": "tool", "name": "submit_noncompliance_summaries"},
        messages=[{"role": "user", "content": prompt}],
    )

    if response.stop_reason == "max_tokens":
        print("Non-compliance summaries were cut off (max_tokens) - skipping.")
        return {}

    tool_use_block = next(block for block in response.content if block.type == "tool_use")
    return {item["record_number"]: item["summary"] for item in tool_use_block.input["summaries"]}


def get_recommended_fixes(sn_i, sn_u, sn_p, findings):
    """Recommended fix per finding, pulled from ServiceNow's already-
    generated remediation guidance (u_aws_config_evidence.u_remediation_steps,
    produced by agent/remediation.py during the main pipeline run) - not
    regenerated here. Cached per rule so cloudtrail's two controls, which
    share one evidence trail, only cost one lookup.
    """
    import grc_validation

    fixes_by_rule = {}
    fixes_by_number = {}
    for finding in findings:
        rule_name = finding["rule_name"]
        if rule_name not in fixes_by_rule:
            mapping_sys_id = RULE_MAPPING_SYS_IDS.get(rule_name)
            guidance = (
                grc_validation.get_latest_evidence_guidance(sn_i, sn_u, sn_p, mapping_sys_id)
                if mapping_sys_id else None
            )
            fixes_by_rule[rule_name] = guidance.get("remediation_steps_text", "") if guidance else ""
        fixes_by_number[finding["number"]] = fixes_by_rule[rule_name]

    return fixes_by_number


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


def build_pdf_report(changed, unchanged, history=None, executive_summary=None,
                      noncompliance_summaries=None, recommended_fixes=None, other_noncompliant=None,
                      output_path=REPORT_PATH):
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
    summary_body_style = ParagraphStyle(
        "summary_body", parent=normal, fontSize=10.5, leading=15
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

    if executive_summary:
        elements.append(Paragraph("Executive Summary", styles["Heading2"]))
        elements.append(Spacer(1, 0.08 * inch))
        elements.append(Paragraph(executive_summary, summary_body_style))
        elements.append(Spacer(1, 0.35 * inch))

    noncompliance_summaries = noncompliance_summaries or {}
    recommended_fixes = recommended_fixes or {}

    # Owner dropped from this table (was a constant demo value across every
    # row, low information density) to make room for the two prose columns
    # below, which are what actually need the width.
    col_widths = [
        content_width * 0.16,  # Control
        content_width * 0.09,  # Rating
        content_width * 0.27,  # Non-Compliance Summary
        content_width * 0.27,  # Recommended Fix
        content_width * 0.11,  # Annual Exposure
        content_width * 0.10,  # Record
    ]

    def section(title, risks, empty_message):
        elements.append(Paragraph(title, styles["Heading2"]))
        elements.append(Spacer(1, 0.05 * inch))
        if not risks:
            elements.append(Paragraph(empty_message, normal))
            elements.append(Spacer(1, 0.3 * inch))
            return

        header = [Paragraph(h, header_cell) for h in
                   ["Control", "Rating", "Non-Compliance Summary", "Recommended Fix", "Annual Exposure", "Record"]]
        data = [header]
        for risk in risks:
            rating_text = risk["rating"]
            if "previous_rating" in risk:
                rating_text = f"{risk['previous_rating']} &rarr; {risk['rating']}"
            rating_style = ParagraphStyle(
                "rating", parent=cell, textColor=_RATING_COLORS.get(risk["rating"], colors.black),
                fontName="Helvetica-Bold",
            )
            summary_text = noncompliance_summaries.get(risk["number"]) or risk.get("description", "").split("\n\n")[0]
            fix_text = (recommended_fixes.get(risk["number"]) or "No remediation guidance recorded yet.")
            data.append([
                Paragraph(f"<b>{risk['rule_name']}</b><br/>{risk['control_name']}", cell),
                Paragraph(rating_text, rating_style),
                Paragraph(summary_text, cell),
                Paragraph(fix_text.replace("\n", "<br/>"), cell),
                Paragraph(f"${risk['inherent_ale']:,.0f}/yr", cell),
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

    # Non-compliant controls that aren't elevated - lower-rated, or not yet
    # risk-scored at all - still shown, just not mixed in with the
    # Medium High/High findings above.
    elements.append(Paragraph("Other Non-Compliant Controls", styles["Heading2"]))
    elements.append(Spacer(1, 0.05 * inch))
    if not other_noncompliant:
        elements.append(Paragraph("No other non-compliant controls right now.", normal))
        elements.append(Spacer(1, 0.3 * inch))
    else:
        other_widths = [content_width * 0.4, content_width * 0.2, content_width * 0.2, content_width * 0.2]
        header = [Paragraph(h, header_cell) for h in ["Rule", "Rating", "Annual Exposure", "Record"]]
        data = [header]
        for entry in other_noncompliant:
            exposure_text = f"${entry['inherent_ale']:,.0f}/yr" if entry["inherent_ale"] is not None else "&mdash;"
            record_cell = (
                Paragraph(f'<link href="{entry["link"]}">{entry["number"]}</link>', link_style)
                if entry["link"] else Paragraph("&mdash;", cell)
            )
            data.append([
                Paragraph(entry["rule_name"], cell),
                Paragraph(entry["rating"], cell),
                Paragraph(exposure_text, cell),
                record_cell,
            ])

        other_table = Table(data, colWidths=other_widths, repeatRows=1)
        other_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d1d5db")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f9fafb")]),
        ]))
        elements.append(other_table)
        elements.append(Spacer(1, 0.35 * inch))

    # Trend section: every recorded change across all tracked controls, not
    # just today's window. Deliberately thin right now - change history was
    # only enabled today - and fills in naturally as the pipeline runs.
    elements.append(Paragraph("Change History (Trend)", styles["Heading2"]))
    elements.append(Spacer(1, 0.05 * inch))
    elements.append(Paragraph(
        "Every recorded rating/exposure change across all tracked controls, newest first. "
        "Native change tracking was enabled for this report; expect this section to grow "
        "day over day rather than show meaningful trends from a single day's data.",
        disclaimer_style,
    ))
    elements.append(Spacer(1, 0.1 * inch))

    if not history:
        elements.append(Paragraph("No change history recorded yet.", normal))
    else:
        control_style = ParagraphStyle(
            "control_name", parent=normal, fontSize=10, fontName="Helvetica-Bold",
        )
        trend_widths = [content_width * 0.22, content_width * 0.39, content_width * 0.39]

        for control_label, moments in history.items():
            elements.append(Paragraph(control_label, control_style))
            elements.append(Spacer(1, 0.06 * inch))

            header = [Paragraph(h, header_cell) for h in ["Date/Time (UTC)", "Rating", "Annual Exposure"]]
            data = [header]
            for moment in moments:
                rating_text = "&mdash;"
                if moment["rating"]:
                    old, new = moment["rating"]
                    rating_text = f"{old} &rarr; {new}"
                exposure_text = "&mdash;"
                if moment["exposure"]:
                    old, new = moment["exposure"]
                    exposure_text = f"{old} &rarr; {new}"

                data.append([
                    Paragraph(moment["date"], cell),
                    Paragraph(rating_text, cell),
                    Paragraph(exposure_text, cell),
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
            elements.append(Spacer(1, 0.25 * inch))

    doc.build(elements, onFirstPage=_footer, onLaterPages=_footer)
    return output_path


def send_daily_report(sn_i, sn_u, sn_p, sn_t, slack_bot_token, slack_channel_id,
                       from_email, to_email, owner_email, smtp_server, smtp_port, app_password,
                       claude_client=None):
    """Full daily pipeline: pull elevated risks from ServiceNow, diff
    against audit history, build the PDF (with a Claude-written executive
    summary when a client is provided), and deliver via Slack + email -
    both just the PDF itself, no text digest in either channel.
    No-ops cleanly if there's nothing Medium High/High to report.
    """
    from notifications.notify import send_risk_report_email, send_risk_report_slack_file

    elevated = get_elevated_risks(sn_i, sn_u, sn_p, sn_t)
    other_noncompliant = get_other_noncompliant(
        sn_i, sn_u, sn_p, sn_t, {risk["number"] for risk in elevated}
    )
    if not elevated and not other_noncompliant:
        print("No non-compliant controls today - no report sent.")
        return

    changed, unchanged = get_changes_since_last_run(sn_i, sn_u, sn_p, elevated)
    history = get_change_history(sn_i, sn_u, sn_p)
    all_findings = changed + unchanged
    executive_summary = generate_executive_summary(claude_client, changed, unchanged)
    noncompliance_summaries = generate_noncompliance_summaries(claude_client, all_findings)
    recommended_fixes = get_recommended_fixes(sn_i, sn_u, sn_p, all_findings)
    build_pdf_report(
        changed, unchanged, history, executive_summary,
        noncompliance_summaries, recommended_fixes, other_noncompliant, REPORT_PATH,
    )

    if slack_bot_token and slack_channel_id:
        send_risk_report_slack_file(slack_bot_token, slack_channel_id, REPORT_PATH)

    if all([from_email, to_email, smtp_server, smtp_port, app_password]):
        recipients = sorted({to_email, owner_email})
        send_risk_report_email(
            from_email, recipients, smtp_server, smtp_port, app_password, REPORT_PATH,
        )


if __name__ == "__main__":
    # Manual test harness: python -m risk.report
    import anthropic
    from dotenv import load_dotenv

    load_dotenv()

    api_key = os.getenv("ANTHROPIC_API_KEY")
    claude_client = anthropic.Anthropic(api_key=api_key) if api_key else None

    send_daily_report(
        sn_i=os.getenv("SN_I"),
        sn_u=os.getenv("SN_U"),
        sn_p=os.getenv("SN_P"),
        sn_t=os.getenv("SN_T"),
        slack_bot_token=os.getenv("SLACK_BOT_TOKEN"),
        slack_channel_id=os.getenv("SLACK_CHANNEL_ID"),
        from_email=os.getenv("EMAIL_FROM"),
        to_email=os.getenv("EMAIL_TO"),
        owner_email="priya.natarajan@example.com",
        smtp_server=os.getenv("SMTP_SERVER"),
        smtp_port=os.getenv("SMTP_PORT"),
        app_password=os.getenv("EMAIL_APP_PASSWORD"),
        claude_client=claude_client,
    )
