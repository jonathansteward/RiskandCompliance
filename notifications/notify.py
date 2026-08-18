import smtplib
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import requests


def build_drift_report(drift):
    """Human-readable drift summary, shared by Slack and email.

    Built directly from the drift facts already in memory - no ServiceNow
    round-trip - so notification stays fast and never depends on anything
    else in the pipeline succeeding.
    """
    if not drift:
        return "No compliance drift detected."

    lines = []
    for change in drift:
        rule = change["rule_name"]
        prev = change["previous_compliance"]
        curr = change["current_compliance"]
        lines.append(f"* {rule}: {prev} -> {curr}")

        for resource in change.get("resources", []):
            rtype = resource.get("resource_type", "unknown")
            rid = resource.get("resource_id", "unknown")
            lines.append(f"    - {rtype}: {rid}")

    return "\n".join(lines)


def send_slack_alert(webhook_url, drift):
    """Post a drift summary to Slack via an Incoming Webhook.

    One-way, no OAuth app/bot token needed - this only ever posts, it never
    needs to read anything back from Slack.
    """
    if not drift:
        return

    report = build_drift_report(drift)
    payload = {
        "blocks": [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": "AWS Compliance Drift Detected"},
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"```{report}```"},
            },
        ]
    }

    response = requests.post(webhook_url, json=payload)
    if response.status_code != 200:
        print(f"Failed to send Slack alert. Status: {response.status_code}")
        print(response.text)
    else:
        print("Slack alert sent.")


def send_email_alert(from_email, to_email, smtp_server, smtp_port, app_password, drift):
    """Email a drift summary via SMTP/STARTTLS."""
    if not drift:
        return

    report = build_drift_report(drift)

    message = MIMEMultipart()
    message["From"] = from_email
    message["To"] = to_email
    message["Subject"] = "AWS Compliance Drift Detected"
    message.attach(MIMEText(report, "plain"))

    with smtplib.SMTP(smtp_server, int(smtp_port)) as server:
        server.starttls()
        server.login(from_email, app_password)
        server.send_message(message)

    print("Email alert sent.")


def build_risk_digest(changed, unchanged):
    """Slack-friendly digest of elevated-risk findings, split into what
    changed since the last run and what's still persisting - and with a
    clickable link to the ServiceNow record for each, using Slack's
    <url|text> mrkdwn link syntax.

    changed/unchanged: lists of dicts with rule_name, control_name, rating,
    inherent_ale, owner_email, number, link (and previous_rating for changed).
    """
    lines = []

    if changed:
        lines.append("*New / Changed Since Last Run:*")
        for risk in changed:
            lines.append(
                f"• {risk['rule_name']} ({risk['control_name']}): "
                f"{risk.get('previous_rating', '(new)')} -> {risk['rating']} "
                f"(${risk['inherent_ale']:,.0f}/yr) - <{risk['link']}|{risk['number']}>"
            )

    if unchanged:
        if lines:
            lines.append("")
        lines.append("*Persisting (Unchanged):*")
        for risk in unchanged:
            lines.append(
                f"• {risk['rule_name']} ({risk['control_name']}): {risk['rating']} "
                f"(${risk['inherent_ale']:,.0f}/yr) - <{risk['link']}|{risk['number']}>"
            )

    return "\n".join(lines)


def send_risk_digest_slack(webhook_url, changed, unchanged):
    """Post the daily elevated-risk digest to Slack, with clickable links
    back to each ServiceNow record.

    Only fires when there's at least one Medium High/High finding - this is
    the severity gate, not a report of every drift event.
    """
    if not changed and not unchanged:
        return

    report = build_risk_digest(changed, unchanged)
    payload = {
        "blocks": [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": "Daily Risk Report: Elevated Findings"},
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": report},
            },
        ]
    }

    response = requests.post(webhook_url, json=payload)
    if response.status_code != 200:
        print(f"Failed to send risk digest Slack alert. Status: {response.status_code}")
        print(response.text)
    else:
        print("Risk digest Slack alert sent.")


def send_risk_report_email(from_email, to_emails, smtp_server, smtp_port, app_password, pdf_path):
    """Email the daily elevated-risk report to multiple recipients (risk
    owner + engineering team responsible for fixing the resource) - just
    the PDF attached, no summary text in the body.

    to_emails: list of recipient addresses.
    """
    message = MIMEMultipart()
    message["From"] = from_email
    message["To"] = ", ".join(to_emails)
    message["Subject"] = "Daily Risk Report: Elevated Findings"

    with open(pdf_path, "rb") as f:
        attachment = MIMEApplication(f.read(), _subtype="pdf")
    attachment.add_header("Content-Disposition", "attachment", filename="daily_risk_report.pdf")
    message.attach(attachment)

    with smtplib.SMTP(smtp_server, int(smtp_port)) as server:
        server.starttls()
        server.login(from_email, app_password)
        server.send_message(message)

    print("Risk report email sent.")


if __name__ == "__main__":
    # Manual test harness: python -m notifications.notify
    # Sends a sample drift event via Slack/email. The elevated-risk report
    # (PDF + digest) has its own test entry point in risk/report.py, since
    # it needs live ServiceNow data rather than a hardcoded sample.
    import os

    from dotenv import load_dotenv

    load_dotenv()

    sample_drift = [
        {
            "rule_name": "iam-password-policy",
            "previous_compliance": "COMPLIANT",
            "current_compliance": "NON_COMPLIANT",
            "resources": [
                {"resource_type": "AWS::IAM::AccountPasswordPolicy", "resource_id": "149030068572"}
            ],
        }
    ]

    webhook_url = os.getenv("SLACK_WEBHOOK_URL")
    from_email = os.getenv("EMAIL_FROM")
    to_email = os.getenv("EMAIL_TO")
    smtp_server = os.getenv("SMTP_SERVER")
    smtp_port = os.getenv("SMTP_PORT")
    app_password = os.getenv("EMAIL_APP_PASSWORD")

    if webhook_url:
        send_slack_alert(webhook_url, sample_drift)
    else:
        print("SLACK_WEBHOOK_URL not set, skipping Slack test.")

    if all([from_email, to_email, smtp_server, smtp_port, app_password]):
        send_email_alert(from_email, to_email, smtp_server, smtp_port, app_password, sample_drift)
    else:
        print("Email env vars not fully set, skipping email test.")
