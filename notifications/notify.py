import os
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


def send_risk_report_slack_file(bot_token, channel_id, pdf_path):
    """Upload the daily risk report PDF directly into a Slack channel.

    Incoming Webhooks (the SLACK_WEBHOOK_URL path used elsewhere in this
    file) can only post text/blocks - they have no file-upload capability
    at all. Actually delivering a file requires a Bot Token and Slack's
    current external-upload flow: request an upload URL, upload the bytes
    to it, then finalize/share it to the channel. Deliberately not using
    the older files.upload endpoint, which Slack has been deprecating for
    newer apps.
    """
    filename = os.path.basename(pdf_path)
    file_size = os.path.getsize(pdf_path)
    headers = {"Authorization": f"Bearer {bot_token}"}

    url_response = requests.get(
        "https://slack.com/api/files.getUploadURLExternal",
        headers=headers,
        params={"filename": filename, "length": file_size},
    ).json()
    if not url_response.get("ok"):
        print(f"Failed to get Slack upload URL: {url_response.get('error')}")
        return

    with open(pdf_path, "rb") as f:
        upload_response = requests.post(url_response["upload_url"], files={"file": f})
    if upload_response.status_code != 200:
        print(f"Failed to upload PDF to Slack. Status: {upload_response.status_code}")
        return

    complete_response = requests.post(
        "https://slack.com/api/files.completeUploadExternal",
        headers={**headers, "Content-Type": "application/json"},
        json={
            "files": [{"id": url_response["file_id"], "title": "Daily Risk Report"}],
            "channel_id": channel_id,
        },
    ).json()

    if complete_response.get("ok"):
        print("Risk report PDF uploaded to Slack.")
    else:
        print(f"Failed to complete Slack upload: {complete_response.get('error')}")


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
