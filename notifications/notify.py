import smtplib
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


if __name__ == "__main__":
    # Manual test harness: python notifications/notify.py
    # Sends a sample drift event so you can verify Slack/email setup end to
    # end before this is wired into main.py by Tier 1's detect_drift().
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
    if webhook_url:
        send_slack_alert(webhook_url, sample_drift)
    else:
        print("SLACK_WEBHOOK_URL not set, skipping Slack test.")

    from_email = os.getenv("EMAIL_FROM")
    to_email = os.getenv("EMAIL_TO")
    smtp_server = os.getenv("SMTP_SERVER")
    smtp_port = os.getenv("SMTP_PORT")
    app_password = os.getenv("EMAIL_APP_PASSWORD")
    if all([from_email, to_email, smtp_server, smtp_port, app_password]):
        send_email_alert(from_email, to_email, smtp_server, smtp_port, app_password, sample_drift)
    else:
        print("Email env vars not fully set, skipping email test.")
