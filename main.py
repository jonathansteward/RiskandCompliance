import boto3
import grc_validation
from dotenv import load_dotenv
from openai import OpenAI
import os
from datetime import date

def main():

    # Load environment variables
    load_dotenv()

    OI = os.getenv("OI")
    WEP = os.getenv("WEP")
    FROM_EMAIL = os.getenv("FROM_EMAIL")
    TO_EMAIL = os.getenv("TO_EMAIL")

    smtp_server = "smtp.gmail.com"
    smtp_port = 587
    pdf = "reports/aws_control_status_report.pdf"
    oi_client = OpenAI(api_key=OI)
    config_client = boto3.client('config')

    # Get Status of security controls
    statuses = grc_validation.get_all_control_statuses(config_client)

    # Summarize the statuses for the prompt
    status_summary = grc_validation.build_status_summary(statuses)
    
    # Build the prompt
    prompt = f"""
    You are a security risk analyst. Analyze the AWS Config rule control status summary below and generate a report.
    
    On the first page, the report header should include:
    - Title as AWS Control Status Report
    - Date of report is {date.today()}

    For each rule, include:
    - A short description of what it checks for
    - Why it's important for cloud security or risk mitigation
    - What the current compliance status means
    - If it's NON_COMPLIANT, include the resource details that are non-compliant and clear recommendations for remediation

    Compliance Summary:
    
    {status_summary}
    
    Instructions:
    - Do NOT use Markdown symbols (like #, *, **)
    - Format using plain text with clear headings
    - Use proper capitalization and spacing
    - Write the report in clear, concise language that a risk or GRC stakeholder would understand
    - Number and bold each rule name."""

    # Generate Report
    grc_validation.generate_report(prompt, pdf, oi_client)

    # Send report email to relevant stakeholder
    grc_validation.send_email(FROM_EMAIL, TO_EMAIL, smtp_server, smtp_port, WEP, pdf)

if __name__ == "__main__":
    main()