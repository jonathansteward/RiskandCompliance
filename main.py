import boto3
import grc_validation
from dotenv import load_dotenv
from openai import OpenAI
import os

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
rule_name="root-account-mfa-enabled"

# Get Status of security controls
status = grc_validation.get_control_status(rule_name, config_client)

# Build the prompt
prompt = f"""
You're a cybersecurity analyst. Generate a short compliance status summary report for an AWS Config rule that checks whether root account MFA is enabled.

The current status is: """ + status + """

Include in your summary:
- What this rule checks for
- Why it matters
- What the current status means
- If it's NON_COMPLIANT, include a recommendation
"""

# Generate Report
grc_validation.generate_report(prompt, pdf, oi_client)

# Send report email to relevant stakeholder
grc_validation.send_email(FROM_EMAIL, TO_EMAIL, smtp_server, smtp_port, WEP, pdf)