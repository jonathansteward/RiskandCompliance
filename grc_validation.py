import smtplib
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from email.mime.text import MIMEText

# Gets the status of AWS Config rules
def get_control_status(rule_name, config_client):
    
    response = config_client.describe_compliance_by_config_rule(ConfigRuleNames=[rule_name])
    return response['ComplianceByConfigRules'][0]['Compliance']['ComplianceType']

# Generates reports
def generate_report(prompt, pdf, oi_client):

    # Call ChatGPT
    response = oi_client.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=[{"role": "user", "content": prompt}]
    )

    report_text = response.choices[0].message.content

    # Create PDF
    c = canvas.Canvas(pdf, pagesize=letter)
    width, height = letter

    # Create a text object to wrap text
    text_object = c.beginText()
    text_object.setTextOrigin(50, height - 50)
    text_object.setFont("Helvetica", 12)

    # Set max width in points (letter page ~612 points wide)
    max_width = 500

    # Wrap long lines
    from textwrap import wrap
    for paragraph in report_text.split("\n"):
        wrapped_lines = wrap(paragraph, width=90)  # Tune wrap width
        for line in wrapped_lines:
            text_object.textLine(line)
        text_object.textLine("")  # Add a blank line between paragraphs

    c.drawText(text_object)
    c.save()

# Sends report emails
def send_email(from_email, to_email, smtp_server, smtp_port, wep, pdf):
    
    message = MIMEMultipart()
    message['From'] = from_email
    message['To'] = to_email
    message['Subject'] = "AWS Control Status Report"

    body = "Please find the attached status report."
    message.attach(MIMEText(body, 'plain'))

    with open(pdf, 'rb') as f:
        part = MIMEApplication(f.read(), Name="control_status_report.pdf")
        part['Content-Disposition'] = 'attachment; filename="control_status_report.pdf"'
        message.attach(part)

    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()
        server.login(from_email, wep)
        server.send_message(message)

    print("Email sent successfully.")