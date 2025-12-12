import smtplib
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from email.mime.text import MIMEText
from textwrap import wrap
import requests
from requests.auth import HTTPBasicAuth

# Build the summary for the prompt
def build_status_summary(statuses):
    summary = ""

    for rule_name, details in statuses.items():
        compliance = details['compliance']
        summary += f"{rule_name}: {compliance}\n"

        if compliance == "NON_COMPLIANT" and 'resources' in details:
            for resource in details['resources']:
                rtype = resource['resource_type']
                rid = resource['resource_id']
                summary += f"  - {rtype}: {rid}\n"

    return summary

# Gets the status of AWS Config rules
def get_all_control_statuses(config_client):

    statuses = {}

    # Get all compliance statuses
    paginator = config_client.get_paginator('describe_compliance_by_config_rule')
    for page in paginator.paginate():
        for rule in page.get('ComplianceByConfigRules', []):
            rule_name = rule['ConfigRuleName']
            compliance = rule['Compliance']['ComplianceType']
            rule_info = {'compliance': compliance}

            # If NON_COMPLIANT, get resource details
            if compliance == "NON_COMPLIANT":
                resource_list = []
                res_paginator = config_client.get_paginator('get_compliance_details_by_config_rule')
                for res_page in res_paginator.paginate(ConfigRuleName=rule_name, ComplianceTypes=['NON_COMPLIANT']):
                    for result in res_page['EvaluationResults']:
                        rtype = result['EvaluationResultIdentifier']['EvaluationResultQualifier']['ResourceType']
                        rid = result['EvaluationResultIdentifier']['EvaluationResultQualifier']['ResourceId']
                        resource_list.append({'resource_type': rtype, 'resource_id': rid})
                rule_info['resources'] = resource_list

            statuses[rule_name] = rule_info

    return statuses

def update_service_now(sn_i, sn_t, statuses, sn_u, sn_p):
    
    base_url = f"https://{sn_i}.service-now.com/api/now/table/{sn_t}"
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    for rule_name, info in statuses.items():
        control_status = info.get("compliance", "UNKNOWN")

        # Step 1: Check if rule already exists by rule_name
        query_url = f"{base_url}?sysparm_query=u_aws_config_rule_name={rule_name}&sysparm_limit=1"
        get_response = requests.get(query_url, auth=(sn_u, sn_p), headers=headers)

        if get_response.status_code == 200:
            results = get_response.json().get("result", [])
            if results:
                # Rule exists — use PATCH to update
                sys_id = results[0]['sys_id']
                patch_url = f"{base_url}/{sys_id}"
                payload = {"u_status": control_status}

                patch_response = requests.patch(patch_url, auth=(sn_u, sn_p), headers=headers, json=payload)
                if patch_response.status_code == 200:
                    print(f"Updated: {rule_name} - {control_status}")
                else:
                    print(f"Failed to update {rule_name}. Status: {patch_response.status_code}")
                    print(patch_response.text)
            else:
                # Rule does not exist — use POST to create
                payload = {
                    "u_aws_config_rule_name": rule_name,
                    "u_status": control_status
                }
                post_response = requests.post(base_url, auth=(sn_u, sn_p), headers=headers, json=payload)
                if post_response.status_code in [200, 201]:
                    print(f"Created: {rule_name} - {control_status}")
                else:
                    print(f"Failed to create {rule_name}. Status: {post_response.status_code}")
                    print(post_response.text)
        else:
            print(f"Failed to query for {rule_name}. Status: {get_response.status_code}")
            print(get_response.text)

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

    text_object = c.beginText()
    text_object.setFont("Helvetica", 12)
    x_margin = 50
    y_position = height - 50
    line_height = 15
    max_lines_per_page = int((height - 100) / line_height)

    line_count = 0
    text_object.setTextOrigin(x_margin, y_position)

    for paragraph in report_text.split("\n"):
        wrapped_lines = wrap(paragraph, width=90)
        for line in wrapped_lines:
            if line_count >= max_lines_per_page:
                c.drawText(text_object)
                c.showPage()
                text_object = c.beginText()
                text_object.setFont("Helvetica", 12)
                text_object.setTextOrigin(x_margin, height - 50)
                line_count = 0
            text_object.textLine(line)
            line_count += 1
        text_object.textLine("")
        line_count += 1

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