import json

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
                        annotation = result.get('Annotation', '')
                        recorded_time = result.get('ResultRecordedTime')
                        resource_list.append({
                            'resource_type': rtype,
                            'resource_id': rid,
                            'annotation': annotation,
                            # ServiceNow's Table API expects "YYYY-MM-DD HH:mm:ss", not ISO 8601
                            'result_recorded_time': recorded_time.strftime('%Y-%m-%d %H:%M:%S') if recorded_time else '',
                        })
                rule_info['resources'] = resource_list

            statuses[rule_name] = rule_info

    return statuses

def get_rule_definition(config_client, rule_name):
    """Fetch AWS Config's own description and configured thresholds for a
    rule - the authoritative "what standard is this enforcing" source, so
    nothing about the control's policy gets duplicated/hardcoded elsewhere.
    """
    response = config_client.describe_config_rules(ConfigRuleNames=[rule_name])
    rule = response['ConfigRules'][0]

    raw_parameters = rule.get('InputParameters', '{}')
    input_parameters = json.loads(raw_parameters) if raw_parameters else {}

    return {
        'description': rule.get('Description', ''),
        'source_identifier': rule.get('Source', {}).get('SourceIdentifier', ''),
        'input_parameters': input_parameters,
    }


def update_service_now(sn_i, sn_t, statuses, sn_u, sn_p):

    base_url = f"https://{sn_i}.service-now.com/api/now/table/{sn_t}"
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    # rule_name -> sys_id, so push_evidence() can link evidence rows back to
    # the right parent record without re-querying ServiceNow for each one.
    rule_sys_ids = {}

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
                rule_sys_ids[rule_name] = sys_id
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
                    rule_sys_ids[rule_name] = post_response.json()["result"]["sys_id"]
                    print(f"Created: {rule_name} - {control_status}")
                else:
                    print(f"Failed to create {rule_name}. Status: {post_response.status_code}")
                    print(post_response.text)
        else:
            print(f"Failed to query for {rule_name}. Status: {get_response.status_code}")
            print(get_response.text)

    return rule_sys_ids


def push_evidence(sn_i, sn_u, sn_p, statuses, rule_sys_ids):
    """Insert one evidence row per non-compliant resource per run into
    u_aws_config_evidence.

    Always a POST, never a PATCH — each run's finding is its own row, so a
    prior finding is never overwritten. That's what lets an auditor open a
    control's record in ServiceNow and see the full history of what failed,
    when, and why, without leaving the platform.
    """
    base_url = f"https://{sn_i}.service-now.com/api/now/table/u_aws_config_evidence"
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    for rule_name, info in statuses.items():
        if info.get("compliance") != "NON_COMPLIANT":
            continue

        sys_id = rule_sys_ids.get(rule_name)
        if not sys_id:
            print(f"No sys_id for {rule_name}, skipping evidence push.")
            continue

        for resource in info.get("resources", []):
            payload = {
                "u_control_mapping": sys_id,
                "u_resource_type": resource.get("resource_type", ""),
                "u_resource_id": resource.get("resource_id", ""),
                "u_annotation": resource.get("annotation", ""),
                "u_compliance_status": "NON_COMPLIANT",
                "u_captured_at": resource.get("result_recorded_time", ""),
            }

            response = requests.post(base_url, auth=(sn_u, sn_p), headers=headers, json=payload)
            if response.status_code in (200, 201):
                print(f"Evidence recorded: {rule_name} - {resource.get('resource_id')}")
            else:
                print(f"Failed to push evidence for {rule_name} - {resource.get('resource_id')}. Status: {response.status_code}")
                print(response.text)