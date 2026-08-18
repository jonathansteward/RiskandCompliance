import os

import anthropic
import boto3
from dotenv import load_dotenv

import agent.remediation as remediation
import grc_validation


def main():

    # Load environment variables
    load_dotenv()

    SN_I = os.getenv("SN_I")
    SN_T = os.getenv("SN_T")
    SN_U = os.getenv("SN_U")
    SN_P = os.getenv("SN_P")
    ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")

    config_client = boto3.client('config')
    claude_client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY) if ANTHROPIC_API_KEY else None

    # Get Status of security controls
    statuses = grc_validation.get_all_control_statuses(config_client)

    # Update ServiceNow GRC table with statuses from AWS; previous_status
    # lets us tell a brand-new failure from one that's still failing.
    rule_context = grc_validation.update_service_now(SN_I, SN_T, statuses, SN_U, SN_P)

    # Only generate fresh remediation guidance for rules that just became
    # non-compliant. A rule that was already non-compliant last run carries
    # forward its existing guidance instead of paying for another Claude
    # call on a finding that hasn't changed.
    guidance_by_rule = {}
    for rule_name, info in statuses.items():
        if info.get("compliance") != "NON_COMPLIANT":
            continue

        context = rule_context.get(rule_name)
        if not context:
            continue

        is_new_failure = context["previous_status"] != "NON_COMPLIANT"

        if is_new_failure and claude_client:
            rule_definition = grc_validation.get_rule_definition(config_client, rule_name)
            guidance = remediation.get_remediation_guidance(
                claude_client, rule_name, rule_definition, info.get("resources", [])
            )
            guidance_by_rule[rule_name] = {
                "standard_summary": guidance["standard_summary"],
                "gap_summary": guidance["gap_summary"],
                "remediation_steps_text": remediation.format_remediation_steps(guidance["remediation_steps"]),
            }
            print(f"Generated new remediation guidance for {rule_name} (new failure).")
        else:
            carried_forward = grc_validation.get_latest_evidence_guidance(SN_I, SN_U, SN_P, context["sys_id"])
            if carried_forward:
                guidance_by_rule[rule_name] = carried_forward
                print(f"Carried forward existing guidance for {rule_name} (still failing).")
            else:
                print(f"No prior guidance to carry forward for {rule_name} yet.")

    # Record per-resource evidence for non-compliant rules, including guidance
    grc_validation.push_evidence(SN_I, SN_U, SN_P, statuses, rule_context, guidance_by_rule)


if __name__ == "__main__":
    main()
