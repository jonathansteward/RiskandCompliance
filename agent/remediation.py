import anthropic

MODEL = "claude-sonnet-5"

SUBMIT_GUIDANCE_TOOL = {
    "name": "submit_remediation_guidance",
    "description": "Submit structured remediation guidance for a non-compliant AWS control.",
    "input_schema": {
        "type": "object",
        "properties": {
            "standard_summary": {
                "type": "string",
                "description": "Plain-English summary of the policy/standard this control enforces, "
                                "grounded in AWS Config's own rule description and configured parameters. "
                                "2-3 sentences, not a full essay.",
            },
            "gap_summary": {
                "type": "string",
                "description": "What is currently wrong, specific to the non-compliant resource(s) found. "
                                "2-3 sentences, not a full essay.",
            },
            "remediation_steps": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Concrete, ordered steps to bring the resource(s) into compliance.",
            },
        },
        "required": ["standard_summary", "gap_summary", "remediation_steps"],
    },
}


def build_prompt(rule_name, rule_definition, evidence):
    """Assemble the full context for one non-compliant rule: what AWS Config
    itself says the standard is, and the specific resources/annotations that
    show where the account currently falls short of it.
    """
    parameters = rule_definition.get("input_parameters") or {}
    parameters_text = "\n".join(f"- {key}: {value}" for key, value in parameters.items())
    if not parameters_text:
        parameters_text = "(no parameters configured for this rule)"

    findings = []
    for resource in evidence:
        annotation = resource.get("annotation") or "(no annotation provided by AWS Config)"
        findings.append(
            f"- {resource.get('resource_type')}: {resource.get('resource_id')}\n"
            f"  AWS Config's explanation: {annotation}"
        )
    findings_text = "\n".join(findings) if findings else "(no resource-level detail available)"

    return f"""You are reviewing an AWS Config rule that is currently non-compliant.

Rule: {rule_name}
AWS Config's description of what this rule checks: {rule_definition.get('description') or '(not provided)'}
Configured parameters for this rule in this account:
{parameters_text}

Non-compliant findings:
{findings_text}

Identify the policy/standard this rule enforces, summarize the specific gap shown by these \
findings, and give concrete remediation steps."""


def get_remediation_guidance(client, rule_name, rule_definition, evidence):
    """Single structured call - Claude never chooses what to look up here,
    it just reasons over the context already assembled above and returns
    guidance via one forced tool call, so the output is reliably parseable
    JSON rather than free text.
    """
    prompt = build_prompt(rule_name, rule_definition, evidence)

    response = client.messages.create(
        model=MODEL,
        max_tokens=2048,
        tools=[SUBMIT_GUIDANCE_TOOL],
        tool_choice={"type": "tool", "name": "submit_remediation_guidance"},
        messages=[{"role": "user", "content": prompt}],
    )

    if response.stop_reason == "max_tokens":
        raise RuntimeError(
            "Claude's response was cut off before finishing the tool call "
            "(hit max_tokens) - raise max_tokens or shorten the prompt."
        )

    tool_use_block = next(block for block in response.content if block.type == "tool_use")
    return tool_use_block.input


if __name__ == "__main__":
    # Manual test harness: python agent/remediation.py
    # Pulls one real non-compliant rule from AWS Config and runs it through
    # the guidance call end to end, so this can be verified on its own
    # before any decision is made about wiring it into main.py.
    import os

    import boto3
    from dotenv import load_dotenv

    import grc_validation

    load_dotenv()

    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        raise SystemExit("ANTHROPIC_API_KEY not set in .env")

    config_client = boto3.client("config")
    statuses = grc_validation.get_all_control_statuses(config_client)

    non_compliant = {
        rule_name: info
        for rule_name, info in statuses.items()
        if info.get("compliance") == "NON_COMPLIANT"
    }
    if not non_compliant:
        raise SystemExit("No non-compliant rules found right now - nothing to test against.")

    rule_name, info = next(iter(non_compliant.items()))
    rule_definition = grc_validation.get_rule_definition(config_client, rule_name)

    client = anthropic.Anthropic(api_key=api_key)
    guidance = get_remediation_guidance(client, rule_name, rule_definition, info.get("resources", []))

    print(f"Rule: {rule_name}\n")
    print(f"Standard:\n{guidance['standard_summary']}\n")
    print(f"Gap:\n{guidance['gap_summary']}\n")
    print("Remediation steps:")
    for i, step in enumerate(guidance["remediation_steps"], start=1):
        print(f"  {i}. {step}")
