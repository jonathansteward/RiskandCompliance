import boto3

config_client = boto3.client('config')

rule_name="root-account-mfa-enabled"

response = config_client.describe_compliance_by_config_rule(
    ConfigRuleNames=[rule_name]
)

for rule in response['ComplianceByConfigRules']:
    print(f"Rule: {rule['ConfigRuleName']}")
    print(f"Compliance Status: {rule['Compliance']['ComplianceType']}")
