package main

import rego.v1

# CTRL-002 / iam-password-policy
# Mirrors the AWS Config managed rule's default parameters: minimum length
# 14, all four complexity classes required, 90-day max age, reuse
# prevention across the last 24 passwords.

deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_iam_account_password_policy"
	after := rc.change.after
	after.minimum_password_length < 14
	msg := sprintf("[CTRL-002] IAM password policy %q minimum length is %d, must be at least 14", [rc.address, after.minimum_password_length])
}

deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_iam_account_password_policy"
	after := rc.change.after
	after.require_uppercase_characters == false
	msg := sprintf("[CTRL-002] IAM password policy %q does not require uppercase characters", [rc.address])
}

deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_iam_account_password_policy"
	after := rc.change.after
	after.require_lowercase_characters == false
	msg := sprintf("[CTRL-002] IAM password policy %q does not require lowercase characters", [rc.address])
}

deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_iam_account_password_policy"
	after := rc.change.after
	after.require_numbers == false
	msg := sprintf("[CTRL-002] IAM password policy %q does not require numbers", [rc.address])
}

deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_iam_account_password_policy"
	after := rc.change.after
	after.require_symbols == false
	msg := sprintf("[CTRL-002] IAM password policy %q does not require symbols", [rc.address])
}

deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_iam_account_password_policy"
	after := rc.change.after
	after.max_password_age == 0
	msg := sprintf("[CTRL-002] IAM password policy %q does not enforce password expiration (max_password_age = 0)", [rc.address])
}

deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_iam_account_password_policy"
	after := rc.change.after
	after.max_password_age > 90
	msg := sprintf("[CTRL-002] IAM password policy %q max_password_age is %d days, must be 90 or fewer", [rc.address, after.max_password_age])
}

deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_iam_account_password_policy"
	after := rc.change.after
	after.password_reuse_prevention < 24
	msg := sprintf("[CTRL-002] IAM password policy %q allows password reuse after %d changes, must prevent reuse for at least 24", [rc.address, after.password_reuse_prevention])
}
