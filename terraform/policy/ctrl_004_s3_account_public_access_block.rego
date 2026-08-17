package main

import rego.v1

# CTRL-004 / s3-account-level-public-access-blocks-periodic
# All four account-level public access block settings must be enabled.

account_blocks_enabled(after) if {
	after.block_public_acls == true
	after.block_public_policy == true
	after.ignore_public_acls == true
	after.restrict_public_buckets == true
}

deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_s3_account_public_access_block"
	after := rc.change.after
	not account_blocks_enabled(after)
	msg := sprintf("[CTRL-004] Account-level S3 public access block %q does not have all four block settings enabled", [rc.address])
}
