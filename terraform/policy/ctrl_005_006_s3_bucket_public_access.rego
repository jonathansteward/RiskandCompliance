package main

import rego.v1

# CTRL-005 / s3-bucket-public-read-prohibited
# CTRL-006 / s3-bucket-public-write-prohibited
# Both controls are driven by the same two Terraform resource types:
# the bucket's ACL, and its (bucket-level, not account-level) public
# access block settings. Public access block covers both read and write
# exposure at once, so a failing bucket-level block is tagged with both
# control IDs; the ACL value itself distinguishes read-only exposure
# (public-read, authenticated-read) from read-write exposure
# (public-read-write).

bucket_blocks_enabled(after) if {
	after.block_public_acls == true
	after.block_public_policy == true
	after.ignore_public_acls == true
	after.restrict_public_buckets == true
}

deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_s3_bucket_public_access_block"
	after := rc.change.after
	not bucket_blocks_enabled(after)
	msg := sprintf("[CTRL-005][CTRL-006] Bucket-level public access block %q does not have all four block settings enabled", [rc.address])
}

deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_s3_bucket_acl"
	after := rc.change.after
	after.acl in {"public-read", "public-read-write", "authenticated-read"}
	msg := sprintf("[CTRL-005] S3 bucket ACL %q grants public read access (acl = %q)", [rc.address, after.acl])
}

deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_s3_bucket_acl"
	after := rc.change.after
	after.acl == "public-read-write"
	msg := sprintf("[CTRL-006] S3 bucket ACL %q grants public write access (acl = %q)", [rc.address, after.acl])
}
