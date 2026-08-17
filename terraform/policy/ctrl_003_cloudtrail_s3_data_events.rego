package main

import rego.v1

# CTRL-003 / cloudtrail-all-read-s3-data-event-check
# A trail is only compliant if it has an event selector covering S3 object
# data events with a read_write_type of "All" or "ReadOnly" - a trail with
# no data event selector (or write-only) never logs S3 reads.

trail_logs_s3_reads(after) if {
	some selector in after.event_selector
	selector.read_write_type in {"All", "ReadOnly"}
	some resource in selector.data_resource
	resource.type == "AWS::S3::Object"
}

deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_cloudtrail"
	after := rc.change.after
	not trail_logs_s3_reads(after)
	msg := sprintf("[CTRL-003] CloudTrail trail %q does not log S3 data-plane read events (missing or incomplete event_selector)", [rc.address])
}
