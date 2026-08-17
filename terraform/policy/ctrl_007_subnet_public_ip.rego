package main

import rego.v1

# CTRL-007 / subnet-auto-assign-public-ip-disabled
# Subnets must not auto-assign public IP addresses to launched instances.

deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_subnet"
	after := rc.change.after
	after.map_public_ip_on_launch == true
	msg := sprintf("[CTRL-007] Subnet %q auto-assigns public IP addresses on launch", [rc.address])
}
