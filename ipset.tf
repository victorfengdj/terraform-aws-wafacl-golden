# SOC IP Blocklist — managed by the Security Operations Center.
# Named IPBlockDVSocList to keep it independent from other workspaces
# so this workspace can be destroyed without affecting other WAF ACLs.
# IPs here are added/removed via tools/manage_soc_blocklist.py, not Terraform.
# lifecycle { ignore_changes } prevents terraform apply from overwriting
# IPs that the SOC script has added since the last terraform apply.
resource "aws_wafv2_ip_set" "soc_blocklist" {
  name               = "IPBlockDVSocList_g"
  scope              = "CLOUDFRONT"
  ip_address_version = "IPV4"

  # Seed addresses — real blocklist is maintained by SOC via script.
  # All CIDRs must have host bits zeroed (e.g. 76.9.24.32/28 not 76.9.24.33/28).
  addresses = [
    "34.23.120.12/32",
    "76.9.24.32/28",
  ]

  lifecycle {
    ignore_changes = [addresses]
  }
}
