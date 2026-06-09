# ================================================================
# Baseline CloudFront WAF ACL — aws_wafacl_golden
# ================================================================
# This ACL mirrors the organization-wide baseline that AWS Firewall
# Manager would enforce centrally across all CloudFront distributions.
#
# Rule priority zones:
#   1   – 99   → First rules  : security baseline, applied before app rules
#   100 – 999  → Middle zone  : application team customizations (rate limits,
#                               geo-blocks, path-specific allow exceptions)
#   1000+      → Last rules   : catch-all rules that run after app exceptions
#
# WCU budget (max 1500):
#   IP Reputation List  :   25
#   SOC Blocklist       :   ~5
#   Anti-DDoS L7        :   50
#   Anonymous IP List   :   50
#   Known Bad Inputs    :  200
#   Core Rule Set       :  700
#   SQLi Rule Set       :  200
#   Bot Control TARGETED:  100
#   ─────────────────────────
#   Total               : ~1330  (leaves ~170 WCU for middle-zone rules)
#
# Cost note (at 3B requests/month):
#   Free rule groups  → $0 extra beyond base WAF request fee
#   Anti-DDoS L7      → $20/month flat
#   Bot Control       → $10/million requests (scope-down to sensitive
#                       paths to avoid $30,000/month at full volume 3 billion requests per month)
# ================================================================

resource "aws_wafv2_web_acl" "baseline" {
  name        = "aws_wafacl_golden"
  description = "Enterprise WAF for CloudFront"
  scope       = "CLOUDFRONT"

  # Allow all traffic by default; rules below explicitly block threats.
  default_action {
    allow {}
  }

  # ── FIRST RULES (priority 1-99) ────────────────────────────────
  # Enforced before any application-specific rules.
  # Equivalent to Firewall Manager "First rule groups" (locked).
  # Ordered from cheapest to most expensive so low-cost checks
  # eliminate traffic before heavier rules consume WCU capacity.
  # ───────────────────────────────────────────────────────────────

  # Priority 1 — Amazon IP Reputation List (25 WCU, free)
  # Drops IPs flagged by Amazon threat intelligence (scanners, botnets,
  # command-and-control servers). Cheapest possible check — eliminates
  # known bad actors before any inspection occurs.
  rule {
    name     = "AWSManagedRulesAmazonIpReputationList"
    priority = 1
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesAmazonIpReputationList"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSManagedRulesAmazonIpReputationList"
      sampled_requests_enabled   = true
    }
  }

  # Priority 2 — SOC IP Blocklist (custom IP set, ~5 WCU)
  # Blocks IPs actively flagged by the Security Operations Center.
  # Updated in real-time via tools/manage_soc_blocklist.py — changes
  # take effect within seconds without a Terraform apply.
  # Placed immediately after IP Reputation List so incident response
  # blocks are enforced org-wide before any other inspection.
  rule {
    name     = "BlockSocList"
    priority = 2
    action {
      block {}
    }
    statement {
      ip_set_reference_statement {
        arn = aws_wafv2_ip_set.soc_blocklist.arn
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "BlockSocList"
      sampled_requests_enabled   = true
    }
  }

  # Priority 3 — Anti-DDoS L7 (50 WCU, $20/month flat)
  # Protects against application-layer (Layer 7) DDoS floods that
  # exhaust origin capacity with high request volumes.
  # Placed early so flood traffic is stopped before it reaches the
  # heavier Core Rule Set (700 WCU) and drives up inspection cost.
  rule {
    name     = "AWSManagedRulesAntiDDoSRuleSet"
    priority = 3
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesAntiDDoSRuleSet"

        # Anti-DDoS requires explicit client-side action config.
        # Challenge issues a silent browser challenge to suspected flood traffic.
        # exempt_uri_regular_expressions is required when Challenge is ENABLED —
        # it exempts non-browser endpoints (health checks, API callbacks) that
        # cannot complete a browser challenge and must not be blocked.
        # sensitivity_to_block: LOW = fewer false positives, HIGH = more aggressive.
        managed_rule_group_configs {
          aws_managed_rules_anti_ddos_rule_set {
            client_side_action_config {
              challenge {
                usage_of_action = "ENABLED"
                exempt_uri_regular_expression {
                  regex_string = "^/health$"
                }
              }
            }
            sensitivity_to_block = "LOW"
          }
        }
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSManagedRulesAntiDDoSRuleSet"
      sampled_requests_enabled   = true
    }
  }

  # Priority 4 — Anonymous IP List (50 WCU, free)
  # Blocks Tor exit nodes, VPNs, open proxies, and hosting providers
  # used to obfuscate attacker identity.
  # In regulated financial and health sectors, legitimate users do not
  # route through anonymizers — false positive risk is near zero.
  rule {
    name     = "AWSManagedRulesAnonymousIpList"
    priority = 4
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesAnonymousIpList"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSManagedRulesAnonymousIpList"
      sampled_requests_enabled   = true
    }
  }

  # Priority 5 — Known Bad Inputs (200 WCU, free)
  # Blocks request patterns tied to known exploits: Log4j RCE CVE-2021-44228),
  # Java deserialization attacks, and path traversal attempts.
  # Runs before Core Rule Set so obvious exploit signatures are caught
  # without consuming the full 700 WCU of the Core Rule Set.
  rule {
    name     = "AWSManagedRulesKnownBadInputsRuleSet"
    priority = 5
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSManagedRulesKnownBadInputsRuleSet"
      sampled_requests_enabled   = true
    }
  }

  # Priority 6 — Core Rule Set (700 WCU, free)
  # OWASP Top 10 baseline: XSS, SSRF, path traversal, malformed HTTP, LFI/RFI.
  # Heaviest free rule group by WCU — placed last in the First zone so
  # lighter rules above eliminate traffic before this runs.
  # If specific rules cause false positives, override individual rules
  # to Count mode here rather than disabling the whole rule group.
  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 6
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesCommonRuleSet"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSManagedRulesCommonRuleSet"
      sampled_requests_enabled   = true
    }
  }

  # ── MIDDLE ZONE (priority 100-999) ─────────────────────────────
  # Reserved for application team customizations. Examples:
  #
  #   priority 100 — GlobalRateLimit: block IPs exceeding N req/5min
  #   priority 200 — FinancePathRateLimit: tighter limit on /finance
  #   priority 300 — GeoBlock: restrict to allowed jurisdictions
  #   priority 400 — AllowHealthException: permit known-safe patterns
  #                  on /health before SQLi catch-all blocks them
  #
  # Middle zone rules run AFTER First rules and BEFORE Last rules.
  # This means app teams can allow specific traffic here and it will
  # not be re-evaluated by the SQLi or Bot Control Last rules below.
  # ───────────────────────────────────────────────────────────────

  # ── LAST RULES (priority 1000+) ────────────────────────────────
  # Catch-all rules that run after all application exceptions.
  # Equivalent to Firewall Manager "Last rule groups" (locked).
  # App teams must add path-specific allow exceptions in the middle
  # zone (100-999) BEFORE these rules block legitimate edge cases.
  # ───────────────────────────────────────────────────────────────

  # Priority 1000 — SQLi Rule Set (~200 WCU, free)
  # Final catch-all for SQL injection across all request components.
  # Placed in Last zone so app teams can add targeted allow exceptions
  # in the middle zone for known-safe SQLi-like patterns (e.g. health
  # check queries with session IDs that resemble SQLi syntax).
  rule {
    name     = "AWSManagedRulesSQLiRuleSet"
    priority = 1000
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesSQLiRuleSet"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSManagedRulesSQLiRuleSet"
      sampled_requests_enabled   = true
    }
  }

  # Priority 1001 — Bot Control TARGETED (100 WCU, $10/million requests)
  # ML-based bot detection using browser fingerprinting and behavioral
  # analysis applied to all web requests.
  # TARGETED mode includes COMMON protections plus advanced ML-based
  # detection that identifies bots even when they mimic legitimate browsers.
  # Cost: $10/month base + $10/million requests processed.
  rule {
    name     = "AWSManagedRulesBotControlRuleSet"
    priority = 1001
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesBotControlRuleSet"

        managed_rule_group_configs {
          aws_managed_rules_bot_control_rule_set {
            # TARGETED uses ML fingerprinting; COMMON is cheaper ($1/million)
            # but less accurate. Switch to COMMON if cost becomes a concern.
            inspection_level = "TARGETED"
          }
        }
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSManagedRulesBotControlRuleSet"
      sampled_requests_enabled   = true
    }
  }

  # Top-level visibility config — enables WAF-level CloudWatch metrics
  # and sampling for the web ACL as a whole (separate from per-rule metrics).
  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "aws_wafacl_golden"
    sampled_requests_enabled   = true
  }
}
