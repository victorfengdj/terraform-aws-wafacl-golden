# terraform-aws-wafacl-golden

![Terraform](https://img.shields.io/badge/Terraform-%3E%3D1.12-7B42BC?logo=terraform)
![AWS WAFv2](https://img.shields.io/badge/AWS-WAFv2-FF9900?logo=amazon-aws)

Enterprise CloudFront WAF ACL — codified as Terraform, deployed via HCP Terraform Cloud.

---

## Project Abstract

Every CloudFront distribution in the organisation needs the same security baseline: OWASP
Top 10 protection, bot mitigation, DDoS defence, and SOC-managed IP blocks. Configuring
these rules manually per-distribution is inconsistent, error-prone, and impossible to audit.

`terraform-aws-wafacl-golden` solves this by defining the **organisation-wide baseline WAF
ACL as code**. One `terraform apply` creates a single CLOUDFRONT-scoped Web ACL that acts as
the golden standard. The companion module
[terraform-aws-auto-remediate-waf-loss](https://github.com/victorfengdj/terraform-aws-auto-remediate-waf-loss)
enforces it automatically on every distribution.

---

## Architecture Blueprint

```
┌─────────────────────────────────────────────────────────────────┐
│         terraform-aws-wafacl-golden (WAFv2 Web ACL)             │
│                                                                 │
│  FIRST ZONE  (priority 1-99)  ← security baseline, locked      │
│  ──────────────────────────────────────────────────────────     │
│  Pri 1  │ AWSManagedRulesAmazonIpReputationList  │  25 WCU     │
│  Pri 2  │ SOC IP Blocklist (custom IP set)        │  ~5 WCU     │
│  Pri 3  │ AWSManagedRulesAntiDDoSRuleSet (L7)     │  50 WCU     │
│  Pri 4  │ AWSManagedRulesAnonymousIpList           │  50 WCU     │
│  Pri 5  │ AWSManagedRulesKnownBadInputsRuleSet     │ 200 WCU     │
│  Pri 6  │ AWSManagedRulesCommonRuleSet (OWASP)     │ 700 WCU     │
│                                                                 │
│  MIDDLE ZONE (priority 100-999) ← app-team customisations      │
│  ──────────────────────────────────────────────────────────     │
│  Reserved for rate limits, geo-blocks, path exceptions          │
│                                                                 │
│  LAST ZONE  (priority 1000+) ← catch-all, locked               │
│  ──────────────────────────────────────────────────────────     │
│  Pri 1000 │ AWSManagedRulesSQLiRuleSet             │ 200 WCU    │
│  Pri 1001 │ AWSManagedRulesBotControlRuleSet        │ 100 WCU    │
│           │ (TARGETED — ML browser fingerprinting)  │            │
│                                                                 │
│  Total WCU consumed: ~1 330 / 1 500 budget                     │
└─────────────────────────────────────────────────────────────────┘
          │
          │  attached to
          ▼
  CloudFront Distributions (enforced by terraform-aws-auto-remediate-waf-loss)
```

| Layer | Technology | Purpose |
|---|---|---|
| Infrastructure-as-Code | Terraform ≥ 1.12 | Declarative WAF configuration |
| WAF | AWS WAFv2 (CLOUDFRONT scope) | Traffic inspection and blocking |
| Managed rules | AWS Managed Rule Groups | OWASP, SQLi, Bot, DDoS, IP reputation |
| Custom IP set | `aws_wafv2_ip_set` | SOC-managed real-time blocklist |
| Remote state | HCP Terraform Cloud | State locking and team collaboration |

### Rule priority design

Rules are ordered cheapest → most expensive within each zone so that low-cost checks
(IP reputation, custom blocklist) eliminate known-bad traffic before the heavy Core Rule
Set (700 WCU) and Bot Control ML model run. This keeps WCU consumption and cost predictable
even at high request volumes.

### SOC blocklist

`ipset.tf` defines an `aws_wafv2_ip_set` with `lifecycle { ignore_changes = [addresses] }`.
The Security Operations Center updates the live blocklist in real time via a management
script — changes take effect in seconds without a Terraform apply. Terraform will never
overwrite SOC additions on the next plan/apply.

---

## Usage

### As a Terraform module

```hcl
module "wafacl_golden" {
  source = "github.com/victorfengdj/terraform-aws-wafacl-golden"
}
```

### As a standalone deployment

```bash
git clone https://github.com/victorfengdj/terraform-aws-wafacl-golden.git
cd terraform-aws-wafacl-golden
# first: edit terraform.tf — set organization to your own HCP Terraform org
terraform login        # authenticate with HCP Terraform (one-time)
terraform init
terraform plan
terraform apply
```

---

## Deployment Instructions

### Prerequisites

| Requirement | Version |
|---|---|
| [Terraform CLI](https://developer.hashicorp.com/terraform/downloads) | ≥ 1.12 |
| AWS provider | ~> 6.0 (pinned in `terraform.tf`) |

> **Region note:** CloudFront-scoped WAF ACLs **must** be deployed in `us-east-1`.
> The provider is hardcoded to that region in `terraform.tf`.

### Credentials & secrets handling

This project stores no secrets in the repository, in Terraform state, or at runtime.

| Layer | Mechanism | Detail |
|---|---|---|
| Remote state | HCP Terraform | org — edit `organization` in `terraform.tf` to your own HCP Terraform org; workspace — defaults to `aws_wafacl_golden` (project `aws`). State is stored remotely, encrypted at rest, with access restricted to the workspace |
| Deployment credentials | HCP Terraform workspace environment variables, marked **Sensitive** | Write-only once saved — cannot be read back through the UI or API; never appear in the repository, plan output, or on a local machine. For production, [dynamic provider credentials](https://developer.hashicorp.com/terraform/cloud-docs/workspaces/dynamic-provider-credentials) (OIDC) are recommended — Terraform assumes a short-lived IAM role per run, so no static credentials are stored at all |

### Steps

```bash
# 1. Clone the repository
git clone https://github.com/victorfengdj/terraform-aws-wafacl-golden.git
cd terraform-aws-wafacl-golden

# 2. Authenticate with HCP Terraform (one-time setup)
# first: edit terraform.tf — set organization to your own HCP Terraform org
terraform login

# 3. Initialise — downloads providers and connects to the remote workspace
terraform init

# 4. Preview the changes
terraform plan

# 5. Apply
terraform apply
```

### Cost estimate (at 3 billion requests/month)

| Rule group | Cost |
|---|---|
| Managed rules (IP Rep, Anon IP, KBI, CRS, SQLi) | $0 beyond base WAF fee |
| Anti-DDoS L7 | $20 / month flat |
| Bot Control TARGETED | ~$10 / million requests on scoped paths |
| Base WAF ACL | $5 / month |