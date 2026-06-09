terraform {
  cloud {
    organization = "wgf"
    workspaces {
      project = "aws"
      name    = "aws_wafacl_golden"
    }
  }

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }

  required_version = ">= 1.2"
}

# CloudFront-scoped WAFs must be deployed in us-east-1 regardless of
# where the application resources live.
provider "aws" {
  region = "us-east-1"
}
