// Benchmarks and controls for specific services should override the "service" tag
locals {
  aws_perimeter_common_tags = {
    category = "Perimeter"
    plugin   = "aws"
    service  = "AWS"
  }
}

mod "aws_perimeter" {
  # hub metadata
  title = "AWS Perimeter"
  description   = "Run security controls across all your AWS accounts to look for resources that are publicly accessible, shared with untrusted accounts, have insecure network configurations, and more across all your AWS accounts using Steampipe."
  color         = "#FF9900"
  documentation = file("./docs/index.md")
  icon          = "/images/mods/turbot/aws-perimeter.svg"
  categories    = ["aws", "perimeter", "public cloud", "security"]

  opengraph {
    title       = "Steampipe Mod for AWS Perimeter"
  description   = "Run security controls across all your AWS accounts to look for resources that are publicly accessible, shared with untrusted accounts, have insecure network configurations, and more across all your AWS accounts using Steampipe."
    image       = "/images/mods/turbot/aws-perimeter-social-graphic.png"
  }

  # requires {
  #   plugin "aws" {
  #     version = "0.70.0"
  #   }
  # }
}
