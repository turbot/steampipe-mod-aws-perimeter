mod "aws_perimeter" {
  # Hub metadata
  title         = "AWS Perimeter"
  description   = "Run security controls across all your AWS accounts to look for resources that are publicly accessible, shared with untrusted accounts, have insecure network configurations, and more across all your AWS accounts using Powerpipe and Steampipe."
  color         = "#FF9900"
  documentation = file("./docs/index.md")
  icon          = "/images/mods/turbot/aws-perimeter.svg"
  categories    = ["aws", "perimeter", "public cloud", "security"]

  opengraph {
    title       = "Powerpipe Mod for AWS Perimeter"
    description = "Run security controls across all your AWS accounts to look for resources that are publicly accessible, shared with untrusted accounts, have insecure network configurations, and more across all your AWS accounts using Powerpipe and Steampipe."
    image       = "/images/mods/turbot/aws-perimeter-social-graphic.png"
  }

  require {
    plugin "aws" {
      min_version = "0.70.0"
    }
  }
}
