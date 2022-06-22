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
  description   = "Run individual configuration, and security controls or full compliance benchmarks for resources publicly shared across all your AWS accounts using Steampipe."
  color         = "#FF9900"
  documentation = file("./docs/index.md")
  icon          = "/images/mods/turbot/aws-perimeter.svg"
  categories    = ["aws", "perimeter", "public cloud", "security"]

  opengraph {
    title       = "Steampipe Mod for AWS Perimeter"
    description = "Run individual configuration checks for AWS public accessible service resource types across all your AWS accounts using Steampipe."
    image       = "/images/mods/turbot/aws-perimeter-social-graphic.png"
  }

  requires {
    plugin "aws" {
      version = "0.65.0"
    }
  }
}
