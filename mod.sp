// Benchmarks and controls for specific services should override the "service" tag
locals {
  aws_perimeter_common_tags = {
    category = "Perimeter"
    plugin   = "aws"
    service  = "AWS"
  }
}

variable "common_dimensions" {
  type        = list(string)
  description = "A list of common dimensions to add to each control."
  # Define which common dimensions should be added to each control.
  # - account_id
  # - connection_name (_ctx ->> 'connection_name')
  # - region
  default     = [ "account_id", "region" ,"connection_name"]
}

locals {
  # Local internal variable to build the SQL select clause for common
  # dimensions using a table name qualifier if required. Do not edit directly.
  common_dimensions_qualifier_sql = <<-EOQ
  %{~ if contains(var.common_dimensions, "connection_name") }, __QUALIFIER___ctx ->> 'connection_name'%{ endif ~}
  %{~ if contains(var.common_dimensions, "region") }, __QUALIFIER__region%{ endif ~}
  %{~ if contains(var.common_dimensions, "account_id") }, __QUALIFIER__account_id%{ endif ~}
  EOQ
}

locals {
  # Local internal variable with the full SQL select clause for common
  # dimensions. Do not edit directly.
  common_dimensions_sql = replace(local.common_dimensions_qualifier_sql, "__QUALIFIER__", "")
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

  requires {
    plugin "aws" {
      version = "0.70.0"
    }
  }
}
