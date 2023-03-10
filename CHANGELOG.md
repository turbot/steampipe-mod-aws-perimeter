## v0.3 [2023-03-10]

_What's new?_

- Added `tags` as dimensions to group and filter findings. (see [var.tag_dimensions](https://hub.steampipe.io/mods/turbot/aws_perimeter/variables)) ([#25](https://github.com/turbot/steampipe-mod-aws-perimeter/pull/25))
- Added `connection_name` in the common dimensions to group and filter findings. (see [var.common_dimensions](https://hub.steampipe.io/mods/turbot/aws_perimeter/variables)) ([#25](https://github.com/turbot/steampipe-mod-aws-perimeter/pull/25))

## v0.2 [2022-07-15]

_What's new?_

- New controls added: ([#10](https://github.com/turbot/steampipe-mod-aws-perimeter/pull/10))
  - API Gateway APIs should prohibit public access (`steampipe check control.api_gateway_rest_api_prohibit_public_access`)
  - Lambda functions should be in a VPC (`steampipe check control.lambda_function_in_vpc`)

_Bug fixes_

- Fixed the `elb_application_lb_waf_enabled` query to correctly check if application load balancers have WAF enabled or not. ([#12](https://github.com/turbot/steampipe-mod-aws-perimeter/pull/12))

_Dependencies_

- AWS plugin `v0.70.0` or higher is now required. ([#14](https://github.com/turbot/steampipe-mod-aws-perimeter/pull/14))

## v0.1 [2022-06-23]

_What's new?_

- Added: Network Access benchmark (`steampipe check benchmark.network_access`)
- Added: Public Access benchmark (`steampipe check benchmark.public_access`)
- Added: Shared Access benchmark (`steampipe check benchmark.shared_access`)
