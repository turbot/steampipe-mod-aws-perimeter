## v0.2 [2022-07-15]

_Dependencies_

- AWS plugin `v0.70.0` or higher is now required. ([#14](https://github.com/turbot/steampipe-mod-aws-perimeter/pull/14))

_What's new?_

- New controls added: ([#10](https://github.com/turbot/steampipe-mod-aws-perimeter/pull/10))
  - API Gateway APIs should prohibit public access (`steampipe check control.api_gateway_rest_api_prohibit_public_access`)
  - Lambda functions should be in a VPC (`steampipe check control.lambda_function_in_vpc`)

_Bug fixes_

- Fixed the `elb_application_lb_waf_enabled` query to correctly check if elastic load balancers have WAF enabled or not. ([#12](https://github.com/turbot/steampipe-mod-aws-perimeter/pull/12))

## v0.1 [2022-06-23]

_What's new?_

- Added: Network Access benchmark (`steampipe check benchmark.network_access`)
- Added: Public Access benchmark (`steampipe check benchmark.public_access`)
- Added: Shared Access benchmark (`steampipe check benchmark.shared_access`)
