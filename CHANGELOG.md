## v0.7 [2023-11-03]

_Breaking changes_

- Updated the plugin dependency section of the mod to use `min_version` instead of `version`. ([#45](https://github.com/turbot/steampipe-mod-aws-perimeter/pull/45))

- Fixed the README doc to include correct links to the benchmarks. ([#47](https://github.com/turbot/steampipe-mod-aws-perimeter/pull/47)) (Thanks [@vil02](https://github.com/vil02) for the contribution!)

## v0.6 [2023-07-31]

_Enhancements_

- Added the following controls to `Public Access` benchmark: ([#37](https://github.com/turbot/steampipe-mod-aws-perimeter/pull/37))
  - `api_gateway_rest_api_policy_prohibit_public_access`
  - `backup_vault_policy_prohibit_public_access`
  - `cloudwatch_log_resource_policy_prohibit_public_access`
  - `codeartifact_domain_policy_prohibit_public_access`
  - `codeartifact_repository_policy_prohibit_public_access`
  - `efs_file_system_policy_prohibit_public_access`
  - `elasticsearch_domain_policy_prohibit_public_access`
  - `eventbridge_bus_policy_prohibit_public_access`
  - `media_store_container_policy_prohibit_public_access`
  - `secretsmanager_secret_policy_prohibit_public_access`

## v0.5 [2023-07-13]

_Bug fixes_

- Fixed the inline query of the `ec2_ami_shared_with_trusted_accounts` control to correctly check if EC2 AMIs are only shared with trusted accounts. ([#34](https://github.com/turbot/steampipe-mod-aws-perimeter/pull/34))

## v0.4 [2023-06-28]

_Bug fixes_

- Fixed the inline query of the `kms_key_policy_prohibit_public_access` control to correctly check if KMS key policies allow public access. ([#30](https://github.com/turbot/steampipe-mod-aws-perimeter/pull/30))
- Fixed dashboard localhost URLs in README and index doc. ([#29](https://github.com/turbot/steampipe-mod-aws-perimeter/pull/29))

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
