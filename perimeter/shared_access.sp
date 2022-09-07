variable "trusted_accounts" {
  type        = list(string)
  default     = ["123456781234", "123456781200"]
  description = "A list of trusted AWS accounts which can be shared with resources."
}

variable "trusted_organizations" {
  type        = list(string)
  default     = ["o-abcdhqk8mns", "o-efghqk8pab"]
  description = "A list of trusted AWS organizations which can be shared with resources."
}

variable "trusted_organization_units" {
  type        = list(string)
  default     = ["ou-abcdek7fks", "ou-123def789"]
  description = "A list of trusted AWS organizations units (OUs) which can be shared with resources."
}

variable "trusted_services" {
  type        = list(string)
  default     = ["ec2.amazonaws.com", "elasticloadbalancing.amazonaws.com"]
  description = "A list of trusted AWS services which can be shared with resources."
}

variable "trusted_identity_providers" {
  type        = list(string)
  default     = ["arn:aws:iam::987654321098:saml-provider/provider-name", "accounts.google.com"]
  description = "A list of trusted AWS identity providers which can be shared with resources."
}

benchmark "shared_access" {
  title         = "Shared Access"
  description   = "Resources should only be shared with trusted entities through AWS Resource Access Manager (RAM), configurations, or resource policies."
  documentation = file("./perimeter/docs/shared_access.md")
  children = [
    benchmark.ram_shared_access,
    benchmark.shared_access_settings,
    benchmark.resource_policy_shared_access,
  ]

  tags = merge(local.aws_perimeter_common_tags, {
    type = "Benchmark"
  })
}

benchmark "ram_shared_access" {
  title         = "RAM Shared Access"
  description   = "AWS Resource Access Manager (RAM) helps you securely share your resources that you create in one AWS account with other AWS accounts. Resources shared through RAM should only be shared with trusted accounts."
  documentation = file("./perimeter/docs/ram_shared_access.md")
  children = [
    control.ram_resource_shared_with_trusted_accounts,
    control.ram_resource_shared_with_trusted_organization_units,
    control.ram_resource_shared_with_trusted_organizations
  ]

  tags = merge(local.aws_perimeter_common_tags, {
    type = "Benchmark"
  })
}

control "ram_resource_shared_with_trusted_accounts" {
  title       = "Resources shared through RAM should only be shared with trusted accounts"
  description = "AWS Resource Access Manager (RAM) helps you securely share your resources across AWS accounts, organizational units (OUs), and organizations for supported resource types. Check if you share resources with an account that is not part of the trusted list of accounts."

  sql = <<-EOT
    with ram_shared_resources as (
      select distinct
        rsa.associated_entity as "shared_resource",
        rpa.associated_entity as "shared_with_principal",
        rsa.status,
        rsa.region,
        rsa.account_id
      from
        aws_ram_resource_association as rsa
        inner join aws_ram_principal_association as rpa on rsa.resource_share_name = rpa.resource_share_name
      where
        rsa.status <> 'FAILED' and rpa.status <> 'FAILED'
        and rpa.associated_entity ~ '^[0-9]+$'
    ),
    shared_data as (
      select
        (regexp_split_to_array(shared_resource, ':'))[6] as resource,
        to_jsonb(string_to_array(string_agg(shared_with_principal, ','), ',', '')) - ($1)::text[] as untrusted_accounts,
        region,
        account_id
      FROM
        ram_shared_resources
      group by
        shared_resource,
        region,
        account_id
    )
    select
      resource,
      case
        when jsonb_array_length(untrusted_accounts) > 0 then 'alarm'
        else 'ok'
      end as status,
      case
        when jsonb_array_length(untrusted_accounts) > 0 then
          resource ||
          case
            when jsonb_array_length(untrusted_accounts) > 2 then
              concat(' shared with untrusted accounts ', untrusted_accounts #>> '{0}', ', ', untrusted_accounts #>> '{1}', ' and ', (jsonb_array_length(untrusted_accounts) - 2)::text, ' more.')
            when jsonb_array_length(untrusted_accounts) = 2 then concat(' shared with untrusted accounts ', untrusted_accounts #>> '{0}', ' and ', untrusted_accounts #>> '{1}', '.')
            else concat(' shared with untrusted account ', untrusted_accounts #>> '{0}', '.')
          end
        else resource || ' shared with trusted account(s).'
      end as reason,
      region,
      account_id
    from
      shared_data;
  EOT

  param "trusted_accounts" {
    description = "A list of trusted accounts."
    default     = var.trusted_accounts
  }

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/RAM"
  })
}

control "ram_resource_shared_with_trusted_organizations" {
  title       = "Resources shared through RAM should only be shared with trusted organizations"
  description = "AWS Resource Access Manager (RAM) helps you securely share your resources across AWS accounts, organizational units (OUs), and organizations for supported resource types. Check if you share resources with an account that is not part of the trusted list of organizations."

  sql = <<-EOT
    with ram_shared_resources as (
      select distinct
        rsa.associated_entity as "shared_resource",
        rpa.associated_entity as "shared_with_organization",
        rsa.status,
        rsa.region,
        rsa.account_id,
        split_part((rpa.associated_entity), '/', 1)
      from
        aws_ram_resource_association as rsa
        inner join aws_ram_principal_association as rpa on rsa.resource_share_name = rpa.resource_share_name
      where
        rsa.status <> 'FAILED' and rpa.status <> 'FAILED'
        and split_part((rpa.associated_entity), '/', 1) like '%:organization'
    ),
    shared_data as (
      select
        (regexp_split_to_array(shared_resource, ':'))[6] as resource,
        to_jsonb(string_to_array(string_agg(split_part(shared_with_organization, '/', 2), ','), ',', '')) - ($1)::text[] as untrusted_organizations,
        region,
        account_id
      FROM
        ram_shared_resources
      group by
        shared_resource,
        region,
        account_id
    )
    select
      resource,
      case
        when jsonb_array_length(untrusted_organizations) > 0 then 'alarm'
        else 'ok'
      end as status,
      case
        when jsonb_array_length(untrusted_organizations) > 0 then
          resource ||
          case
            when jsonb_array_length(untrusted_organizations) > 2 then
              concat(' shared with untrusted organizations ', untrusted_organizations #>> '{0}', ', ', untrusted_organizations #>> '{1}', ' and ', (jsonb_array_length(untrusted_organizations) - 2)::text, ' more.')
            when jsonb_array_length(untrusted_organizations) = 2 then concat(' shared with untrusted organizations ', untrusted_organizations #>> '{0}', ' and ', untrusted_organizations #>> '{1}', '.')
            else concat(' shared with untrusted organization ', untrusted_organizations #>> '{0}', '.')
          end
        else resource || ' shared with trusted organizationt(s).'
      end as reason,
      region,
      account_id
    from
      shared_data;
  EOT

  param "trusted_organizations" {
    description = "A list of trusted organizations."
    default     = var.trusted_organizations
  }

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/RAM"
  })
}

control "ram_resource_shared_with_trusted_organization_units" {
  title       = "Resources shared through RAM should only be shared with trusted OUs"
  description = "AWS Resource Access Manager (RAM) helps you securely share your resources across AWS accounts, organizational units (OUs), and organizations for supported resource types. Check if you share resources with an account that is not part of the trusted list of OUs."

  sql = <<-EOT
    with ram_shared_resources as (
      select distinct
        rsa.associated_entity as "shared_resource",
        rpa.associated_entity as "shared_with_organization_unit",
        rsa.status,
        rsa.region,
        rsa.account_id,
        split_part((rpa.associated_entity), '/', 1)
      from
        aws_ram_resource_association as rsa
        inner join aws_ram_principal_association as rpa on rsa.resource_share_name = rpa.resource_share_name
      where
        rsa.status <> 'FAILED' and rpa.status <> 'FAILED'
        and split_part((rpa.associated_entity), '/', 1) like '%:ou'
    ),
    shared_data as (
      select
        (regexp_split_to_array(shared_resource, ':'))[6] as resource,
        to_jsonb(string_to_array(string_agg(split_part(shared_with_organization_unit, '/', 3), ','), ',', '')) - ($1)::text[] as untrusted_organizations_unit,
        region,
        account_id
      FROM
        ram_shared_resources
      group by
        shared_resource,
        region,
        account_id
    )
    select
      resource,
      case
        when jsonb_array_length(untrusted_organizations_unit) > 0 then 'alarm'
        else 'ok'
      end as status,
      case
        when jsonb_array_length(untrusted_organizations_unit) > 0 then
          resource ||
          case
            when jsonb_array_length(untrusted_organizations_unit) > 2 then
              concat( ' shared with untrusted OUs ' ,untrusted_organizations_unit #>> '{0}', ', ', untrusted_organizations_unit #>> '{1}', ' and ', (jsonb_array_length(untrusted_organizations_unit) - 2)::text, ' more.')
            when jsonb_array_length(untrusted_organizations_unit) = 2 then concat(' shared with untrusted OUs ', untrusted_organizations_unit #>> '{0}', ', ', untrusted_organizations_unit #>> '{1}', '.')
            else concat(' shared with untrusted OU ', untrusted_organizations_unit #>> '{0}', '.')
          end
        else resource || ' shared with trusted OU(s).'
      end as reason,
      region,
      account_id
    from
      shared_data;
  EOT

  param "trusted_organization_units" {
    description = "A list of trusted organization units."
    default     = var.trusted_organization_units
  }

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/RAM"
  })
}

benchmark "shared_access_settings" {
  title         = "Shared Access Settings"
  description   = "The AWS resource config shared access is a set of controls that detect if your deployed cloud resources are shared for use by principals outside of the AWS account that created the resource. This can be configured by modifying any parameter using sharing API."
  documentation = file("./perimeter/docs/shared_access_settings.md")
  children = [
    control.config_aggregator_shared_with_trusted_accounts,
    control.directory_service_directory_shared_with_trusted_accounts,
    control.dlm_ebs_snapshot_policy_shared_with_trusted_accounts,
    control.ebs_snapshot_shared_with_trusted_accounts,
    control.ec2_ami_shared_with_trusted_accounts,
    control.ec2_ami_shared_with_trusted_organization_units,
    control.ec2_ami_shared_with_trusted_organizations,
    control.guarduty_findings_shared_with_trusted_accounts,
    control.rds_db_snapshot_shared_with_trusted_accounts
  ]

  tags = merge(local.aws_perimeter_common_tags, {
    type = "Benchmark"
  })
}

control "config_aggregator_shared_with_trusted_accounts" {
  title       = "Config service aggregator should only collect data from trusted accounts"
  description = "Config service aggregator helps in monitoring compliance data for rules and accounts in the aggregated view. An aggregator is an AWS Config resource type that collects AWS Config configuration and compliance data from (1) Multiple accounts and multiple regions, (2) Single account and multiple regions, (3) An organization in AWS Organizations and all the accounts in that organization which have AWS Config enabled."

  sql = <<-EOT
    select
      title as resource,
      case
        when authorized_account_id is null or authorized_account_id = any (($1)::text[]) then 'ok'
        else 'info'
      end as status,
      case
        when authorized_account_id is null or authorized_account_id = any (($1)::text[]) then title || ' shared with trusted account.'
        else title || ' shared with untrusted account ' || authorized_account_id || '.'
      end as reason,
      region,
      account_id
    from
      aws_config_aggregate_authorization;
  EOT

  param "trusted_accounts" {
    description = "A list of trusted accounts."
    default     = var.trusted_accounts
  }

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/Config"
  })
}

control "directory_service_directory_shared_with_trusted_accounts" {
  title       = "Directory Service directories should only be shared with trusted accounts"
  description = "This control checks whether Directory Service directories access are restricted to trusted accounts."

  sql = <<-EOT
    with all_directories as (
      select
        directory_id,
        shared_directories,
        region,
        title,
        account_id
      from
        aws_directory_service_directory
      order by
        account_id,
        region,
        directory_id,
        title
    ),
    directory_data as (
      select
        directory_id,
        to_jsonb(string_to_array(string_agg(sd ->> 'SharedAccountId', ','), ',')) as shared_accounts,
        to_jsonb(string_to_array(string_agg(sd ->> 'SharedAccountId', ','), ',')) - ($1)::text[] as untrusted_accounts,
        region,
        title,
        account_id
      from
        all_directories,
        jsonb_array_elements(shared_directories) sd
      group by
        directory_id,
        region,
        account_id,
        title
    ),
    evaluated_directories as (
      select
        all_directories.*,
        shared_accounts,
        untrusted_accounts
      from
        all_directories
        left join directory_data on all_directories.directory_id = directory_data.directory_id
    )
    select
      directory_id as resource,
      case
        when shared_accounts is null or jsonb_array_length(shared_accounts) = 0 then 'ok'
        when untrusted_accounts is not null or jsonb_array_length(untrusted_accounts) > 0 then 'info'
        else 'ok'
      end as status,
      case
        when shared_accounts is null or jsonb_array_length(shared_accounts) = 0 then directory_id || ' is not shared.'
        when untrusted_accounts is not null or jsonb_array_length(shared_accounts) > 0 then directory_id || ' shared with ' ||
          case
            when jsonb_array_length(untrusted_accounts) > 2
            then concat('untrusted accounts ' , untrusted_accounts #>> '{0}', ', ', untrusted_accounts #>> '{1}', ' and ' || (jsonb_array_length(untrusted_accounts) - 2)::text || ' more.')
            when jsonb_array_length(untrusted_accounts) = 2 then
            concat('untrusted accounts ', untrusted_accounts #>> '{0}', ' and ', untrusted_accounts #>> '{1}', '.')
            else concat('untrusted account ', untrusted_accounts #>> '{0}', '.')
          end
        else directory_id || ' shared with trusted account(s).'
      end as reason,
      region,
      account_id
    from
      evaluated_directories;
  EOT

  param "trusted_accounts" {
    description = "A list of trusted accounts."
    default     = var.trusted_accounts
  }

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/DirectoryService"
  })
}

control "dlm_ebs_snapshot_policy_shared_with_trusted_accounts" {
  title       = "DLM policies should only share EBS snapshot copies with trusted accounts"
  description = "Automating cross-account snapshot copies enables you to copy your EBS snapshots to specific regions in an isolated account and encrypt those snapshots with an encryption key. This enables you to protect yourself against data loss in the event of your account being compromised. This control checks if EBS snapshots are being copied to untrusted accounts."

  sql = <<-EOT
    with dlm_policy_shared_snapshot_copies as (
      select
        policy_id,
        policy_type,
        state,
        -- A DLM policy can have at most 4 schedules, we need to verify each schedule if snapshots, through it will be shared to external accounts
        (policy_details #> '{Schedules,0,ShareRules,0,TargetAccounts}')::jsonb - ($1)::text[] as schedule_0_untrusted_accountss,
        (policy_details #> '{Schedules,1,ShareRules,0,TargetAccounts}')::jsonb - ($1)::text[] as schedule_1_untrusted_accountss,
        (policy_details #> '{Schedules,2,ShareRules,0,TargetAccounts}')::jsonb - ($1)::text[] as schedule_2_untrusted_accountss,
        (policy_details #> '{Schedules,3,ShareRules,0,TargetAccounts}')::jsonb - ($1)::text[] as schedule_3_untrusted_accountss,
        account_id,
        region
      from
        aws_dlm_lifecycle_policy
      where
        policy_type = 'EBS_SNAPSHOT_MANAGEMENT'
    )
    select
      policy_id as resource,
      case
        when state = 'DISABLED' then 'skip'
        when jsonb_array_length(schedule_0_untrusted_accountss) > 0
        or jsonb_array_length(schedule_1_untrusted_accountss) > 0
        or jsonb_array_length(schedule_2_untrusted_accountss) > 0
        or jsonb_array_length(schedule_3_untrusted_accountss) > 0 then 'info'
      else 'ok'
      end as status,
      case
        when state = 'DISABLED' then policy_id || ' policy disabled.'
        when jsonb_array_length(schedule_0_untrusted_accountss) > 0 then
          policy_id || ' creates EBS snapshots and shares with ' ||
          case
            when jsonb_array_length(schedule_0_untrusted_accountss) > 2 then
              concat(schedule_0_untrusted_accountss #>> '{0}', ', ', schedule_0_untrusted_accountss #>> '{1}', ' and ', (jsonb_array_length(schedule_0_untrusted_accountss) - 2)::text, ' more untrusted account(s).')
            when jsonb_array_length(schedule_0_untrusted_accountss) = 2 then
              concat(schedule_0_untrusted_accountss #>> '{0}', ', ', schedule_0_untrusted_accountss #>> '{1}', ' untrusted accounts.')
            else concat(schedule_0_untrusted_accountss #>> '{0}', ' untrusted account.')
          end
        when jsonb_array_length(schedule_1_untrusted_accountss) > 0 then
          policy_id || ' creates EBS snapshots and shares with ' ||
          case
            when jsonb_array_length(schedule_1_untrusted_accountss) > 2 then
              concat('untrusted accounts ', schedule_1_untrusted_accountss #>> '{0}', ', ', schedule_1_untrusted_accountss #>> '{1}', ' and ', (jsonb_array_length(schedule_1_untrusted_accountss) - 2)::text, ' more.')
            when jsonb_array_length(schedule_1_untrusted_accountss) = 2 then
              concat('untrusted accounts ', schedule_1_untrusted_accountss #>> '{0}', ' and ', schedule_1_untrusted_accountss #>> '{1}', '.')
            else concat('untrusted account ', schedule_1_untrusted_accountss #>> '{0}', '.')
          end

        when jsonb_array_length(schedule_2_untrusted_accountss) > 0 then
          policy_id || ' creates EBS snapshots and shares with ' ||
          case
            when jsonb_array_length(schedule_2_untrusted_accountss) > 2 then
              concat('untrusted accounts ', schedule_2_untrusted_accountss #>> '{0}', ', ', schedule_2_untrusted_accountss #>> '{1}', ' and ', (jsonb_array_length(schedule_2_untrusted_accountss) - 2)::text, ' more.')
            when jsonb_array_length(schedule_2_untrusted_accountss) = 2 then
              concat('untrusted accounts ', schedule_2_untrusted_accountss #>> '{0}', ' and ', schedule_2_untrusted_accountss #>> '{1}', '.')
            else concat('untrusted account ', schedule_2_untrusted_accountss #>> '{0}', '.')
          end

        when jsonb_array_length(schedule_3_untrusted_accountss) > 0 then
          policy_id || ' creates EBS snapshots and shares with ' ||
          case
            when jsonb_array_length(schedule_3_untrusted_accountss) > 2 then
              concat('untrusted accounts ', schedule_3_untrusted_accountss #>> '{0}', ', ', schedule_3_untrusted_accountss #>> '{1}', ' and ', (jsonb_array_length(schedule_3_untrusted_accountss) - 2)::text, ' more.')
            when jsonb_array_length(schedule_3_untrusted_accountss) = 2 then
              concat('untrusted accounts ', schedule_3_untrusted_accountss #>> '{0}', ' and ', schedule_3_untrusted_accountss #>> '{1}', '.')
            else concat('untrusted account ', schedule_3_untrusted_accountss #>> '{0}', '.')
          end
        else policy_id || ' does not create any EBS snapshot shared with untrusted account(s).'
      end as reason,
      region,
      account_id
    from
      dlm_policy_shared_snapshot_copies;
  EOT

  param "trusted_accounts" {
    description = "A list of trusted accounts."
    default     = var.trusted_accounts
  }

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/EBS"
  })
}

control "ec2_ami_shared_with_trusted_accounts" {
  title       = "EC2 AMIs should only be shared with trusted accounts"
  description = "AWS AMIs can be shared with specific AWS accounts without making the AMI public. This control checks if AMIs are shared with untrusted accounts."

  sql = <<-EOT
    with all_amis as (
      select
        title,
        public,
        launch_permissions,
        region,
        account_id
      from
        aws_ec2_ami
      order by
        account_id,
        region,
        title
    ),
    ami_data as (
      select
        title,
        public,
        string_agg(lp ->> 'Group', ',') as public_access,
        to_jsonb(string_to_array(string_agg(lp ->> 'UserId', ','), ',')) as shared_accounts,
        to_jsonb(string_to_array(string_agg(lp ->> 'UserId', ','), ',')) - ($1)::text as untrusted_accounts,
        region,
        account_id
      from
        all_amis,
        jsonb_array_elements(launch_permissions) lp
      group by
        title, public,region,account_id
    ),
    evaluated_amis as (
      select
        all_amis.*,
        public_access,
        untrusted_accounts,
        shared_accounts
      from
        all_amis left join ami_data on all_amis.account_id = ami_data.account_id and all_amis.region = ami_data.region and all_amis.title = ami_data.title
    )
    select
      title as resource,
      case
        when public then 'info'
        when shared_accounts is null then 'ok'
        when untrusted_accounts is not null then 'info'
        else 'ok'
      end as status,
      case
        when public then title || ' is public.'
        when shared_accounts is null then title || ' is not shared.'
        when untrusted_accounts is not null then title ||
          case
            when jsonb_array_length(untrusted_accounts) > 2
            then concat(' shared with untrusted accounts ', untrusted_accounts #>> '{0}', ', ', untrusted_accounts #>> '{1}', ' and ' || (jsonb_array_length(untrusted_accounts) - 2)::text || ' more.' )
            when jsonb_array_length(untrusted_accounts) = 2
            then concat(' shared with untrusted accounts ', untrusted_accounts #>> '{0}', ' and ', untrusted_accounts #>> '{1}', '.')
            else concat(' shared with untrusted account ', untrusted_accounts #>> '{0}', '.')
          end
        else title || ' shared with trusted account(s).'
      end as reason,
        region,
        account_id
    from
      evaluated_amis;
  EOT

  param "trusted_accounts" {
    description = "A list of trusted accounts."
    default     = var.trusted_accounts
  }

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/EC2"
  })
}

control "ec2_ami_shared_with_trusted_organizations" {
  title       = "EC2 AMIs should only be shared with trusted organizations"
  description = "AWS AMIs can be shared with specific AWS organizations without making the AMI public. This control checks if AMIs are shared with untrusted organizations."

  sql = <<-EOT
    with all_amis as (
      select
        title,
        public,
        launch_permissions,
        region,
        account_id
      from
        aws_ec2_ami
      order by
        account_id,
        region,
        title
    ),
    ami_data as (
      select
        title,
        public,
        string_agg(lp ->> 'Group', ',') as public_access,
        to_jsonb(string_to_array(string_agg(split_part((lp ->> 'OrganizationArn'), '/', 2), ','), ',')) as shared_organizations,
        to_jsonb(string_to_array(string_agg(split_part((lp ->> 'OrganizationArn'), '/', 2), ','), ',')) - ($1)::text[] as untrusted_organizations,
        region,
        account_id
      from
        all_amis,
        jsonb_array_elements(launch_permissions) lp
      group by
        title, public,region,account_id
    ),
    evaluated_amis as (
      select
        all_amis.*,
        public_access,
        untrusted_organizations,
        shared_organizations
      from
        all_amis left join ami_data on all_amis.account_id = ami_data.account_id and all_amis.region = ami_data.region and all_amis.title = ami_data.title
    )
    select
      title as resource,
      case
        when public then 'info'
        when shared_organizations is null then 'ok'
        when untrusted_organizations is not null then 'info'
        else 'ok'
      end as status,
      case
        when public then title || ' is public.'
        when shared_organizations is null then title || ' is not shared.'
        when untrusted_organizations is not null then title || ' shared with ' ||
          case
            when jsonb_array_length(untrusted_organizations) > 2
            then concat('untrusted organizations ', untrusted_organizations #>> '{0}', ', ', untrusted_organizations #>> '{1}', ' and ' || (jsonb_array_length(untrusted_organizations) - 2)::text || ' more.' )
            when jsonb_array_length(untrusted_organizations) = 2
            then concat('untrusted organizations ', untrusted_organizations #>> '{0}', ' and ', untrusted_organizations #>> '{1}', '.')
            else concat('untrusted organization ', untrusted_organizations #>> '{0}', '.')
          end
        else title || ' shared with trusted organization(s).'
        end as reason,
        region,
        account_id
    from
      evaluated_amis;
  EOT

  param "trusted_organizations" {
    description = "A list of trusted organizations."
    default     = var.trusted_organizations
  }

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/EC2"
  })
}

control "ec2_ami_shared_with_trusted_organization_units" {
  title       = "EC2 AMIs should only be shared with trusted OUs"
  description = "AWS AMIs can be shared with specific AWS organizations units (OUs) without making the AMI public. This control checks if AMIs are shared with untrusted OUs."

  sql = <<-EOT
    with all_amis as (
      select
        title,
        public,
        launch_permissions,
        region,
        account_id
      from
        aws_ec2_ami
      order by
        account_id,
        region,
        title
    ),
    ami_data as (
      select
        title,
        public,
        string_agg(lp ->> 'Group', ',') as public_access,
        to_jsonb(string_to_array(string_agg(split_part((lp ->> 'OrganizationalUnitArn'), '/', 3), ','), ',')) as shared_organization_units,
        to_jsonb(string_to_array(string_agg(split_part((lp ->> 'OrganizationalUnitArn'), '/', 3), ','), ',')) - ($1)::text[] as untrusted_organization_units,
        region,
        account_id
      from
        all_amis,
        jsonb_array_elements(launch_permissions) lp
      group by
        title, public,region,account_id
    ),
    evaluated_amis as (
      select
        all_amis.*,
        public_access,
        shared_organization_units,
        untrusted_organization_units
      from
        all_amis left join ami_data on all_amis.account_id = ami_data.account_id and all_amis.region = ami_data.region and all_amis.title = ami_data.title
    )
    select
      title as resource,
      case
        when public then 'info'
        when shared_organization_units is null then 'ok'
        when untrusted_organization_units is not null then 'info'
        else 'ok'
      end as status,
      case
        when public then title || ' is public.'
        when shared_organization_units is null then title || ' is not shared.'
        when shared_organization_units is not null then title || ' shared with ' ||
          case
            when jsonb_array_length(untrusted_organization_units) > 2
            then concat('untrusted OUs ', untrusted_organization_units #>> '{0}', ', ', untrusted_organization_units #>> '{1}', ' and ' || (jsonb_array_length(untrusted_organization_units) - 2)::text || ' more.' )
            when jsonb_array_length(untrusted_organization_units) = 2
            then concat('untrusted OUs ', untrusted_organization_units #>> '{0}', ' and ', untrusted_organization_units #>> '{1}', '.')
            else concat('untrusted OU ', untrusted_organization_units #>> '{0}', '.')
          end
        else title || ' shared with trusted OU(s).'
      end as reason,
      region,
      account_id
    from
      evaluated_amis;
  EOT

  param "trusted_organization_units" {
    description = "A list of trusted organization units."
    default     = var.trusted_organization_units
  }

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/EC2"
  })
}

control "ebs_snapshot_shared_with_trusted_accounts" {
  title       = "EBS snapshots should only be shared with trusted accounts"
  description = "This control checks whether EBS snapshots access is restricted to trusted accounts."

  sql = <<-EOT
    with list_of_snashpot_shared_accounts as (
      select
        jsonb_agg((p -> 'UserId')) as list,
        arn
      from
        aws_ebs_snapshot,
        jsonb_array_elements(create_volume_permissions) as p
      group by arn
    ), shared_ebs_snapshot as (
      select
        arn,
        list,
        list::jsonb - ($1)::text[] as untrusted_accounts
      from
        list_of_snashpot_shared_accounts
    )
    select
      s.arn as resource,
      case
        when jsonb_array_length(untrusted_accounts) > 0 then 'info'
        else 'ok'
      end status,
      case
        when s.create_volume_permissions @> '[{"Group": "all"}]'
        then s.title || ' publicly restorable.'
        when jsonb_array_length(untrusted_accounts) > 0 and untrusted_accounts #>> '{0}' != 'all'
        then s.title || ' shared with ' ||
      case
        when jsonb_array_length(untrusted_accounts) > 2
        then concat('untrusted accounts ', untrusted_accounts #>> '{0}', ', ', untrusted_accounts #>> '{1}', ' and ' || (jsonb_array_length(untrusted_accounts) - 2)::text || ' more.' )
        when jsonb_array_length(untrusted_accounts) = 2
        then concat('untrusted accounts ', untrusted_accounts #>> '{0}', ' and ', untrusted_accounts #>> '{1}' , '.')
        else concat('untrusted account ', untrusted_accounts #>> '{0}', '.')
      end
        else
          case when list is null then s.title || ' is not shared.'
          else s.title || ' shared with trusted account(s).' end
      end reason,
      s.region,
      s.account_id
    from
      aws_ebs_snapshot as s left join shared_ebs_snapshot as ss on s.arn = ss.arn ;
  EOT

  param "trusted_accounts" {
    description = "A list of trusted accounts."
    default     = var.trusted_accounts
  }

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/EBS"
  })
}

control "guarduty_findings_shared_with_trusted_accounts" {
  title       = "GuardDuty findings should only be shared with trusted accounts"
  description = "This control checks if GuardDuty findings are only shared with trusted administrator accounts."

  sql = <<-EOT
    select
      title as resource,
      case when master_account ->> 'AccountId' is null or (master_account ->> 'AccountId')::text = any (($1)::text[]) then
        'ok'
      else
        'info'
      end as status,
      case when master_account ->> 'AccountId' is null or (master_account ->> 'AccountId')::text = any (($1)::text[]) then
        title || ' findings shared with trusted administrator account.'
      else
        title || ' findings shared with untrusted administrator account ' || (master_account ->> 'AccountId')::text || '.'
      end as reason,
      region,
      account_id
    from
      aws_guardduty_detector;
  EOT

  param "trusted_accounts" {
    description = "A list of trusted accounts."
    default     = var.trusted_accounts
  }

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/GuardDuty"
  })
}

control "rds_db_snapshot_shared_with_trusted_accounts" {
  title       = "RDS DB snapshots should only be shared with trusted accounts"
  description = "This control checks whether RDS DB snapshots access is restricted to trusted accounts."

  sql = <<-EOT
    (with shared_cluster_snapshot_data as (
      select
        arn,
        title,
        (cluster_snapshot ->> 'AttributeValues')::jsonb as shared_accounts,
        (cluster_snapshot ->> 'AttributeValues')::jsonb - ($1)::text[] as untrusted_accounts,
        region,
        account_id
      from
        aws_rds_db_cluster_snapshot,
        jsonb_array_elements(db_cluster_snapshot_attributes) as cluster_snapshot
    )
    select
      arn as resource,
      case
        when jsonb_array_length(untrusted_accounts) > 0 then 'info'
        else 'ok'
      end status,
      case
        when untrusted_accounts #>> '{0}' = 'all' then title || ' publicly restorable.'
        when jsonb_array_length(untrusted_accounts) > 0 and untrusted_accounts #>> '{0}' != 'all'
        then title ||
      case
        when jsonb_array_length(untrusted_accounts) > 2
        then concat(' shared with untrusted accounts ', untrusted_accounts #>> '{0}', ', ', untrusted_accounts #>> '{1}', ' and ' || (jsonb_array_length(untrusted_accounts) - 2)::text || ' more.' )
        when jsonb_array_length(untrusted_accounts) = 2
        then concat(' shared with untrusted accounts ', untrusted_accounts #>> '{0}', ' and ', untrusted_accounts #>> '{1}', '.')
        else concat(' shared with untrusted account ', untrusted_accounts #>> '{0}', '.')
      end
        else
          case
            when shared_accounts is null then title || ' is not shared.'
            else title || ' shared with trusted account(s).'
          end
      end reason,
      region,
      account_id
    from
      shared_cluster_snapshot_data)

    union

    ( with shared_db_snapshot_data as (
      select
        arn,
        title,
        (database_snapshot ->> 'AttributeValues')::jsonb as shared_accounts,
        (database_snapshot ->> 'AttributeValues')::jsonb - ($1)::text[] as untrusted_accounts,
        region,
        account_id
      from
        aws_rds_db_snapshot,
        jsonb_array_elements(db_snapshot_attributes) as database_snapshot
    )
    select
      arn as resource,
      case
        when jsonb_array_length(untrusted_accounts) > 0 then 'info'
        else 'ok'
      end status,
      case
        when untrusted_accounts #>> '{0}' = 'all'
        then title || ' publicly restorable.'
        when jsonb_array_length(untrusted_accounts) > 0 and untrusted_accounts #>> '{0}' != 'all'
        then title ||
      case
        when jsonb_array_length(untrusted_accounts) > 2
        then concat(' shared with untrusted accounts ', untrusted_accounts #>> '{0}', ', ', untrusted_accounts #>> '{1}', ' and ' || (jsonb_array_length(untrusted_accounts) - 2)::text || ' more.' )
        when jsonb_array_length(untrusted_accounts) = 2
        then concat(' shared with untrusted accounts ', untrusted_accounts #>> '{0}', ' and ', untrusted_accounts #>> '{1}')
        else concat(' shared with untrusted account ', untrusted_accounts #>> '{0}', '.')
      end
        else
          case
            when shared_accounts is null then title || ' is not shared.'
            else title || ' shared with trusted account(s).'
          end
      end reason,
      region,
      account_id
    from
      shared_db_snapshot_data);
  EOT

  param "trusted_accounts" {
    description = "A list of trusted accounts."
    default     = var.trusted_accounts
  }

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/RDS"
  })
}

locals {
  resource_policy_shared_account_sql = <<-EOT
    select
      r.__ARN_COLUMN__ as resource,
      case
        when jsonb_array_length(pa.allowed_principal_account_ids) = 0 then 'ok'
        when pa.access_level = 'private' then 'ok'
        when pa.access_level = 'public' then 'alarm'
        when pa.allowed_principal_account_ids <@ to_jsonb(($1)::text[]) then 'ok'
        else 'alarm'
      end as status,
      case
        when jsonb_array_length(pa.allowed_principal_account_ids) = 0 then title || ' trust policy does not reference any accounts.'
        when pa.access_level = 'private' then title || ' trust policy does not reference any cross-accounts.'
        when pa.access_level = 'public' then title || ' trust policy grants access to all AWS accounts.'
        when pa.allowed_principal_account_ids <@ to_jsonb(($1)::text[]) then concat(
          title, 
          ' trust policy grants cross-account access to ',
          jsonb_array_length(pa.allowed_principal_account_ids),
          ' trusted account(s).'
        )
        when jsonb_array_length(to_jsonb(pa.allowed_principal_account_ids) - ($1)::text[]) = 1 then concat(
          title,
          ' trust policy grants cross-account access to ',
          jsonb_array_length(to_jsonb(pa.allowed_principal_account_ids) - ($1)::text[]),
          ' untrusted account: [',
          to_jsonb(pa.allowed_principal_account_ids) - ($1)::text[] ->> 0,
          '].'
        )
        when jsonb_array_length(to_jsonb(pa.allowed_principal_account_ids) - ($1)::text[]) = 2 then concat(
          title,
          ' trust policy grants cross-account access to ',
          jsonb_array_length(to_jsonb(pa.allowed_principal_account_ids) - ($1)::text[]),
          ' untrusted accounts: [',
          to_jsonb(pa.allowed_principal_account_ids) - ($1)::text[] ->> 0,
          ',',
          to_jsonb(pa.allowed_principal_account_ids) - ($1)::text[] ->> 1,
          '].'
        )
        else concat(
          title,
          ' trust policy grants cross-account access to ',
          jsonb_array_length(to_jsonb(pa.allowed_principal_account_ids) - ($1)::text[]),
          ' untrusted accounts: [',
          to_jsonb(pa.allowed_principal_account_ids) - ($1)::text[] ->> 0,
          ',',
          to_jsonb(pa.allowed_principal_account_ids) - ($1)::text[] ->> 1,
          ',..].'
        )
      end as reason,
      __DIMENSIONS__
    from
      __TABLE_NAME__ as r,
      aws_resource_policy_analysis as pa
    where
      pa.account_id = r.account_id
      __CRITERIA__
    group by
      resource,
      title,
      pa.is_public,
      pa.allowed_principal_account_ids,
      pa.access_level,
      __DIMENSIONS__
  EOT
}

locals {
  resource_policy_shared_accounts_sql_account = replace(replace(local.resource_policy_shared_account_sql, "__DIMENSIONS__", "r.account_id"), "__CRITERIA__", "and pa.policy = r.assume_role_policy_std")
  resource_policy_shared_accounts_sql_region  = replace(replace(local.resource_policy_shared_account_sql, "__DIMENSIONS__", "r.region, r.account_id"), "__CRITERIA__", "and pa.policy = r.policy_std")
  resource_policy_shared_accounts_sql_kms     = replace(replace(local.resource_policy_shared_account_sql, "__DIMENSIONS__", "r.region, r.account_id"), "__CRITERIA__", "and pa.policy = r.policy_std and key_manager = 'CUSTOMER'")
}

benchmark "resource_policy_shared_access" {
  title         = "Shared Access"                                                                                                                          # TODO
  description   = "Resources should only be shared with trusted entities through AWS Resource Access Manager (RAM), configurations, or resource policies." # TODO
  documentation = file("./perimeter/docs/resource_policy_shared_access.md")
  children = [
    benchmark.resource_policy_shared_accounts_access,
    benchmark.resource_policy_shared_organizations_access,
    benchmark.resource_policy_shared_services_access,
    benchmark.resource_policy_shared_identity_providers_access,
  ]

  tags = merge(local.aws_perimeter_common_tags, {
    type = "Benchmark"
  })
}

benchmark "resource_policy_shared_accounts_access" {
  title         = "Resource Policy Shared Accounts Access"
  description   = "Resources should not be accessible to untrusted accounts through statements in their resource policies."
  documentation = file("./perimeter/docs/resource_policy_shared_accounts_access.md")
  children = [
    control.ecr_repository_policy_prohibits_untrusted_accounts_access,
    control.glacier_vault_policy_prohibits_untrusted_accounts_access,
    control.iam_role_trust_policy_prohibits_untrusted_accounts_access,
    control.kms_key_policy_prohibits_untrusted_accounts_access,
    control.lambda_function_policy_prohibits_untrusted_accounts_access,
    control.s3_bucket_policy_prohibits_untrusted_accounts_access,
    control.sns_topic_policy_prohibits_untrusted_accounts_access,
    control.sqs_queue_policy_prohibits_untrusted_accounts_access
  ]

  tags = merge(local.aws_perimeter_common_tags, {
    type = "Benchmark"
  })
}

control "ecr_repository_policy_prohibits_untrusted_accounts_access" {
  title       = "ECR repository policies should prohibit untrusted account access"
  description = "Check if ECR repository policies allows access to untrusted accounts"
  sql         = replace(replace(local.resource_policy_shared_accounts_sql_region, "__TABLE_NAME__", "aws_ecr_repository"), "__ARN_COLUMN__", "arn")

  param "trusted_accounts" {
    description = "A list of trusted accounts."
    default     = var.trusted_accounts
  }

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/ECR"
  })
}

control "glacier_vault_policy_prohibits_untrusted_accounts_access" {
  title       = "Glacier vault policies should prohibit untrusted account access"
  description = "Check if Glacier vault policies allows access to untrusted accounts"
  sql         = replace(replace(local.resource_policy_shared_accounts_sql_region, "__TABLE_NAME__", "aws_glacier_vault"), "__ARN_COLUMN__", "vault_arn")

  param "trusted_accounts" {
    description = "A list of trusted accounts."
    default     = var.trusted_accounts
  }

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/Glacier"
  })
}

control "iam_role_trust_policy_prohibits_untrusted_accounts_access" {
  title       = "IAM role trust policies should prohibit untrusted account access"
  description = "Check if IAM role trust policies provide access to untrusted accounts, allowing untrusted accounts to assume the role."
  sql         = replace(replace(local.resource_policy_shared_accounts_sql_account, "__TABLE_NAME__", "aws_iam_role"), "__ARN_COLUMN__", "arn")

  param "trusted_accounts" {
    description = "A list of trusted accounts."
    default     = var.trusted_accounts
  }

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/IAM"
  })
}

control "kms_key_policy_prohibits_untrusted_accounts_access" {
  title       = "KMS key policies should prohibit untrusted account access"
  description = "Check if KMS key policies allows access to untrusted accounts"
  sql         = replace(replace(replace(local.resource_policy_shared_accounts_sql_kms, "__TABLE_NAME__", "aws_kms_key"), "__ARN_COLUMN__", "arn"), "__CRITERIA__", "and key_manager = 'CUSTOMER'")

  param "trusted_accounts" {
    description = "A list of trusted accounts."
    default     = var.trusted_accounts
  }

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/KMS"
  })
}

control "lambda_function_policy_prohibits_untrusted_accounts_access" {
  title       = "Lambda function policies should prohibit untrusted account access"
  description = "Check if Lambda function policies allows access to untrusted accounts"
  sql         = replace(replace(local.resource_policy_shared_accounts_sql_region, "__TABLE_NAME__", "aws_lambda_function"), "__ARN_COLUMN__", "arn")

  param "trusted_accounts" {
    description = "A list of trusted accounts."
    default     = var.trusted_accounts
  }

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/Lambda"
  })
}

control "s3_bucket_policy_prohibits_untrusted_accounts_access" {
  title       = "S3 bucket policies should prohibit untrusted account access"
  description = "Check if S3 bucket policies allows access to untrusted accounts"
  sql         = replace(replace(local.resource_policy_shared_accounts_sql_region, "__TABLE_NAME__", "aws_s3_bucket"), "__ARN_COLUMN__", "arn")

  param "trusted_accounts" {
    description = "A list of trusted accounts."
    default     = var.trusted_accounts
  }

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/S3"
  })
}

control "sns_topic_policy_prohibits_untrusted_accounts_access" {
  title       = "SNS topic policies should prohibit untrusted account access"
  description = "Check if SNS topic policies allows access to untrusted accounts"
  sql         = replace(replace(local.resource_policy_shared_accounts_sql_region, "__TABLE_NAME__", "aws_sns_topic"), "__ARN_COLUMN__", "topic_arn")

  param "trusted_accounts" {
    description = "A list of trusted accounts."
    default     = var.trusted_accounts
  }

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/SNS"
  })
}

control "sqs_queue_policy_prohibits_untrusted_accounts_access" {
  title       = "SQS queue policies should prohibit untrusted account access"
  description = "Check if SQS queue policies allows access to untrusted accounts"
  sql         = replace(replace(local.resource_policy_shared_accounts_sql_region, "__TABLE_NAME__", "aws_sqs_queue"), "__ARN_COLUMN__", "queue_arn")

  param "trusted_accounts" {
    description = "A list of trusted accounts."
    default     = var.trusted_accounts
  }

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/SQS"
  })
}

locals {
  resource_policy_shared_organizations_sql = <<-EOT
    select
      r.__ARN_COLUMN__ as resource,
      case
        when jsonb_array_length(pa.allowed_organization_ids) = 0 then 'ok'
        when pa.access_level = 'public' then 'alarm'
        when pa.allowed_organization_ids <@ to_jsonb(($1)::text[]) then 'ok'
        else 'alarm'
      end as status,
      case
        when jsonb_array_length(pa.allowed_organization_ids) = 0 then title || ' trust policy does not reference any organizations.'
        when pa.access_level = 'public' then title || ' trust policy grants wildcarded access to organizations.'
        when pa.allowed_organization_ids <@ to_jsonb(($1)::text[] || ($2)::text[]) then concat(
          title, 
          ' trust policy grants access to ',
          jsonb_array_length(pa.allowed_organization_ids),
          ' trusted organization(s).'
        )
        when jsonb_array_length(to_jsonb(pa.allowed_organization_ids) - (($1)::text[] || ($2)::text[])) = 1 then concat(
          title,
          ' trust policy grants access to ',
          jsonb_array_length(to_jsonb(pa.allowed_organization_ids) - (($1)::text[] || ($2)::text[])),
          ' untrusted organization: [',
          to_jsonb(pa.allowed_organization_ids) - (($1)::text[] || ($2)::text[]) ->> 0,
          '].'
        )
        when jsonb_array_length(to_jsonb(pa.allowed_organization_ids) - (($1)::text[] || ($2)::text[])) = 2 then concat(
          title,
          ' trust policy grants access to ',
          jsonb_array_length(to_jsonb(pa.allowed_organization_ids) - (($1)::text[] || ($2)::text[])),
          ' untrusted organizations: [',
          to_jsonb(pa.allowed_organization_ids) - (($1)::text[] || ($2)::text[]) ->> 0,
          ',',
          to_jsonb(pa.allowed_organization_ids) - (($1)::text[] || ($2)::text[]) ->> 1,
          '].'
        )
        else concat(
          title,
          ' trust policy grants access to ',
          jsonb_array_length(to_jsonb(pa.allowed_organization_ids) - (($1)::text[] || ($2)::text[])),
          ' untrusted organizations: [',
          to_jsonb(pa.allowed_organization_ids) - (($1)::text[] || ($2)::text[]) ->> 0,
          ',',
          to_jsonb(pa.allowed_organization_ids) - (($1)::text[] || ($2)::text[]) ->> 1,
          ',..].'
        )
      end as reason,
      __DIMENSIONS__
    from
      __TABLE_NAME__ as r,
      aws_resource_policy_analysis as pa
    where
      pa.account_id = r.account_id
      __CRITERIA__
    group by
      resource,
      title,
      pa.is_public,
      pa.allowed_organization_ids,
      pa.access_level,
      __DIMENSIONS__
  EOT
}

locals {
  resource_policy_shared_organizations_sql_account = replace(replace(local.resource_policy_shared_organizations_sql, "__DIMENSIONS__", "r.account_id"), "__CRITERIA__", "and pa.policy = r.assume_role_policy_std")
  resource_policy_shared_organizations_sql_region  = replace(replace(local.resource_policy_shared_organizations_sql, "__DIMENSIONS__", "r.region, r.account_id"), "__CRITERIA__", "and pa.policy = r.policy_std")
  resource_policy_shared_organizations_sql_kms     = replace(replace(local.resource_policy_shared_organizations_sql, "__DIMENSIONS__", "r.region, r.account_id"), "__CRITERIA__", "and pa.policy = r.policy_std and key_manager = 'CUSTOMER'")
}

benchmark "resource_policy_shared_organizations_access" {
  title         = "Resource Policy Shared Organizations Access"
  description   = "Resources should not be accessible to untrusted organizations through statements in their resource policies."
  documentation = file("./perimeter/docs/resource_policy_shared_organizations_access.md")
  children = [
    control.ecr_repository_policy_prohibits_untrusted_organizations_access,
    control.glacier_vault_policy_prohibits_untrusted_organizations_access,
    control.iam_role_trust_policy_prohibits_untrusted_organizations_access,
    control.kms_key_policy_prohibits_untrusted_organizations_access,
    control.lambda_function_policy_prohibits_untrusted_organizations_access,
    control.s3_bucket_policy_prohibits_untrusted_organizations_access,
    control.sns_topic_policy_prohibits_untrusted_organizations_access,
    control.sqs_queue_policy_prohibits_untrusted_organizations_access
  ]

  tags = merge(local.aws_perimeter_common_tags, {
    type = "Benchmark"
  })
}

control "ecr_repository_policy_prohibits_untrusted_organizations_access" {
  title       = "ECR repository policies should prohibit untrusted organization access"
  description = "Check if ECR repository policies allows access to untrusted organizations"
  sql         = replace(replace(local.resource_policy_shared_organizations_sql_region, "__TABLE_NAME__", "aws_ecr_repository"), "__ARN_COLUMN__", "arn")

  param "trusted_organizations" {
    description = "A list of trusted organizations."
    default     = var.trusted_organizations
  }

  param "trusted_organization_units" {
    description = "A list of trusted organizations unit."
    default     = var.trusted_organization_units
  }

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/ECR"
  })
}

control "glacier_vault_policy_prohibits_untrusted_organizations_access" {
  title       = "Glacier vault policies should prohibit untrusted organization access"
  description = "Check if Glacier vault policies allows access to untrusted organizations"
  sql         = replace(replace(local.resource_policy_shared_organizations_sql_region, "__TABLE_NAME__", "aws_glacier_vault"), "__ARN_COLUMN__", "vault_arn")

  param "trusted_organizations" {
    description = "A list of trusted organizations."
    default     = var.trusted_organizations
  }

  param "trusted_organization_units" {
    description = "A list of trusted organizations unit."
    default     = var.trusted_organization_units
  }

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/Glacier"
  })
}

control "iam_role_trust_policy_prohibits_untrusted_organizations_access" {
  title       = "IAM role trust policies should prohibit untrusted organization access"
  description = "Check if IAM role trust policies provide access to untrusted organizations, allowing untrusted organizations to assume the role."
  sql         = replace(replace(local.resource_policy_shared_organizations_sql_account, "__TABLE_NAME__", "aws_iam_role"), "__ARN_COLUMN__", "arn")

  param "trusted_organizations" {
    description = "A list of trusted organizations."
    default     = var.trusted_organizations
  }

  param "trusted_organization_units" {
    description = "A list of trusted organizations unit."
    default     = var.trusted_organization_units
  }

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/IAM"
  })
}

control "kms_key_policy_prohibits_untrusted_organizations_access" {
  title       = "KMS key policies should prohibit untrusted organization access"
  description = "Check if KMS key policies allows access to untrusted organizations"
  sql         = replace(replace(replace(local.resource_policy_shared_organizations_sql_kms, "__TABLE_NAME__", "aws_kms_key"), "__ARN_COLUMN__", "arn"), "__CRITERIA__", "and key_manager = 'CUSTOMER'")

  param "trusted_organizations" {
    description = "A list of trusted organizations."
    default     = var.trusted_organizations
  }

  param "trusted_organization_units" {
    description = "A list of trusted organizations unit."
    default     = var.trusted_organization_units
  }

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/KMS"
  })
}

control "lambda_function_policy_prohibits_untrusted_organizations_access" {
  title       = "Lambda function policies should prohibit untrusted organization access"
  description = "Check if Lambda function policies allows access to untrusted organizations"
  sql         = replace(replace(local.resource_policy_shared_organizations_sql_region, "__TABLE_NAME__", "aws_lambda_function"), "__ARN_COLUMN__", "arn")

  param "trusted_organizations" {
    description = "A list of trusted organizations."
    default     = var.trusted_organizations
  }

  param "trusted_organization_units" {
    description = "A list of trusted organizations unit."
    default     = var.trusted_organization_units
  }

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/Lambda"
  })
}

control "s3_bucket_policy_prohibits_untrusted_organizations_access" {
  title       = "S3 bucket policies should prohibit untrusted organization access"
  description = "Check if S3 bucket policies allows access to untrusted organizations"
  sql         = replace(replace(local.resource_policy_shared_organizations_sql_region, "__TABLE_NAME__", "aws_s3_bucket"), "__ARN_COLUMN__", "arn")

  param "trusted_organizations" {
    description = "A list of trusted organizations."
    default     = var.trusted_organizations
  }

  param "trusted_organization_units" {
    description = "A list of trusted organizations unit."
    default     = var.trusted_organization_units
  }

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/S3"
  })
}

control "sns_topic_policy_prohibits_untrusted_organizations_access" {
  title       = "SNS topic policies should prohibit untrusted organization access"
  description = "Check if SNS topic policies allows access to untrusted organizations"
  sql         = replace(replace(local.resource_policy_shared_organizations_sql_region, "__TABLE_NAME__", "aws_sns_topic"), "__ARN_COLUMN__", "topic_arn")

  param "trusted_organizations" {
    description = "A list of trusted organizations."
    default     = var.trusted_organizations
  }

  param "trusted_organization_units" {
    description = "A list of trusted organizations unit."
    default     = var.trusted_organization_units
  }

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/SNS"
  })
}

control "sqs_queue_policy_prohibits_untrusted_organizations_access" {
  title       = "SQS queue policies should prohibit untrusted organization access"
  description = "Check if SQS queue policies allows access to untrusted organizations"
  sql         = replace(replace(local.resource_policy_shared_organizations_sql_region, "__TABLE_NAME__", "aws_sqs_queue"), "__ARN_COLUMN__", "queue_arn")

  param "trusted_organizations" {
    description = "A list of trusted organizations."
    default     = var.trusted_organizations
  }

  param "trusted_organization_units" {
    description = "A list of trusted organizations unit."
    default     = var.trusted_organization_units
  }

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/SQS"
  })
}

locals {
  resource_policy_shared_services_sql = <<-EOT
    select
      r.__ARN_COLUMN__ as resource,
      case
        when jsonb_array_length(pa.allowed_principal_services) = 0 then 'ok'
        when pa.access_level = 'public' then 'alarm'
        when pa.allowed_principal_services <@ to_jsonb(($1)::text[]) then 'ok'
        else 'alarm'
      end as status,
      case
        when jsonb_array_length(pa.allowed_principal_services) = 0 then title || ' trust policy does not reference any services.'
        when pa.access_level = 'public' then title || ' trust policy grants service access to public accounts.'
        when pa.allowed_principal_services <@ to_jsonb(($1)::text[]) then concat(
          title, 
          ' trust policy grants access to ',
          jsonb_array_length(pa.allowed_principal_services),
          ' trusted service(s).'
        )
        when jsonb_array_length(to_jsonb(pa.allowed_principal_services) - ($1)::text[]) = 1 then concat(
          title,
          ' trust policy grants access to ',
          jsonb_array_length(to_jsonb(pa.allowed_principal_services) - ($1)::text[]),
          ' untrusted service: [',
          to_jsonb(pa.allowed_principal_services) - ($1)::text[] ->> 0,
          '].'
        )
        when jsonb_array_length(to_jsonb(pa.allowed_principal_services) - ($1)::text[]) = 2 then concat(
          title,
          ' trust policy grants access to ',
          jsonb_array_length(to_jsonb(pa.allowed_principal_services) - ($1)::text[]),
          ' untrusted services: [',
          to_jsonb(pa.allowed_principal_services) - ($1)::text[] ->> 0,
          ',',
          to_jsonb(pa.allowed_principal_services) - ($1)::text[] ->> 1,
          '].'
        )
        else concat(
          title,
          ' trust policy grants access to ',
          jsonb_array_length(to_jsonb(pa.allowed_principal_services) - ($1)::text[]),
          ' untrusted services: [',
          to_jsonb(pa.allowed_principal_services) - ($1)::text[] ->> 0,
          ',',
          to_jsonb(pa.allowed_principal_services) - ($1)::text[] ->> 1,
          ',..].'
        )
      end as reason,
      __DIMENSIONS__
    from
      __TABLE_NAME__ as r,
      aws_resource_policy_analysis as pa
    where
      pa.account_id = r.account_id
      __CRITERIA__
    group by
      resource,
      title,
      pa.is_public,
      pa.allowed_principal_services,
      pa.access_level,
      __DIMENSIONS__
  EOT
}

locals {
  resource_policy_shared_services_sql_account = replace(replace(local.resource_policy_shared_services_sql, "__DIMENSIONS__", "r.account_id"), "__CRITERIA__", "and pa.policy = r.assume_role_policy_std")
  resource_policy_shared_services_sql_region  = replace(replace(local.resource_policy_shared_services_sql, "__DIMENSIONS__", "r.region, r.account_id"), "__CRITERIA__", "and pa.policy = r.policy_std")
  resource_policy_shared_services_sql_kms     = replace(replace(local.resource_policy_shared_services_sql, "__DIMENSIONS__", "r.region, r.account_id"), "__CRITERIA__", "and pa.policy = r.policy_std and key_manager = 'CUSTOMER'")
}

benchmark "resource_policy_shared_services_access" {
  title         = "Resource Policy Shared Services Access"
  description   = "Resources should not be accessible to untrusted services through statements in their resource policies."
  documentation = file("./perimeter/docs/resource_policy_shared_services_access.md")
  children = [
    control.ecr_repository_policy_prohibits_untrusted_services_access,
    control.glacier_vault_policy_prohibits_untrusted_services_access,
    control.iam_role_trust_policy_prohibits_untrusted_services_access,
    control.kms_key_policy_prohibits_untrusted_services_access,
    control.lambda_function_policy_prohibits_untrusted_services_access,
    control.s3_bucket_policy_prohibits_untrusted_services_access,
    control.sns_topic_policy_prohibits_untrusted_services_access,
    control.sqs_queue_policy_prohibits_untrusted_services_access
  ]

  tags = merge(local.aws_perimeter_common_tags, {
    type = "Benchmark"
  })
}

control "ecr_repository_policy_prohibits_untrusted_services_access" {
  title       = "ECR repository policies should prohibit untrusted organization access"
  description = "Check if ECR repository policies allows access to untrusted services"
  sql         = replace(replace(local.resource_policy_shared_services_sql_region, "__TABLE_NAME__", "aws_ecr_repository"), "__ARN_COLUMN__", "arn")

  param "trusted_services" {
    description = "A list of trusted services."
    default     = var.trusted_services
  }

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/ECR"
  })
}

control "glacier_vault_policy_prohibits_untrusted_services_access" {
  title       = "Glacier vault policies should prohibit untrusted organization access"
  description = "Check if Glacier vault policies allows access to untrusted services"
  sql         = replace(replace(local.resource_policy_shared_services_sql_region, "__TABLE_NAME__", "aws_glacier_vault"), "__ARN_COLUMN__", "vault_arn")

  param "trusted_services" {
    description = "A list of trusted services."
    default     = var.trusted_services
  }

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/Glacier"
  })
}

control "iam_role_trust_policy_prohibits_untrusted_services_access" {
  title       = "IAM role trust policies should prohibit untrusted organization access"
  description = "Check if IAM role trust policies provide access to untrusted services, allowing untrusted services to assume the role."
  sql         = replace(replace(local.resource_policy_shared_services_sql_account, "__TABLE_NAME__", "aws_iam_role"), "__ARN_COLUMN__", "arn")

  param "trusted_services" {
    description = "A list of trusted services."
    default     = var.trusted_services
  }

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/IAM"
  })
}

control "kms_key_policy_prohibits_untrusted_services_access" {
  title       = "KMS key policies should prohibit untrusted organization access"
  description = "Check if KMS key policies allows access to untrusted services"
  sql         = replace(replace(replace(local.resource_policy_shared_services_sql_kms, "__TABLE_NAME__", "aws_kms_key"), "__ARN_COLUMN__", "arn"), "__CRITERIA__", "and key_manager = 'CUSTOMER'")

  param "trusted_services" {
    description = "A list of trusted services."
    default     = var.trusted_services
  }

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/KMS"
  })
}

control "lambda_function_policy_prohibits_untrusted_services_access" {
  title       = "Lambda function policies should prohibit untrusted organization access"
  description = "Check if Lambda function policies allows access to untrusted services"
  sql         = replace(replace(local.resource_policy_shared_services_sql_region, "__TABLE_NAME__", "aws_lambda_function"), "__ARN_COLUMN__", "arn")

  param "trusted_services" {
    description = "A list of trusted services."
    default     = var.trusted_services
  }

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/Lambda"
  })
}

control "s3_bucket_policy_prohibits_untrusted_services_access" {
  title       = "S3 bucket policies should prohibit untrusted organization access"
  description = "Check if S3 bucket policies allows access to untrusted services"
  sql         = replace(replace(local.resource_policy_shared_services_sql_region, "__TABLE_NAME__", "aws_s3_bucket"), "__ARN_COLUMN__", "arn")

  param "trusted_services" {
    description = "A list of trusted services."
    default     = var.trusted_services
  }

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/S3"
  })
}

control "sns_topic_policy_prohibits_untrusted_services_access" {
  title       = "SNS topic policies should prohibit untrusted organization access"
  description = "Check if SNS topic policies allows access to untrusted services"
  sql         = replace(replace(local.resource_policy_shared_services_sql_region, "__TABLE_NAME__", "aws_sns_topic"), "__ARN_COLUMN__", "topic_arn")

  param "trusted_services" {
    description = "A list of trusted services."
    default     = var.trusted_services
  }

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/SNS"
  })
}

control "sqs_queue_policy_prohibits_untrusted_services_access" {
  title       = "SQS queue policies should prohibit untrusted organization access"
  description = "Check if SQS queue policies allows access to untrusted services"
  sql         = replace(replace(local.resource_policy_shared_services_sql_region, "__TABLE_NAME__", "aws_sqs_queue"), "__ARN_COLUMN__", "queue_arn")

  param "trusted_services" {
    description = "A list of trusted services."
    default     = var.trusted_services
  }

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/SQS"
  })
}

locals {
  resource_policy_shared_identity_providers_sql = <<-EOT
    select
      r.__ARN_COLUMN__ as resource,
      case
        when jsonb_array_length(pa.allowed_principal_federated_identities) = 0 then 'ok'
        when pa.access_level = 'public' then 'alarm'
        when pa.allowed_principal_federated_identities <@ to_jsonb(($1)::text[]) then 'ok'
        else 'alarm'
      end as status,
      case
        when jsonb_array_length(pa.allowed_principal_federated_identities) = 0 then title || ' trust policy does not reference any identity providers.'
        when pa.access_level = 'public' then title || ' trust policy grants to wildcarded access to identity providers.'
        when pa.allowed_principal_federated_identities <@ to_jsonb(($1)::text[]) then concat(
          title, 
          ' trust policy grants access to ',
          jsonb_array_length(pa.allowed_principal_federated_identities),
          ' trusted identity provider(s).'
        )
        when jsonb_array_length(to_jsonb(pa.allowed_principal_federated_identities) - ($1)::text[]) = 1 then concat(
          title,
          ' trust policy grants access to ',
          jsonb_array_length(to_jsonb(pa.allowed_principal_federated_identities) - ($1)::text[]),
          ' untrusted identity provider: [',
          to_jsonb(pa.allowed_principal_federated_identities) - ($1)::text[] ->> 0,
          '].'
        )
        when jsonb_array_length(to_jsonb(pa.allowed_principal_federated_identities) - ($1)::text[]) = 2 then concat(
          title,
          ' trust policy grants access to ',
          jsonb_array_length(to_jsonb(pa.allowed_principal_federated_identities) - ($1)::text[]),
          ' untrusted identity providers: [',
          to_jsonb(pa.allowed_principal_federated_identities) - ($1)::text[] ->> 0,
          ',',
          to_jsonb(pa.allowed_principal_federated_identities) - ($1)::text[] ->> 1,
          '].'
        )
        else concat(
          title,
          ' trust policy grants access to ',
          jsonb_array_length(to_jsonb(pa.allowed_principal_federated_identities) - ($1)::text[]),
          ' untrusted identity providers: [',
          to_jsonb(pa.allowed_principal_federated_identities) - ($1)::text[] ->> 0,
          ',',
          to_jsonb(pa.allowed_principal_federated_identities) - ($1)::text[] ->> 1,
          ',..].'
        )
      end as reason,
      __DIMENSIONS__
    from
      __TABLE_NAME__ as r,
      aws_resource_policy_analysis as pa
    where
      pa.account_id = r.account_id
      __CRITERIA__
    group by
      resource,
      title,
      pa.is_public,
      pa.allowed_principal_federated_identities,
      pa.access_level,
      __DIMENSIONS__
  EOT
}

locals {
  resource_policy_shared_identity_providers_sql_account = replace(replace(local.resource_policy_shared_identity_providers_sql, "__DIMENSIONS__", "r.account_id"), "__CRITERIA__", "and pa.policy = r.assume_role_policy_std")
  resource_policy_shared_identity_providers_sql_region  = replace(replace(local.resource_policy_shared_identity_providers_sql, "__DIMENSIONS__", "r.region, r.account_id"), "__CRITERIA__", "and pa.policy = r.policy_std")
  resource_policy_shared_identity_providers_sql_kms     = replace(replace(local.resource_policy_shared_identity_providers_sql, "__DIMENSIONS__", "r.region, r.account_id"), "__CRITERIA__", "and pa.policy = r.policy_std and key_manager = 'CUSTOMER'")
}

benchmark "resource_policy_shared_identity_providers_access" {
  title         = "Resource Policy Shared Indentity Providers Access"
  description   = "Resources should not be accessible to untrusted identity providers through statements in their resource policies."
  documentation = file("./perimeter/docs/resource_policy_shared_identity_providers_access.md")
  children = [
    control.ecr_repository_policy_prohibits_untrusted_identity_providers_access,
    control.glacier_vault_policy_prohibits_untrusted_identity_providers_access,
    control.iam_role_trust_policy_prohibits_untrusted_identity_providers_access,
    control.kms_key_policy_prohibits_untrusted_identity_providers_access,
    control.lambda_function_policy_prohibits_untrusted_identity_providers_access,
    control.s3_bucket_policy_prohibits_untrusted_identity_providers_access,
    control.sns_topic_policy_prohibits_untrusted_identity_providers_access,
    control.sqs_queue_policy_prohibits_untrusted_identity_providers_access
  ]

  tags = merge(local.aws_perimeter_common_tags, {
    type = "Benchmark"
  })
}

control "ecr_repository_policy_prohibits_untrusted_identity_providers_access" {
  title       = "ECR repository policies should prohibit access of untrusted identity providers"
  description = "Check if ECR repository policies allows access to untrusted services"
  sql         = replace(replace(local.resource_policy_shared_identity_providers_sql_region, "__TABLE_NAME__", "aws_ecr_repository"), "__ARN_COLUMN__", "arn")

  param "trusted_identity_providers" {
    description = "A list of trusted identity providers."
    default     = var.trusted_identity_providers
  }

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/ECR"
  })
}

control "glacier_vault_policy_prohibits_untrusted_identity_providers_access" {
  title       = "Glacier vault policies should prohibit access of untrusted identity providers"
  description = "Check if Glacier vault policies allows access to untrusted services"
  sql         = replace(replace(local.resource_policy_shared_identity_providers_sql_region, "__TABLE_NAME__", "aws_glacier_vault"), "__ARN_COLUMN__", "vault_arn")

  param "trusted_identity_providers" {
    description = "A list of trusted identity providers."
    default     = var.trusted_identity_providers
  }

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/Glacier"
  })
}

control "iam_role_trust_policy_prohibits_untrusted_identity_providers_access" {
  title       = "IAM role trust policies should prohibit access of untrusted identity providers"
  description = "Check if IAM role trust policies provide access to untrusted services, allowing untrusted services to assume the role."
  sql         = replace(replace(local.resource_policy_shared_identity_providers_sql_account, "__TABLE_NAME__", "aws_iam_role"), "__ARN_COLUMN__", "arn")

  param "trusted_identity_providers" {
    description = "A list of trusted identity providers."
    default     = var.trusted_identity_providers
  }

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/IAM"
  })
}

control "kms_key_policy_prohibits_untrusted_identity_providers_access" {
  title       = "KMS key policies should prohibit access of untrusted identity providers"
  description = "Check if KMS key policies allows access to untrusted services"
  sql         = replace(replace(replace(local.resource_policy_shared_identity_providers_sql_kms, "__TABLE_NAME__", "aws_kms_key"), "__ARN_COLUMN__", "arn"), "__CRITERIA__", "and key_manager = 'CUSTOMER'")

  param "trusted_identity_providers" {
    description = "A list of trusted identity providers."
    default     = var.trusted_identity_providers
  }

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/KMS"
  })
}

control "lambda_function_policy_prohibits_untrusted_identity_providers_access" {
  title       = "Lambda function policies should prohibit access of untrusted identity providers"
  description = "Check if Lambda function policies allows access to untrusted services"
  sql         = replace(replace(local.resource_policy_shared_identity_providers_sql_region, "__TABLE_NAME__", "aws_lambda_function"), "__ARN_COLUMN__", "arn")

  param "trusted_identity_providers" {
    description = "A list of trusted identity providers."
    default     = var.trusted_identity_providers
  }

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/Lambda"
  })
}

control "s3_bucket_policy_prohibits_untrusted_identity_providers_access" {
  title       = "S3 bucket policies should prohibit access of untrusted identity providers"
  description = "Check if S3 bucket policies allows access to untrusted services"
  sql         = replace(replace(local.resource_policy_shared_identity_providers_sql_region, "__TABLE_NAME__", "aws_s3_bucket"), "__ARN_COLUMN__", "arn")

  param "trusted_identity_providers" {
    description = "A list of trusted identity providers."
    default     = var.trusted_identity_providers
  }

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/S3"
  })
}

control "sns_topic_policy_prohibits_untrusted_identity_providers_access" {
  title       = "SNS topic policies should prohibit access of untrusted identity providers"
  description = "Check if SNS topic policies allows access to untrusted services"
  sql         = replace(replace(local.resource_policy_shared_identity_providers_sql_region, "__TABLE_NAME__", "aws_sns_topic"), "__ARN_COLUMN__", "topic_arn")

  param "trusted_identity_providers" {
    description = "A list of trusted identity providers."
    default     = var.trusted_identity_providers
  }

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/SNS"
  })
}

control "sqs_queue_policy_prohibits_untrusted_identity_providers_access" {
  title       = "SQS queue policies should prohibit access of untrusted identity providers"
  description = "Check if SQS queue policies allows access to untrusted services"
  sql         = replace(replace(local.resource_policy_shared_identity_providers_sql_region, "__TABLE_NAME__", "aws_sqs_queue"), "__ARN_COLUMN__", "queue_arn")

  param "trusted_identity_providers" {
    description = "A list of trusted identity providers."
    default     = var.trusted_identity_providers
  }

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/SQS"
  })
}

# control "omero_test" {
#   title       = "S3 bucket policies should prohibit untrusted account access"
#   description = "Check if S3 bucket policies allows access to untrusted accounts"
#   sql         = <<-EOT
#     select
#       r.arn as resource,
#       'ok' as status,
#       r.arn as reason,
#       case when true then '' || ((to_jsonb(pa.allowed_principal_account_ids) - ($1)::text[]) ->> 0)::text
#       else 'Nothing'
#       end as test
#       -- to_jsonb(pa.allowed_principal_account_ids) - ($1)::text[],
#       -- ($1)::text[] as test_array,
#       -- pa.allowed_principal_account_ids,
#       -- to_jsonb(pa.allowed_principal_account_ids) - ($1)::text[],
#       -- jsonb_array_length(to_jsonb(pa.allowed_principal_account_ids) - ($1)::text[]),
#       -- to_jsonb(pa.allowed_principal_account_ids) ->> 0,
#       -- to_jsonb(pa.allowed_principal_account_ids) - ($1)::text[]  #>> '{0}'
#     from
#       aws_s3_bucket as r,
#       aws_resource_policy_analysis as pa
#     where
#       pa.account_id = r.account_id
#       and pa.policy = r.policy_std
#     group by
#       resource,
#       title,
#       pa.is_public,
#       pa.allowed_principal_account_ids,
#       pa.access_level,
#       r.account_id
#   EOT

#   param "trusted_accounts" {
#     description = "A list of trusted accounts."
#     default     = var.trusted_accounts
#   }

#   tags = merge(local.aws_perimeter_common_tags, {
#     service = "AWS/S3"
#   })
# }
