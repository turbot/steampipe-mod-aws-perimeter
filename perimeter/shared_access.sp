variable "trusted_accounts" {
  type        = list(string)
  default     = ["123456781234", "123456781200"]
  description = "A list of AWS accounts trusted for sharing resources."
}

variable "trusted_organizations" {
  type        = list(string)
  default     = ["o-abcdhqk8mns", "o-efghqk8pab"]
  description = "A list of AWS organizations trusted for sharing resources."
}

variable "trusted_organization_units" {
  type        = list(string)
  default     = ["ou-abcdek7fks"]
  description = "A list of AWS organizations units trusted for sharing resources."
}

benchmark "shared_access" {
  title         = "Shared Access"
  description   = "The AWS Shared Access is a set of controls that detect if your deployed accounts and resources are shared for use by principals outside of the AWS account that created the resource. Sharing doesn't change any permissions or quotas that apply to the resource in the account that created it. Shared resources can be achived by AWS Resource Access Manager (RAM) or through sharing APIs or through resource-based policies."
  documentation = file("./perimeter/docs/shared_access.md")
  children = [
    benchmark.ram_shared_access,
    benchmark.shared_access_settings
  ]

  tags = merge(local.aws_perimeter_common_tags, {
    type = "Benchmark"
  })
}

benchmark "ram_shared_access" {
  title         = "RAM Shared Access"
  description   = "AWS Resource Access Manager (RAM) helps you securely share the AWS resources that you create in one AWS account with other AWS accounts. If you have multiple AWS accounts, you can create a resource once and use AWS RAM to make that resource usable by those other accounts."
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
  description = "AWS Resource Access Manager (RAM) helps you securely share your resources across AWS accounts, within your organization or organizational units (OUs) in AWS Organizations, and with IAM roles and IAM users for supported resource types. Check if you share resources with an account that is part of the trusted list of accounts or your organization. AWS RAM initiates an invitation process, the recipient must accept the invitation before that principal can access the shared resources. Sharing within an organization doesn't require an invitation."

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
        string_to_array(string_agg(shared_with_principal, ','), ',', '') as shared_with_accounts,
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
    description = "Trusted Accounts"
    default     = var.trusted_accounts
  }

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/RAM"
  })
}

control "ram_resource_shared_with_trusted_organizations" {
  title       = "Resources shared through RAM should only be shared with trusted organizations"
  description = "AWS Resource Access Manager (RAM) helps you securely share your resources across AWS accounts, within your organization or organizational units (OUs) in AWS Organizations, and with IAM roles and IAM users for supported resource types. Check if you share resources with an account that is part of the trusted list of accounts or your organization. AWS RAM initiates an invitation process, the recipient must accept the invitation before that principal can access the shared resources. Sharing within an organization doesn't require an invitation."

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
        string_to_array(string_agg(shared_with_organization, ','), ',', '') as shared_with_organization,
        to_jsonb(string_to_array(string_agg(split_part(shared_with_organization, '/', 2), ','), ',', '')) - ($1)::text[] as untrusted_organization,
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
        when jsonb_array_length(untrusted_organization) > 0 then 'alarm'
        else 'ok'
      end as status,
      case
        when jsonb_array_length(untrusted_organization) > 0 then
          resource ||
          case
            when jsonb_array_length(untrusted_organization) > 2 then
              concat(' shared with untrusted organizations ', untrusted_organization #>> '{0}', ', ', untrusted_organization #>> '{1}', ' and ', (jsonb_array_length(untrusted_organization) - 2)::text, ' more.')
            when jsonb_array_length(untrusted_organization) = 2 then concat(' shared with untrusted organizations ', untrusted_organization #>> '{0}', ' and ', untrusted_organization #>> '{1}', '.')
            else concat(' shared with untrusted organization ', untrusted_organization #>> '{0}', '.')
          end
        else resource || ' shared with trusted organizationt(s).'
      end as reason,
      region,
      account_id
    from
      shared_data;
  EOT

  param "trusted_organizations" {
    description = "Trusted Organizations"
    default     = var.trusted_organizations
  }

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/RAM"
  })
}

control "ram_resource_shared_with_trusted_organization_units" {
  title       = "Resources shared through RAM should only be shared with trusted OUs"
  description = "AWS Resource Access Manager (RAM) helps you securely share your resources across AWS accounts, within your organization or organizational units (OUs) in AWS Organizations, and with IAM roles and IAM users for supported resource types. Check if you share resources with an account that is part of the trusted list of accounts or your organization. AWS RAM initiates an invitation process, the recipient must accept the invitation before that principal can access the shared resources. Sharing within an organization doesn't require an invitation."

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
        string_to_array(string_agg(shared_with_organization_unit, ','), ',', '') as shared_with_organization_unit,
        to_jsonb(string_to_array(string_agg(split_part(shared_with_organization_unit, '/', 3), ','), ',', '')) - ($1)::text[] as untrusted_organization_unit,
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
        when jsonb_array_length(untrusted_organization_unit) > 0 then 'alarm'
        else 'ok'
      end as status,
      case
        when jsonb_array_length(untrusted_organization_unit) > 0 then
          resource ||
          case
            when jsonb_array_length(untrusted_organization_unit) > 2 then
              concat( ' shared with untrusted OUs ' ,untrusted_organization_unit #>> '{0}', ', ', untrusted_organization_unit #>> '{1}', ' and ', (jsonb_array_length(untrusted_organization_unit) - 2)::text, ' more.')
            when jsonb_array_length(untrusted_organization_unit) = 2 then concat(' shared with untrusted OUs ', untrusted_organization_unit #>> '{0}', ', ', untrusted_organization_unit #>> '{1}', '.')
            else concat(' shared with untrusted OU ', untrusted_organization_unit #>> '{0}', '.')
          end
        else resource || ' shared with trusted OU(s).'
      end as reason,
      region,
      account_id
    from
      shared_data;
  EOT

  param "trusted_organization_units" {
    description = "Trusted Organization Units"
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
    description = "Trusted Accounts"
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
        to_jsonb(string_to_array(string_agg(sd ->> 'SharedAccountId', ','), ',')) as shared_with_accounts,
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
        shared_with_accounts,
        untrusted_accounts
      from
        all_directories
        left join directory_data on all_directories.directory_id = directory_data.directory_id
    )
    select
      directory_id as resource,
      case
        when shared_with_accounts is null or jsonb_array_length(shared_with_accounts) = 0 then 'ok'
        when untrusted_accounts is not null or jsonb_array_length(untrusted_accounts) > 0 then 'info'
        else 'ok'
      end as status,
      case
        when shared_with_accounts is null or jsonb_array_length(shared_with_accounts) = 0 then directory_id || ' not shared.'
        when untrusted_accounts is not null or jsonb_array_length(shared_with_accounts) > 0 then directory_id || ' shared with ' ||
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
    description = "Trusted Accounts"
    default     = var.trusted_accounts
  }

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/DirectoryService"
  })
}

control "dlm_ebs_snapshot_policy_shared_with_trusted_accounts" {
  title       = "DLM policies should only share EBS snapshot copies with trusted accounts"
  description = "Automating cross-account snapshot copies enables you to copy your Amazon EBS snapshots to specific regions in an isolated account and encrypt those snapshots with an encryption key. This enables you to protect yourself against data loss in the event of your account being compromised. This control checks if the cross-acccount sharing."

  sql = <<-EOT
    with dlm_policy_shared_snapshot_copies as (
      select
        policy_id,
        policy_type,
        state,
        -- A DLM policy can have at most 4 schedules, we need to verify each schedule if snapshots, through it will be shared to external accounts
        (policy_details #> '{Schedules,0,ShareRules,0,TargetAccounts}')::jsonb - ($1)::text[] as schedule_0_shared_with_accounts,
        (policy_details #> '{Schedules,1,ShareRules,0,TargetAccounts}')::jsonb - ($1)::text[] as schedule_1_shared_with_accounts,
        (policy_details #> '{Schedules,2,ShareRules,0,TargetAccounts}')::jsonb - ($1)::text[] as schedule_2_shared_with_accounts,
        (policy_details #> '{Schedules,3,ShareRules,0,TargetAccounts}')::jsonb - ($1)::text[] as schedule_3_shared_with_accounts,
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
        when jsonb_array_length(schedule_0_shared_with_accounts) > 0
        or jsonb_array_length(schedule_1_shared_with_accounts) > 0
        or jsonb_array_length(schedule_2_shared_with_accounts) > 0
        or jsonb_array_length(schedule_3_shared_with_accounts) > 0 then 'info'
      else 'ok'
      end as status,
      case
        when state = 'DISABLED' then policy_id || ' policy disabled.'
        when jsonb_array_length(schedule_0_shared_with_accounts) > 0 then
          policy_id || ' creates EBS snapshots and shares with ' ||
          case
            when jsonb_array_length(schedule_0_shared_with_accounts) > 2 then
              concat(schedule_0_shared_with_accounts #>> '{0}', ', ', schedule_0_shared_with_accounts #>> '{1}', ' and ', (jsonb_array_length(schedule_0_shared_with_accounts) - 2)::text, ' more untrusted account(s).')
            when jsonb_array_length(schedule_0_shared_with_accounts) = 2 then
              concat(schedule_0_shared_with_accounts #>> '{0}', ', ', schedule_0_shared_with_accounts #>> '{1}', ' untrusted accounts.')
            else concat(schedule_0_shared_with_accounts #>> '{0}', ' untrusted account.')
          end
        when jsonb_array_length(schedule_1_shared_with_accounts) > 0 then
          policy_id || ' creates EBS snapshots and shares with ' ||
          case
            when jsonb_array_length(schedule_1_shared_with_accounts) > 2 then
              concat('untrusted accounts ', schedule_1_shared_with_accounts #>> '{0}', ', ', schedule_1_shared_with_accounts #>> '{1}', ' and ', (jsonb_array_length(schedule_1_shared_with_accounts) - 2)::text, ' more.')
            when jsonb_array_length(schedule_1_shared_with_accounts) = 2 then
              concat('untrusted accounts ', schedule_1_shared_with_accounts #>> '{0}', ' and ', schedule_1_shared_with_accounts #>> '{1}', '.')
            else concat('untrusted account ', schedule_1_shared_with_accounts #>> '{0}', '.')
          end

        when jsonb_array_length(schedule_2_shared_with_accounts) > 0 then
          policy_id || ' creates EBS snapshots and shares with ' ||
          case
            when jsonb_array_length(schedule_2_shared_with_accounts) > 2 then
              concat('untrusted accounts ', schedule_2_shared_with_accounts #>> '{0}', ', ', schedule_2_shared_with_accounts #>> '{1}', ' and ', (jsonb_array_length(schedule_2_shared_with_accounts) - 2)::text, ' more.')
            when jsonb_array_length(schedule_2_shared_with_accounts) = 2 then
              concat('untrusted accounts ', schedule_2_shared_with_accounts #>> '{0}', ' and ', schedule_2_shared_with_accounts #>> '{1}', '.')
            else concat('untrusted account ', schedule_2_shared_with_accounts #>> '{0}', '.')
          end

        when jsonb_array_length(schedule_3_shared_with_accounts) > 0 then
          policy_id || ' creates EBS snapshots and shares with ' ||
          case
            when jsonb_array_length(schedule_3_shared_with_accounts) > 2 then
              concat('untrusted accounts ', schedule_3_shared_with_accounts #>> '{0}', ', ', schedule_3_shared_with_accounts #>> '{1}', ' and ', (jsonb_array_length(schedule_3_shared_with_accounts) - 2)::text, ' more.')
            when jsonb_array_length(schedule_3_shared_with_accounts) = 2 then
              concat('untrusted accounts ', schedule_3_shared_with_accounts #>> '{0}', ' and ', schedule_3_shared_with_accounts #>> '{1}', '.')
            else concat('untrusted account ', schedule_3_shared_with_accounts #>> '{0}', '.')
          end
        else policy_id || ' does not create any EBS snapshot shared with untrusted account(s).'
      end as reason,
      region,
      account_id
    from
      dlm_policy_shared_snapshot_copies;
  EOT

  param "trusted_accounts" {
    description = "Trusted Accounts"
    default     = var.trusted_accounts
  }

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/EBS"
  })
}

control "ec2_ami_shared_with_trusted_accounts" {
  title       = "EC2 AMIs should only be shared with trusted accounts"
  description = "AWS AMIs can be shared with specific AWS accounts without making the AMI public."

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
        to_jsonb(string_to_array(string_agg(lp ->> 'UserId', ','), ',')) as shared_account,
        to_jsonb(string_to_array(string_agg(lp ->> 'UserId', ','), ',')) - ($1)::text[] as shared_with_account,
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
        shared_with_account,
        shared_account
      from
        all_amis left join ami_data on all_amis.account_id = ami_data.account_id and all_amis.region = ami_data.region and all_amis.title = ami_data.title
    )
    select
      title as resource,
      case
        when public then 'info'
        when shared_account is null then 'ok'
        when shared_with_account is not null then 'info'
        else 'ok'
      end as status,
      case
        when public then title || ' is public.'
        when shared_account is null then title || ' is not shared.'
        when shared_with_account is not null then title ||
          case
            when jsonb_array_length(shared_with_account) > 2
            then concat(' shared with untrusted accounts ', shared_with_account #>> '{0}', ', ', shared_with_account #>> '{1}', ' and ' || (jsonb_array_length(shared_with_account) - 2)::text || ' more.' )
            when jsonb_array_length(shared_with_account) = 2
            then concat(' shared with untrusted accounts ', shared_with_account #>> '{0}', ' and ', shared_with_account #>> '{1}', '.')
            else concat(' shared with untrusted account ', shared_with_account #>> '{0}', '.')
          end
        else title || ' shared with trusted account(s).'
      end as reason,
        region,
        account_id
    from
      evaluated_amis;
  EOT

  param "trusted_accounts" {
    description = "Trusted Accounts"
    default     = var.trusted_accounts
  }

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/EC2"
  })
}

control "ec2_ami_shared_with_trusted_organizations" {
  title       = "EC2 AMIs should only be shared with trusted organizations"
  description = "AWS AMIs can be shared with specific AWS organizations without making the AMI public."

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
        to_jsonb(string_to_array(string_agg(split_part((lp ->> 'OrganizationArn'), '/', 2), ','), ',')) as shared_organization,
        to_jsonb(string_to_array(string_agg(split_part((lp ->> 'OrganizationArn'), '/', 2), ','), ',')) - ($1)::text[] as shared_with_organization,
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
        shared_with_organization,
        shared_organization
      from
        all_amis left join ami_data on all_amis.account_id = ami_data.account_id and all_amis.region = ami_data.region and all_amis.title = ami_data.title
    )
    select
      title as resource,
      case
        when public then 'info'
        when shared_organization is null then 'ok'
        when shared_with_organization is not null then 'info'
        else 'ok'
      end as status,
      case
        when public then title || ' is public.'
        when shared_organization is null then title || ' is not shared.'
        when shared_with_organization is not null then title || ' shared with ' ||
          case
            when jsonb_array_length(shared_with_organization) > 2
            then concat('untrusted organizations ', shared_with_organization #>> '{0}', ', ', shared_with_organization #>> '{1}', ' and ' || (jsonb_array_length(shared_with_organization) - 2)::text || ' more.' )
            when jsonb_array_length(shared_with_organization) = 2
            then concat('untrusted organizations ', shared_with_organization #>> '{0}', ' and ', shared_with_organization #>> '{1}', '.')
            else concat('untrusted organization ', shared_with_organization #>> '{0}', '.')
          end
        else title || ' shared with trusted organization(s).'
        end as reason,
        region,
        account_id
    from
      evaluated_amis;
  EOT

  param "trusted_organizations" {
    description = "Trusted Organizations"
    default     = var.trusted_organizations
  }

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/EC2"
  })
}

control "ec2_ami_shared_with_trusted_organization_units" {
  title       = "EC2 AMIs should only be shared with trusted OUs"
  description = "AWS AMIs can be shared with specific AWS organizations units without making the AMI public."

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
        to_jsonb(string_to_array(string_agg(split_part((lp ->> 'OrganizationalUnitArn'), '/', 3), ','), ',')) as shared_organizational_unit,
        to_jsonb(string_to_array(string_agg(split_part((lp ->> 'OrganizationalUnitArn'), '/', 3), ','), ',')) - ($1)::text[] as shared_with_organizational_unit,
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
        shared_organizational_unit,
        shared_with_organizational_unit
      from
        all_amis left join ami_data on all_amis.account_id = ami_data.account_id and all_amis.region = ami_data.region and all_amis.title = ami_data.title
    )
    select
      title as resource,
      case
        when public then 'info'
        when shared_organizational_unit is null then 'ok'
        when shared_with_organizational_unit is not null then 'info'
        else 'ok'
      end as status,
      case
        when public then title || ' is public.'
        when shared_organizational_unit is null then title || ' is not shared.'
        when shared_organizational_unit is not null then title || ' shared with ' ||
          case
            when jsonb_array_length(shared_with_organizational_unit) > 2
            then concat('untrusted OUs ', shared_with_organizational_unit #>> '{0}', ', ', shared_with_organizational_unit #>> '{1}', ' and ' || (jsonb_array_length(shared_with_organizational_unit) - 2)::text || ' more.' )
            when jsonb_array_length(shared_with_organizational_unit) = 2
            then concat('untrusted OUs ', shared_with_organizational_unit #>> '{0}', ' and ', shared_with_organizational_unit #>> '{1}', '.')
            else concat('untrusted OU ', shared_with_organizational_unit #>> '{0}', '.')
          end
        else title || ' shared with trusted OU(s).'
      end as reason,
      region,
      account_id
    from
      evaluated_amis;
  EOT

  param "trusted_organization_units" {
    description = "Trusted Organization Units"
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
          case when list is null then s.title || ' not shared.'
          else s.title || ' shared with trusted account(s).' end
      end reason,
      s.region,
      s.account_id
    from
      aws_ebs_snapshot as s left join shared_ebs_snapshot as ss on s.arn = ss.arn ;
  EOT

  param "trusted_accounts" {
    description = "Trusted Accounts"
    default     = var.trusted_accounts
  }

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/EBS"
  })
}

control "guarduty_findings_shared_with_trusted_accounts" {
  title       = "GuardDuty findings cross account configuration should be restricted to trusted accounts"
  description = "GuardDuty findings can be shared with administrator account, this control checks whether findings shared with trusted master account."

  sql = <<-EOT
    select
      title as resource,
      case when master_account ->> 'AccountId' is null or (master_account ->> 'AccountId')::text = any (($1)::text[]) then
        'ok'
      else
        'info'
      end as status,
      case when master_account ->> 'AccountId' is null or (master_account ->> 'AccountId')::text = any (($1)::text[]) then
        title || ' findings restricted with trusted administrator account.'
      else
        title || ' findings not restricted with trusted administrator account ' || (master_account ->> 'AccountId')::text || '.'
      end as reason,
      region,
      account_id
    from
      aws_guardduty_detector;
  EOT

  param "trusted_accounts" {
    description = "Trusted Accounts"
    default     = var.trusted_accounts
  }

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/GuardDuty"
  })
}

control "rds_db_snapshot_shared_with_trusted_accounts" {
  title       = "RDS DB snapshots should only be shared with trusted accounts"
  description = "This control checks whether Amazon RDS DB snapshots access is restricted to trusted accounts."

  sql = <<-EOT
    (with shared_cluster_snapshot_data as (
      select
        arn,
        title,
        (cluster_snapshot ->> 'AttributeValues')::jsonb as account_list,
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
            when account_list is null then title || ' not shared.'
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
        (database_snapshot ->> 'AttributeValues')::jsonb as account_list,
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
            when account_list is null then title || ' not shared.'
            else title || ' shared with trusted account(s).'
          end
      end reason,
      region,
      account_id
    from
      shared_db_snapshot_data);
  EOT

  param "trusted_accounts" {
    description = "Trusted Accounts"
    default     = var.trusted_accounts
  }

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/RDS"
  })
}


