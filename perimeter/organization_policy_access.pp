benchmark "organization_policy_access" {
  title         = "Organization Policy Access"
  description   = "Service control policies (SCPs) and resource control policies (RCPs) should set a consistent access perimeter for every member account, only trust known accounts and organizations, and be attached, unique and within AWS Organizations quotas."
  documentation = file("./perimeter/docs/organization_policy_access.md")
  children = [
    benchmark.organization_policy_baseline_access,
    benchmark.organization_policy_trusted_access,
    benchmark.organization_policy_configuration
  ]

  tags = merge(local.aws_perimeter_common_tags, {
    type = "Benchmark"
  })
}

benchmark "organization_policy_baseline_access" {
  title         = "Organization Policy Baseline Access"
  description   = "Every member account should inherit SCPs and RCPs that keep it in the organization, restrict the root user and regions, protect security and logging services from being disabled, and keep resources inside the organization's data perimeter."
  documentation = file("./perimeter/docs/organization_policy_baseline_access.md")
  children = [
    control.organizations_account_rcp_enforces_secure_transport,
    control.organizations_account_rcp_restricts_access_to_organization,
    control.organizations_account_scp_prohibits_access_analyzer_deletion,
    control.organizations_account_scp_prohibits_cloudtrail_disable,
    control.organizations_account_scp_prohibits_config_disable,
    control.organizations_account_scp_prohibits_guardduty_disable,
    control.organizations_account_scp_prohibits_leave_organization,
    control.organizations_account_scp_prohibits_s3_account_public_access_block_change,
    control.organizations_account_scp_prohibits_security_hub_disable,
    control.organizations_account_scp_restricts_regions,
    control.organizations_account_scp_restricts_root_user
  ]

  tags = merge(local.aws_perimeter_common_tags, {
    type = "Benchmark"
  })
}

benchmark "organization_policy_trusted_access" {
  title         = "Organization Policy Trusted Access"
  description   = "Accounts and organizations named in SCPs and RCPs should be trusted, and SCP exemptions should name specific principals rather than whole accounts."
  documentation = file("./perimeter/docs/organization_policy_trusted_access.md")
  children = [
    control.organizations_policy_references_trusted_accounts,
    control.organizations_policy_references_trusted_organizations,
    control.organizations_scp_exemption_prohibit_whole_account
  ]

  tags = merge(local.aws_perimeter_common_tags, {
    type = "Benchmark"
  })
}

benchmark "organization_policy_configuration" {
  title         = "Organization Policy Configuration"
  description   = "SCPs, RCPs and declarative policies should be enabled, attached, unique, have an exemption path and stay within AWS Organizations quotas, so the access perimeter they define is the one that is actually in effect."
  documentation = file("./perimeter/docs/organization_policy_configuration.md")
  children = [
    control.organizations_policy_attached,
    control.organizations_policy_size_within_limit,
    control.organizations_policy_statement_not_duplicated,
    control.organizations_root_access_policy_types_enabled,
    control.organizations_scp_allow_list_not_overridden_by_full_access,
    control.organizations_scp_deny_statement_has_exemption,
    control.organizations_target_rcp_attachments_within_limit,
    control.organizations_target_scp_attachments_within_limit
  ]

  tags = merge(local.aws_perimeter_common_tags, {
    type = "Benchmark"
  })
}

control "organizations_account_scp_prohibits_leave_organization" {
  title       = "Member accounts should be prohibited from leaving the organization by an SCP"
  description = "An account that leaves the organization is no longer governed by its SCPs, RCPs or centralized security services. Check if an SCP attached to the root, a parent OU or the account itself denies organizations:LeaveOrganization."
  query       = query.organizations_account_scp_denies_actions

  args = {
    actions = ["organizations:LeaveOrganization"]
  }

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/Organizations"
  })
}

control "organizations_account_scp_prohibits_cloudtrail_disable" {
  title       = "Member accounts should be prohibited from stopping or deleting CloudTrail trails by an SCP"
  description = "Stopping or deleting a trail removes the audit record of activity in the account. Check if an SCP in effect for the account denies cloudtrail:StopLogging and cloudtrail:DeleteTrail."
  query       = query.organizations_account_scp_denies_actions

  args = {
    actions = ["cloudtrail:StopLogging", "cloudtrail:DeleteTrail"]
  }

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/Organizations"
  })
}

control "organizations_account_scp_prohibits_config_disable" {
  title       = "Member accounts should be prohibited from stopping or deleting the Config recorder by an SCP"
  description = "Stopping or deleting the AWS Config recorder removes the configuration history used to detect access changes. Check if an SCP in effect for the account denies config:StopConfigurationRecorder and config:DeleteConfigurationRecorder."
  query       = query.organizations_account_scp_denies_actions

  args = {
    actions = ["config:StopConfigurationRecorder", "config:DeleteConfigurationRecorder"]
  }

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/Organizations"
  })
}

control "organizations_account_scp_prohibits_guardduty_disable" {
  title       = "Member accounts should be prohibited from disabling GuardDuty by an SCP"
  description = "Deleting the GuardDuty detector or leaving the administrator account stops threat detection for the account. Check if an SCP in effect for the account denies guardduty:DeleteDetector and guardduty:DisassociateFromMasterAccount."
  query       = query.organizations_account_scp_denies_actions

  args = {
    actions = ["guardduty:DeleteDetector", "guardduty:DisassociateFromMasterAccount"]
  }

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/Organizations"
  })
}

control "organizations_account_scp_prohibits_security_hub_disable" {
  title       = "Member accounts should be prohibited from disabling Security Hub by an SCP"
  description = "Disabling Security Hub or leaving the administrator account removes the account from central findings. Check if an SCP in effect for the account denies securityhub:DisableSecurityHub and securityhub:DisassociateFromMasterAccount."
  query       = query.organizations_account_scp_denies_actions

  args = {
    actions = ["securityhub:DisableSecurityHub", "securityhub:DisassociateFromMasterAccount"]
  }

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/Organizations"
  })
}

control "organizations_account_scp_prohibits_access_analyzer_deletion" {
  title       = "Member accounts should be prohibited from deleting IAM Access Analyzer analyzers by an SCP"
  description = "IAM Access Analyzer reports resources shared outside the account or organization. Check if an SCP in effect for the account denies access-analyzer:DeleteAnalyzer."
  query       = query.organizations_account_scp_denies_actions

  args = {
    actions = ["access-analyzer:DeleteAnalyzer"]
  }

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/Organizations"
  })
}

control "organizations_account_scp_prohibits_s3_account_public_access_block_change" {
  title       = "Member accounts should be prohibited from changing the S3 account-level Block Public Access settings by an SCP"
  description = "The account-level S3 Block Public Access settings stop buckets in the account from being made public. Check if an SCP in effect for the account denies s3:PutAccountPublicAccessBlock and s3:DeleteAccountPublicAccessBlock."
  query       = query.organizations_account_scp_denies_actions

  args = {
    actions = ["s3:PutAccountPublicAccessBlock", "s3:DeleteAccountPublicAccessBlock"]
  }

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/Organizations"
  })
}

control "organizations_account_scp_restricts_root_user" {
  title       = "Member account root users should be restricted by an SCP"
  description = "Root user credentials have unrestricted access to the account and can't be limited by IAM policies. Check if an SCP in effect for the account denies all actions to principals matching arn:aws:iam::*:root."

  sql = <<-EOQ
    with management_account as (
      select distinct
        a.organization_master_account_id as id
      from
        aws_account as a
        join aws_organizations_root as r on r.account_id = a.account_id
    ),
    account_targets as (
      select a.id as member_id, r.id as target_id from aws_organizations_account as a join aws_organizations_root as r on r.account_id = a.account_id
      union all
      select a.id, ou.id from aws_organizations_account as a join aws_organizations_organizational_unit as p on p.id = a.parent_id join aws_organizations_organizational_unit as ou on ou.path @> p.path
      union all
      select a.id, a.id from aws_organizations_account as a
    ),
    targets as (
      select id from aws_organizations_root
      union all
      select id from aws_organizations_organizational_unit
      union all
      select id from aws_organizations_account
    ),
    attachments as materialized (
      select
        t.id as target_id,
        pt.id,
        pt.name,
        pt.content
      from
        targets as t
        join aws_organizations_policy_target as pt on pt.target_id = t.id and pt.type = 'SERVICE_CONTROL_POLICY'
    ),
    root_statements as (
      select
        t.member_id,
        pt.name as policy_name,
        s ->> 'Sid' as sid,
        -- Full when every action on every resource is denied and the only other conditions exempt principals.
        coalesce(s -> 'Action' @> '"*"', false)
        and coalesce(s -> 'Resource' @> '"*"', false)
        and not exists (
          select 1
          from jsonb_each(s -> 'Condition') as c(operator, keys), jsonb_object_keys(c.keys) as k
          where not (lower(k) = 'aws:principalarn' and c.operator !~* 'not')
            and not (c.operator ~* 'not' and lower(k) ~ '^aws:(principalarn|principaltag/|principalaccount|userid|principalorgid|principalorgpaths)')
        ) as is_full
      from
        account_targets as t
        join attachments as pt on pt.target_id = t.target_id
        cross join lateral jsonb_array_elements(case jsonb_typeof(pt.content -> 'Statement') when 'array' then pt.content -> 'Statement' else jsonb_build_array(pt.content -> 'Statement') end) as s
      where
        s ->> 'Effect' = 'Deny'
        and exists (
          select 1
          from jsonb_each(s -> 'Condition') as c(operator, keys), jsonb_each(c.keys) as k(key, value),
            jsonb_array_elements_text(case jsonb_typeof(k.value) when 'array' then k.value else jsonb_build_array(k.value) end) as v
          where c.operator !~* 'not' and c.operator ~* '^(arn|string)' and lower(k.key) = 'aws:principalarn' and v ~ ':root$'
        )
    ),
    account_root_restrictions as (
      select
        member_id,
        bool_or(is_full) as is_full,
        string_agg(distinct policy_name, ', ') as policies
      from
        root_statements
      group by
        member_id
    )
    select
      a.arn as resource,
      case
        when a.id in (select id from management_account) then 'skip'
        when r.is_full then 'ok'
        when r.member_id is not null then 'info'
        else 'alarm'
      end as status,
      case
        when a.id in (select id from management_account) then a.name || ' is the management account, SCPs do not apply.'
        when r.is_full then a.name || ' root user is denied all actions by ' || r.policies || '.'
        when r.member_id is not null then a.name || ' root user is only denied some actions by ' || r.policies || '.'
        else a.name || ' root user is not restricted by an SCP.'
      end as reason
      ${replace(local.tag_dimensions_qualifier_sql, "__QUALIFIER__", "a.")}
      ${replace(local.common_dimensions_qualifier_sql, "__QUALIFIER__", "a.")}
    from
      aws_organizations_account as a
      left join account_root_restrictions as r on r.member_id = a.id;
  EOQ

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/Organizations"
  })
}

control "organizations_account_scp_restricts_regions" {
  title       = "Member accounts should be restricted to approved regions by an SCP"
  description = "Restricting regions limits where resources can be created and where data can be stored. Check if an SCP in effect for the account denies requests outside a list of regions (aws:RequestedRegion), and report the regions that remain allowed when several region restrictions apply."

  sql = <<-EOQ
    with management_account as (
      select distinct
        a.organization_master_account_id as id
      from
        aws_account as a
        join aws_organizations_root as r on r.account_id = a.account_id
    ),
    account_targets as (
      select a.id as member_id, r.id as target_id from aws_organizations_account as a join aws_organizations_root as r on r.account_id = a.account_id
      union all
      select a.id, ou.id from aws_organizations_account as a join aws_organizations_organizational_unit as p on p.id = a.parent_id join aws_organizations_organizational_unit as ou on ou.path @> p.path
      union all
      select a.id, a.id from aws_organizations_account as a
    ),
    targets as (
      select id from aws_organizations_root
      union all
      select id from aws_organizations_organizational_unit
      union all
      select id from aws_organizations_account
    ),
    attachments as materialized (
      select
        t.id as target_id,
        pt.id,
        pt.name,
        pt.content
      from
        targets as t
        join aws_organizations_policy_target as pt on pt.target_id = t.id and pt.type = 'SERVICE_CONTROL_POLICY'
    ),
    region_statements as (
      select
        t.member_id,
        pt.name as policy_name,
        pt.id || ':' || ordinality as statement_id,
        k.value as regions
      from
        account_targets as t
        join attachments as pt on pt.target_id = t.target_id
        cross join lateral jsonb_array_elements(case jsonb_typeof(pt.content -> 'Statement') when 'array' then pt.content -> 'Statement' else jsonb_build_array(pt.content -> 'Statement') end) with ordinality as s(statement, ordinality)
        cross join lateral jsonb_each(s.statement -> 'Condition') as c(operator, keys)
        cross join lateral jsonb_each(c.keys) as k(key, value)
      where
        s.statement ->> 'Effect' = 'Deny'
        and c.operator ~* '^string(not)(equals|like)'
        and lower(k.key) = 'aws:requestedregion'
    ),
    region_values as (
      select
        member_id,
        statement_id,
        v as region
      from
        region_statements,
        jsonb_array_elements_text(case jsonb_typeof(regions) when 'array' then regions else jsonb_build_array(regions) end) as v
    ),
    -- An action is only allowed in a region that every region restriction allows.
    allowed_regions as (
      select
        member_id,
        string_agg(region, ', ' order by region) as regions
      from (
        select
          member_id,
          region,
          count(distinct statement_id) as statements
        from
          region_values
        group by
          member_id,
          region
      ) as r
      where
        statements = (select count(distinct statement_id) from region_statements as rs where rs.member_id = r.member_id)
      group by
        member_id
    ),
    account_region_restrictions as (
      select
        member_id,
        string_agg(distinct policy_name, ', ') as policies,
        count(distinct statement_id) as statements
      from
        region_statements
      group by
        member_id
    )
    select
      a.arn as resource,
      case
        when a.id in (select id from management_account) then 'skip'
        when r.member_id is null then 'alarm'
        else 'ok'
      end as status,
      case
        when a.id in (select id from management_account) then a.name || ' is the management account, SCPs do not apply.'
        when r.member_id is null then a.name || ' is not restricted to approved regions by an SCP.'
        else a.name || ' is restricted to ' || coalesce(ar.regions, 'no regions') || ' by ' || r.policies || '.'
      end as reason
      ${replace(local.tag_dimensions_qualifier_sql, "__QUALIFIER__", "a.")}
      ${replace(local.common_dimensions_qualifier_sql, "__QUALIFIER__", "a.")}
    from
      aws_organizations_account as a
      left join account_region_restrictions as r on r.member_id = a.id
      left join allowed_regions as ar on ar.member_id = a.id;
  EOQ

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/Organizations"
  })
}

control "organizations_account_rcp_restricts_access_to_organization" {
  title       = "Member account resources should only be accessible from the organization by an RCP"
  description = "A data perimeter RCP denies access to resources by principals outside the organization, even if a resource policy grants it. Check if an RCP in effect for the account denies access unless aws:PrincipalOrgID (or aws:PrincipalAccount) matches, and report the services it covers."
  query       = query.organizations_account_rcp_denies_with_condition

  args = {
    condition_operator = "^string(not)(equals|like)"
    condition_keys     = ["aws:principalorgid", "aws:principalorgpaths", "aws:principalaccount"]
    condition_label    = "access from outside the organization"
  }

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/Organizations"
  })
}

control "organizations_account_rcp_enforces_secure_transport" {
  title       = "Member account resources should only be accessible over TLS by an RCP"
  description = "An RCP that denies requests where aws:SecureTransport is false enforces encryption in transit for every resource of the covered services. Check if an RCP in effect for the account denies insecure transport, and report the services it covers."
  query       = query.organizations_account_rcp_denies_with_condition

  args = {
    condition_operator = "^bool"
    condition_keys     = ["aws:securetransport"]
    condition_label    = "requests without TLS"
  }

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/Organizations"
  })
}

control "organizations_policy_references_trusted_accounts" {
  title       = "SCPs and RCPs should only reference trusted accounts"
  description = "Account IDs in SCP and RCP conditions and resources should belong to the organization or be trusted. An unknown account in an exemption is a stale or copied exception, and in a positive match it makes the statement never apply."

  sql = <<-EOQ
    with member_accounts as (
      select id from aws_organizations_account
    ),
    policies as (
      select arn, name, type, content, region, account_id from aws_organizations_policy where type = 'SERVICE_CONTROL_POLICY' and not aws_managed
      union all
      select arn, name, type, content, region, account_id from aws_organizations_policy where type = 'RESOURCE_CONTROL_POLICY' and not aws_managed
    ),
    account_references as (
      select distinct
        p.arn,
        (regexp_matches(p.content::text, '(?:arn:aws[a-z-]*:[a-z0-9-]*:[a-z0-9-]*:|")([0-9]{12})[:/"]', 'g'))[1] as referenced_account
      from
        policies as p
    ),
    untrusted_references as (
      select
        arn,
        string_agg(referenced_account, ', ' order by referenced_account) as accounts
      from
        account_references
      where
        referenced_account not in (select id from member_accounts)
        and not referenced_account = any (($1)::text[])
      group by
        arn
    )
    select
      p.arn as resource,
      case
        when u.arn is null then 'ok'
        else 'alarm'
      end as status,
      case
        when u.arn is null then p.name || ' only references trusted accounts.'
        else p.name || ' references untrusted accounts ' || u.accounts || '.'
      end as reason
      ${replace(local.common_dimensions_qualifier_sql, "__QUALIFIER__", "p.")}
    from
      policies as p
      left join untrusted_references as u on u.arn = p.arn;
  EOQ

  param "trusted_accounts" {
    description = "A list of trusted accounts."
    default     = var.trusted_accounts
  }

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/Organizations"
  })
}

control "organizations_policy_references_trusted_organizations" {
  title       = "SCPs and RCPs should only reference trusted organizations"
  description = "Organization IDs in SCP and RCP conditions, such as aws:PrincipalOrgID and aws:ResourceOrgID, should be this organization or a trusted one. A policy copied from another organization can lock out your own principals or trust the wrong organization."

  sql = <<-EOQ
    with organization as (
      select distinct
        a.organization_id as id
      from
        aws_account as a
        join aws_organizations_root as r on r.account_id = a.account_id
    ),
    policies as (
      select arn, name, type, content, region, account_id from aws_organizations_policy where type = 'SERVICE_CONTROL_POLICY' and not aws_managed
      union all
      select arn, name, type, content, region, account_id from aws_organizations_policy where type = 'RESOURCE_CONTROL_POLICY' and not aws_managed
    ),
    organization_references as (
      select distinct
        p.arn,
        (regexp_matches(p.content::text, '"(o-[a-z0-9]{10,32})[/"]', 'g'))[1] as referenced_organization
      from
        policies as p
    ),
    untrusted_references as (
      select
        arn,
        string_agg(referenced_organization, ', ' order by referenced_organization) as organizations
      from
        organization_references
      where
        referenced_organization not in (select id from organization)
        and not referenced_organization = any (($1)::text[])
      group by
        arn
    )
    select
      p.arn as resource,
      case
        when u.arn is null then 'ok'
        else 'alarm'
      end as status,
      case
        when u.arn is null then p.name || ' only references trusted organizations.'
        else p.name || ' references untrusted organizations ' || u.organizations || '.'
      end as reason
      ${replace(local.common_dimensions_qualifier_sql, "__QUALIFIER__", "p.")}
    from
      policies as p
      left join untrusted_references as u on u.arn = p.arn;
  EOQ

  param "trusted_organizations" {
    description = "A list of trusted organizations."
    default     = var.trusted_organizations
  }

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/Organizations"
  })
}

control "organizations_scp_exemption_prohibit_whole_account" {
  title       = "SCP exemptions should not exempt whole accounts or all roles"
  description = "An SCP exemption (ArnNotLike or StringNotEquals on aws:PrincipalArn or aws:PrincipalAccount) should name specific break-glass or automation principals. Exempting every principal in an account, or every role, turns the statement off for that scope."

  sql = <<-EOQ
    with broad_exemptions as (
      select
        p.arn,
        string_agg(distinct coalesce(s.statement ->> 'Sid', 'statement ' || s.ordinality) || ' (' || v || ')', ', ') as exemptions
      from
        aws_organizations_policy as p
        cross join lateral jsonb_array_elements(case jsonb_typeof(p.content -> 'Statement') when 'array' then p.content -> 'Statement' else jsonb_build_array(p.content -> 'Statement') end) with ordinality as s(statement, ordinality)
        cross join lateral jsonb_each(s.statement -> 'Condition') as c(operator, keys)
        cross join lateral jsonb_each(c.keys) as k(key, value)
        cross join lateral jsonb_array_elements_text(case jsonb_typeof(k.value) when 'array' then k.value else jsonb_build_array(k.value) end) as v
      where
        p.type = 'SERVICE_CONTROL_POLICY'
        and not p.aws_managed
        and s.statement ->> 'Effect' = 'Deny'
        and c.operator ~* 'not'
        and (
          lower(k.key) = 'aws:principalaccount'
          or (lower(k.key) = 'aws:principalarn' and v ~* '^arn:[^:]*:iam::[^:]*:(\*|role/\*|user/\*)$')
        )
      group by
        p.arn
    )
    select
      p.arn as resource,
      case
        when b.arn is null then 'ok'
        else 'alarm'
      end as status,
      case
        when b.arn is null then p.name || ' does not exempt whole accounts or all roles.'
        else p.name || ' exempts whole accounts or all roles in ' || b.exemptions || '.'
      end as reason
      ${replace(local.common_dimensions_qualifier_sql, "__QUALIFIER__", "p.")}
    from
      aws_organizations_policy as p
      left join broad_exemptions as b on b.arn = p.arn
    where
      p.type = 'SERVICE_CONTROL_POLICY'
      and not p.aws_managed;
  EOQ

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/Organizations"
  })
}

control "organizations_policy_attached" {
  title       = "SCPs, RCPs and declarative policies should be attached to at least one target"
  description = "A policy that isn't attached to the root, an OU or an account enforces nothing. Unattached policies are often drafts or copies that drift from the policies in effect. Check if each customer managed SCP, RCP and EC2 declarative policy is attached."

  sql = <<-EOQ
    with policies as (
      select arn, id, name, region, account_id from aws_organizations_policy where type = 'SERVICE_CONTROL_POLICY' and not aws_managed
      union all
      select arn, id, name, region, account_id from aws_organizations_policy where type = 'RESOURCE_CONTROL_POLICY' and not aws_managed
      union all
      select arn, id, name, region, account_id from aws_organizations_policy where type = 'DECLARATIVE_POLICY_EC2' and not aws_managed
    ),
    targets as (
      select id from aws_organizations_root
      union all
      select id from aws_organizations_organizational_unit
      union all
      select id from aws_organizations_account
    ),
    attached_policies as (
      select pt.id from targets as t join aws_organizations_policy_target as pt on pt.target_id = t.id and pt.type = 'SERVICE_CONTROL_POLICY'
      union
      select pt.id from targets as t join aws_organizations_policy_target as pt on pt.target_id = t.id and pt.type = 'RESOURCE_CONTROL_POLICY'
      union
      select pt.id from targets as t join aws_organizations_policy_target as pt on pt.target_id = t.id and pt.type = 'DECLARATIVE_POLICY_EC2'
    )
    select
      p.arn as resource,
      case
        when a.id is null then 'alarm'
        else 'ok'
      end as status,
      case
        when a.id is null then p.name || ' is not attached to any root, OU or account.'
        else p.name || ' is attached.'
      end as reason
      ${replace(local.common_dimensions_qualifier_sql, "__QUALIFIER__", "p.")}
    from
      policies as p
      left join attached_policies as a on a.id = p.id;
  EOQ

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/Organizations"
  })
}

control "organizations_policy_size_within_limit" {
  title       = "SCPs, RCPs and declarative policies should use less than 80% of the policy size limit"
  description = "AWS Organizations limits SCPs to 10,240 characters, RCPs to 5,120 and declarative policies to 10,000. A policy close to the limit can't take new statements. Size is estimated from the policy document without whitespace, as saved by the console."

  sql = <<-EOQ
    with policies as (
      select arn, name, content, 10240 as size_limit, region, account_id from aws_organizations_policy where type = 'SERVICE_CONTROL_POLICY' and not aws_managed
      union all
      select arn, name, content, 5120 as size_limit, region, account_id from aws_organizations_policy where type = 'RESOURCE_CONTROL_POLICY' and not aws_managed
      union all
      select arn, name, content, 10000 as size_limit, region, account_id from aws_organizations_policy where type = 'DECLARATIVE_POLICY_EC2' and not aws_managed
    ),
    policy_sizes as (
      select
        arn,
        name,
        size_limit,
        length(regexp_replace(content::text, '([,:]) ', '\1', 'g')) as size,
        region,
        account_id
      from
        policies
    )
    select
      arn as resource,
      case
        when size >= 0.95 * size_limit then 'alarm'
        when size >= 0.8 * size_limit then 'info'
        else 'ok'
      end as status,
      name || ' uses ' || size || ' of ' || size_limit || ' characters (' || round(100.0 * size / size_limit) || '%).' as reason
      ${local.common_dimensions_sql}
    from
      policy_sizes;
  EOQ

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/Organizations"
  })
}

control "organizations_policy_statement_not_duplicated" {
  title       = "SCP and RCP statements should not be duplicated across policies"
  description = "A statement repeated in several policies, or a whole policy copied under another name, uses up size and attachment quota and drifts when only one copy is edited. Statements are compared without their Sid, with actions and resources sorted and lower-cased. Copies between Control Tower managed policies (aws-guardrails-*) are ignored."

  sql = <<-EOQ
    with policies as (
      select arn, name, type, content, region, account_id from aws_organizations_policy where type = 'SERVICE_CONTROL_POLICY' and not aws_managed
      union all
      select arn, name, type, content, region, account_id from aws_organizations_policy where type = 'RESOURCE_CONTROL_POLICY' and not aws_managed
    ),
    statements as (
      select
        p.arn,
        p.name,
        p.type,
        coalesce(s.statement ->> 'Sid', 'statement ' || s.ordinality) as sid,
        s.ordinality,
        (s.statement - 'Sid' - 'Action' - 'NotAction' - 'Resource' - 'NotResource') || coalesce((
          select
            jsonb_object_agg(k, (
              select jsonb_agg(lower(x) order by lower(x))
              from jsonb_array_elements_text(case jsonb_typeof(s.statement -> k) when 'array' then s.statement -> k else jsonb_build_array(s.statement -> k) end) as x
            ))
          from
            unnest(array['Action', 'NotAction', 'Resource', 'NotResource']) as k
          where
            s.statement ? k
        ), '{}') as normalized_statement
      from
        policies as p
        cross join lateral jsonb_array_elements(case jsonb_typeof(p.content -> 'Statement') when 'array' then p.content -> 'Statement' else jsonb_build_array(p.content -> 'Statement') end) with ordinality as s(statement, ordinality)
    ),
    duplicates as (
      select
        a.arn,
        string_agg(distinct a.sid || ' (also in ' || b.name || ')', ', ') as statements
      from
        statements as a
        join statements as b on b.type = a.type and b.normalized_statement = a.normalized_statement and (b.arn, b.ordinality) <> (a.arn, a.ordinality)
      where
        -- Control Tower creates a copy of its SCP statements for each OU it governs.
        not (a.name like 'aws-guardrails-%' and b.name like 'aws-guardrails-%')
      group by
        a.arn
    )
    select
      p.arn as resource,
      case
        when d.arn is null then 'ok'
        else 'alarm'
      end as status,
      case
        when d.arn is null then p.name || ' has no duplicated statements.'
        else p.name || ' has duplicated statements ' || d.statements || '.'
      end as reason
      ${replace(local.common_dimensions_qualifier_sql, "__QUALIFIER__", "p.")}
    from
      policies as p
      left join duplicates as d on d.arn = p.arn;
  EOQ

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/Organizations"
  })
}

control "organizations_root_access_policy_types_enabled" {
  title       = "Organization roots should have SCPs and RCPs enabled"
  description = "SCPs set the maximum permissions for principals in member accounts, and RCPs set the maximum permissions on their resources. Neither has any effect until the policy type is enabled on the root."

  sql = <<-EOQ
    with enabled_types as (
      select
        r.arn,
        array_agg(pt ->> 'Type') filter (where pt ->> 'Status' = 'ENABLED') as types
      from
        aws_organizations_root as r
        left join lateral jsonb_array_elements(r.policy_types) as pt on true
      group by
        r.arn
    )
    select
      r.arn as resource,
      case
        when 'SERVICE_CONTROL_POLICY' = any(coalesce(e.types, '{}')) and 'RESOURCE_CONTROL_POLICY' = any(coalesce(e.types, '{}')) then 'ok'
        else 'alarm'
      end as status,
      case
        when 'SERVICE_CONTROL_POLICY' = any(coalesce(e.types, '{}')) and 'RESOURCE_CONTROL_POLICY' = any(coalesce(e.types, '{}')) then r.title || ' has SCPs and RCPs enabled.'
        when 'SERVICE_CONTROL_POLICY' = any(coalesce(e.types, '{}')) then r.title || ' has RCPs disabled.'
        when 'RESOURCE_CONTROL_POLICY' = any(coalesce(e.types, '{}')) then r.title || ' has SCPs disabled.'
        else r.title || ' has SCPs and RCPs disabled.'
      end as reason
      ${replace(local.common_dimensions_qualifier_sql, "__QUALIFIER__", "r.")}
    from
      aws_organizations_root as r
      left join enabled_types as e on e.arn = r.arn;
  EOQ

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/Organizations"
  })
}

control "organizations_scp_allow_list_not_overridden_by_full_access" {
  title       = "SCP allow lists should not be overridden by FullAWSAccess on the same target"
  description = "SCP Allow statements attached to the same root, OU or account are combined. A custom allow list of services has no effect when FullAWSAccess is also attached to the same target."

  sql = <<-EOQ
    with targets as (
      select arn, id, title, region, account_id from aws_organizations_root
      union all
      select arn, id, title, region, account_id from aws_organizations_organizational_unit
      union all
      select arn, id, title, region, account_id from aws_organizations_account
    ),
    target_policies as (
      select
        t.arn,
        bool_or(pt.id = 'p-FullAWSAccess') as has_full_access,
        string_agg(pt.name, ', ' order by pt.name) filter (
          where pt.id <> 'p-FullAWSAccess'
          and exists (
            select 1
            from jsonb_array_elements(case jsonb_typeof(pt.content -> 'Statement') when 'array' then pt.content -> 'Statement' else jsonb_build_array(pt.content -> 'Statement') end) as s
            where s ->> 'Effect' = 'Allow'
          )
        ) as allow_lists
      from
        targets as t
        join aws_organizations_policy_target as pt on pt.target_id = t.id and pt.type = 'SERVICE_CONTROL_POLICY'
      group by
        t.arn
    )
    select
      t.arn as resource,
      case
        when p.has_full_access and p.allow_lists is not null then 'alarm'
        else 'ok'
      end as status,
      case
        when p.has_full_access and p.allow_lists is not null then t.title || ' allow list ' || p.allow_lists || ' is overridden by FullAWSAccess.'
        when p.allow_lists is not null then t.title || ' allow list ' || p.allow_lists || ' is in effect.'
        else t.title || ' has no custom SCP allow list.'
      end as reason
      ${replace(local.common_dimensions_qualifier_sql, "__QUALIFIER__", "t.")}
    from
      targets as t
      left join target_policies as p on p.arn = t.arn;
  EOQ

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/Organizations"
  })
}

control "organizations_scp_deny_statement_has_exemption" {
  title       = "Attached SCP deny statements should exempt a break-glass principal"
  description = "A deny statement without a principal exemption (ArnNotLike or StringNotEquals on aws:PrincipalArn, aws:PrincipalTag or similar) can only be bypassed by detaching the policy from the management account. Some denies, such as leaving the organization, have no exemption by design, so this control reports info rather than alarm."

  sql = <<-EOQ
    with targets as (
      select id from aws_organizations_root
      union all
      select id from aws_organizations_organizational_unit
      union all
      select id from aws_organizations_account
    ),
    attached_policies as (
      select distinct
        pt.arn,
        pt.name,
        pt.content,
        pt.region,
        pt.account_id
      from
        targets as t
        join aws_organizations_policy_target as pt on pt.target_id = t.id and pt.type = 'SERVICE_CONTROL_POLICY'
      where
        not pt.aws_managed
    ),
    statements_without_exemption as (
      select
        p.arn,
        string_agg(coalesce(s.statement ->> 'Sid', 'statement ' || s.ordinality), ', ' order by s.ordinality) as statements
      from
        attached_policies as p
        cross join lateral jsonb_array_elements(case jsonb_typeof(p.content -> 'Statement') when 'array' then p.content -> 'Statement' else jsonb_build_array(p.content -> 'Statement') end) with ordinality as s(statement, ordinality)
      where
        s.statement ->> 'Effect' = 'Deny'
        and not exists (
          select 1
          from jsonb_each(s.statement -> 'Condition') as c(operator, keys), jsonb_object_keys(c.keys) as k
          where c.operator ~* 'not' and lower(k) ~ '^aws:(principalarn|principaltag/|principalaccount|userid|principalorgpaths)'
        )
      group by
        p.arn
    )
    select
      p.arn as resource,
      case
        when e.arn is null then 'ok'
        else 'info'
      end as status,
      case
        when e.arn is null then p.name || ' deny statements exempt a principal.'
        else p.name || ' deny statements without a principal exemption: ' || e.statements || '.'
      end as reason
      ${replace(local.common_dimensions_qualifier_sql, "__QUALIFIER__", "p.")}
    from
      attached_policies as p
      left join statements_without_exemption as e on e.arn = p.arn;
  EOQ

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/Organizations"
  })
}

control "organizations_target_scp_attachments_within_limit" {
  title       = "Roots, OUs and accounts should use less than 80% of the SCP attachment limit"
  description = "AWS Organizations allows up to 10 SCPs to be attached directly to a root, OU or account. A target at the limit can't take another SCP, and a full set of attachments is often a sign of overlapping policies that should be combined."
  query       = query.organizations_target_policy_attachments_within_limit

  args = {
    policy_type      = "SERVICE_CONTROL_POLICY"
    policy_label     = "SCPs"
    attachment_limit = 10
  }

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/Organizations"
  })
}

control "organizations_target_rcp_attachments_within_limit" {
  title       = "Roots, OUs and accounts should use less than 80% of the RCP attachment limit"
  description = "AWS Organizations allows up to 5 RCPs to be attached directly to a root, OU or account, including RCPFullAWSAccess, which can't be detached."
  query       = query.organizations_target_policy_attachments_within_limit

  args = {
    policy_type      = "RESOURCE_CONTROL_POLICY"
    policy_label     = "RCPs"
    attachment_limit = 5
  }

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/Organizations"
  })
}

query "organizations_account_scp_denies_actions" {
  sql = <<-EOQ
    with management_account as (
      select distinct
        a.organization_master_account_id as id
      from
        aws_account as a
        join aws_organizations_root as r on r.account_id = a.account_id
    ),
    -- SCPs in effect for an account are attached to the root, to each OU on its path, or to the account.
    account_targets as (
      select a.id as member_id, r.id as target_id from aws_organizations_account as a join aws_organizations_root as r on r.account_id = a.account_id
      union all
      select a.id, ou.id from aws_organizations_account as a join aws_organizations_organizational_unit as p on p.id = a.parent_id join aws_organizations_organizational_unit as ou on ou.path @> p.path
      union all
      select a.id, a.id from aws_organizations_account as a
    ),
    targets as (
      select id from aws_organizations_root
      union all
      select id from aws_organizations_organizational_unit
      union all
      select id from aws_organizations_account
    ),
    attachments as materialized (
      select
        t.id as target_id,
        pt.id,
        pt.name,
        pt.content
      from
        targets as t
        join aws_organizations_policy_target as pt on pt.target_id = t.id and pt.type = 'SERVICE_CONTROL_POLICY'
    ),
    deny_statements as (
      select
        t.member_id,
        pt.name as policy_name,
        s as statement,
        case jsonb_typeof(s -> 'Action') when 'array' then s -> 'Action' when 'string' then jsonb_build_array(s -> 'Action') end as actions,
        case jsonb_typeof(s -> 'NotAction') when 'array' then s -> 'NotAction' when 'string' then jsonb_build_array(s -> 'NotAction') end as not_actions
      from
        account_targets as t
        join attachments as pt on pt.target_id = t.target_id
        cross join lateral jsonb_array_elements(case jsonb_typeof(pt.content -> 'Statement') when 'array' then pt.content -> 'Statement' else jsonb_build_array(pt.content -> 'Statement') end) as s
      where
        s ->> 'Effect' = 'Deny'
    ),
    action_coverage as (
      select
        d.member_id,
        want.action,
        d.policy_name,
        -- Full: all resources, and any conditions only exempt principals.
        coalesce(d.statement -> 'Resource' @> '"*"', false)
        and not exists (
          select 1
          from jsonb_each(d.statement -> 'Condition') as c(operator, keys), jsonb_object_keys(c.keys) as k
          where not (c.operator ~* 'not' and lower(k) ~ '^aws:(principalarn|principaltag/|principalaccount|userid|principalorgid|principalorgpaths)')
            and not (c.operator ~* '^bool' and lower(k) in ('aws:principalisawsservice', 'aws:viaawsservice'))
        ) as is_full,
        -- Partial: the statement names the action (not just "*" or NotAction), but is scoped by resource or condition.
        coalesce(d.actions is not null and not d.actions @> '"*"', false) as is_named
      from
        deny_statements as d,
        unnest(($1)::text[]) as want(action)
      where
        case
          when d.actions is not null then exists (
            select 1 from jsonb_array_elements_text(d.actions) as a
            where lower(want.action) like replace(replace(lower(a), '*', '%'), '?', '_')
          )
          when d.not_actions is not null then not exists (
            select 1 from jsonb_array_elements_text(d.not_actions) as a
            where lower(want.action) like replace(replace(lower(a), '*', '%'), '?', '_')
          )
          else false
        end
    ),
    account_actions as (
      select
        a.id as member_id,
        want.action,
        bool_or(c.is_full) as is_full,
        bool_or(c.is_full or c.is_named) as is_partial,
        string_agg(distinct c.policy_name, ', ') filter (where c.is_full or c.is_named) as policies
      from
        aws_organizations_account as a
        cross join unnest(($1)::text[]) as want(action)
        left join action_coverage as c on c.member_id = a.id and c.action = want.action
      group by
        a.id,
        want.action
    ),
    account_summary as (
      select
        member_id,
        bool_and(coalesce(is_full, false)) as all_full,
        string_agg(action, ', ' order by action) filter (where not coalesce(is_partial, false)) as missing_actions,
        string_agg(action, ', ' order by action) filter (where coalesce(is_partial, false) and not coalesce(is_full, false)) as partial_actions,
        string_agg(distinct policies, ', ') as policies,
        string_agg(distinct policies, ', ') filter (where coalesce(is_partial, false) and not coalesce(is_full, false)) as partial_policies
      from
        account_actions
      group by
        member_id
    )
    select
      a.arn as resource,
      case
        when a.id in (select id from management_account) then 'skip'
        when s.all_full then 'ok'
        when s.missing_actions is null then 'info'
        else 'alarm'
      end as status,
      case
        when a.id in (select id from management_account) then a.name || ' is the management account, SCPs do not apply.'
        when s.all_full then a.name || ' denies ' || array_to_string(($1)::text[], ', ') || ' by ' || s.policies || '.'
        when s.missing_actions is null then a.name || ' only denies ' || s.partial_actions || ' for some resources or conditions by ' || s.partial_policies || '.'
        else a.name || ' does not deny ' || s.missing_actions || ' by an SCP.'
      end as reason
      ${replace(local.tag_dimensions_qualifier_sql, "__QUALIFIER__", "a.")}
      ${replace(local.common_dimensions_qualifier_sql, "__QUALIFIER__", "a.")}
    from
      aws_organizations_account as a
      left join account_summary as s on s.member_id = a.id;
  EOQ

  param "actions" {
    description = "The actions that an SCP in effect for each member account should deny."
  }
}

query "organizations_account_rcp_denies_with_condition" {
  sql = <<-EOQ
    with management_account as (
      select distinct
        a.organization_master_account_id as id
      from
        aws_account as a
        join aws_organizations_root as r on r.account_id = a.account_id
    ),
    -- RCPs in effect for an account are attached to the root, to each OU on its path, or to the account.
    account_targets as (
      select a.id as member_id, r.id as target_id from aws_organizations_account as a join aws_organizations_root as r on r.account_id = a.account_id
      union all
      select a.id, ou.id from aws_organizations_account as a join aws_organizations_organizational_unit as p on p.id = a.parent_id join aws_organizations_organizational_unit as ou on ou.path @> p.path
      union all
      select a.id, a.id from aws_organizations_account as a
    ),
    targets as (
      select id from aws_organizations_root
      union all
      select id from aws_organizations_organizational_unit
      union all
      select id from aws_organizations_account
    ),
    attachments as materialized (
      select
        t.id as target_id,
        pt.id,
        pt.name,
        pt.content
      from
        targets as t
        join aws_organizations_policy_target as pt on pt.target_id = t.id and pt.type = 'RESOURCE_CONTROL_POLICY'
    ),
    matching_statements as (
      select
        t.member_id,
        pt.name as policy_name,
        case jsonb_typeof(s -> 'Action') when 'array' then s -> 'Action' when 'string' then jsonb_build_array(s -> 'Action') end as actions
      from
        account_targets as t
        join attachments as pt on pt.target_id = t.target_id
        cross join lateral jsonb_array_elements(case jsonb_typeof(pt.content -> 'Statement') when 'array' then pt.content -> 'Statement' else jsonb_build_array(pt.content -> 'Statement') end) as s
      where
        s ->> 'Effect' = 'Deny'
        and exists (
          select 1
          from jsonb_each(s -> 'Condition') as c(operator, keys), jsonb_object_keys(c.keys) as k
          where c.operator ~* $1 and lower(k) = any (($2)::text[])
        )
    ),
    account_rcps as (
      select
        m.member_id,
        string_agg(distinct m.policy_name, ', ') as policies,
        string_agg(distinct split_part(a, ':', 1), ', ') as services
      from
        matching_statements as m
        left join lateral jsonb_array_elements_text(m.actions) as a on true
      group by
        m.member_id
    )
    select
      a.arn as resource,
      case
        when a.id in (select id from management_account) then 'skip'
        when r.member_id is null then 'alarm'
        else 'ok'
      end as status,
      case
        when a.id in (select id from management_account) then a.name || ' is the management account, RCPs do not apply.'
        when r.member_id is null then a.name || ' does not deny ' || $3 || ' by an RCP.'
        else a.name || ' denies ' || $3 || ' for ' || coalesce(r.services, 'all services') || ' by ' || r.policies || '.'
      end as reason
      ${replace(local.tag_dimensions_qualifier_sql, "__QUALIFIER__", "a.")}
      ${replace(local.common_dimensions_qualifier_sql, "__QUALIFIER__", "a.")}
    from
      aws_organizations_account as a
      left join account_rcps as r on r.member_id = a.id;
  EOQ

  param "condition_operator" {
    description = "A regular expression for the condition operator, e.g. ^bool."
  }

  param "condition_keys" {
    description = "The lower-case condition keys that identify a matching RCP deny statement."
  }

  param "condition_label" {
    description = "A description of what the matching RCP denies, used in the reason."
  }
}

query "organizations_target_policy_attachments_within_limit" {
  sql = <<-EOQ
    with targets as (
      select arn, id, title, region, account_id from aws_organizations_root
      union all
      select arn, id, title, region, account_id from aws_organizations_organizational_unit
      union all
      select arn, id, title, region, account_id from aws_organizations_account
    ),
    attachment_counts as (
      select
        t.arn,
        count(pt.id) as attachments
      from
        targets as t
        left join aws_organizations_policy_target as pt on pt.target_id = t.id and pt.type = $1
      group by
        t.arn
    )
    select
      t.arn as resource,
      case
        when c.attachments >= $3 then 'alarm'
        when c.attachments >= 0.8 * $3 then 'info'
        else 'ok'
      end as status,
      t.title || ' has ' || c.attachments || ' of ' || $3 || ' ' || $2 || ' attached.' as reason
      ${replace(local.common_dimensions_qualifier_sql, "__QUALIFIER__", "t.")}
    from
      targets as t
      join attachment_counts as c on c.arn = t.arn;
  EOQ

  param "policy_type" {
    description = "The policy type, e.g. SERVICE_CONTROL_POLICY."
  }

  param "policy_label" {
    description = "A short name for the policy type, used in the reason."
  }

  param "attachment_limit" {
    description = "The maximum number of policies of the type that can be attached to a target."
  }
}
