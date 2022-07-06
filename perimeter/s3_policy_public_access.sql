select
  name,
  jsonb_pretty(policy) as policy
from
  aws_s3_bucket;

select
  jsonb_pretty(policy),
  is_public,
  access_level,
  allowed_organization_ids,
  allowed_principal_account_ids,
  allowed_principal_federated_identities,
  allowed_principal_services,
  allowed_principals,
  public_access_levels,
  public_statement_ids
from
  aws_resource_policy_analysis
where
  policy = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":["s3:GetBucketLocation","s3:ListBucket"],"Resource":"arn:aws:s3:::test"},{"Sid":"OrganizationAccess","Effect":"Allow","Principal":{"AWS":"*"},"Action":["s3:GetBucketLocation","s3:ListBucket"],"Resource":"arn:aws:s3:::test","Condition":{"StringEquals":{"aws:PrincipalOrgID":["o-123456"]}}},{"Sid":"AccountPrincipals","Effect":"Allow","Principal":{"AWS":["arn:aws:iam::123456789012:user/victor@xyz.com","arn:aws:iam::111122223333:root"]},"Action":["s3:GetBucketLocation","s3:ListBucket"],"Resource":"arn:aws:s3:::test"},{"Sid":"FederatedPrincipals","Effect":"Allow","Principal":{"Federated":"arn:aws:iam::111011101110:saml-provider/AWSSSO_DO_NOT_DELETE"},"Action":["s3:GetBucketLocation","s3:ListBucket"],"Resource":"arn:aws:s3:::test"},{"Sid":"ServicePrincipals","Effect":"Allow","Principal":{"Service":["ecs.amazonaws.com","elasticloadbalancing.amazonaws.com"]},"Action":["s3:GetBucketLocation","s3:ListBucket"],"Resource":"arn:aws:s3:::test"},{"Sid":"PublicAccess","Effect":"Allow","Principal":{"AWS":"*"},"Action":["s3:GetBucketLocation","s3:ListBucket"],"Resource":"arn:aws:s3:::test"}]}';

select
  jsonb_pretty(policy),
  is_public,
  access_level,
  allowed_organization_ids,
  allowed_principal_account_ids,
  allowed_principal_federated_identities,
  allowed_principal_services,
  allowed_principals,
  public_access_levels,
  public_statement_ids
from
  aws_resource_policy_analysis
where
  policy = '{"Statement":[{"Action":"s3:GetBucketAcl","Effect":"Allow","Principal":{"Service":"cloudtrail.amazonaws.com"},"Resource":"arn:aws:s3:::aws-cloudtrail-logs-111122223333-1247fc6c","Sid":"AWSCloudTrailAclCheck20150319"},{"Action":"s3:PutObject","Condition":{"StringEquals":{"AWS:SourceArn":"arn:aws:cloudtrail:ap-south-1:111122223333:trail/management-events","s3:x-amz-acl":"bucket-owner-full-control"}},"Effect":"Allow","Principal":{"Service":"cloudtrail.amazonaws.com"},"Resource":"arn:aws:s3:::aws-cloudtrail-logs-111122223333-1247fc6c/AWSLogs/111122223333/*","Sid":"AWSCloudTrailWrite20150319"},{"Action":"s3:PutObject","Condition":{"StringEquals":{"AWS:SourceArn":"arn:aws:cloudtrail:us-east-1:111122223333:trail/test-sd-pci","s3:x-amz-acl":"bucket-owner-full-control"}},"Effect":"Allow","Principal":{"Service":"cloudtrail.amazonaws.com"},"Resource":"arn:aws:s3:::aws-cloudtrail-logs-111122223333-1247fc6c/AWSLogs/111122223333/*","Sid":"AWSCloudTrailWrite20150319"}],"Version":"2012-10-17"}';

-- allowed_organization_ids,
-- allowed_principal_account_ids,
-- allowed_principal_federated_identities,
-- allowed_principal_services,
-- allowed_principals,
-- public_access_levels,
select
  s3.name as bucket,
  rpa.is_public,
  access_level,
  public_statement_ids
from
  _aws_s3_bucket as s3
  left join aws_resource_policy_analysis as rpa on s3.policy = rpa.policy;

select
  sb.name,
  rpa.is_public,
  access_level,
  public_statement_ids
from
  aws_jamal_ada.aws_s3_bucket as sb
  left join aws_resource_policy_analysis rpa on rpa.policy = sb.policy
  and rpa.account_id = sb.account_id
where
  sb.policy is not null;

-- +-----------------------+-----------+--------------+----------------------+
-- | name                  | is_public | access_level | public_statement_ids |
-- +-----------------------+-----------+--------------+----------------------+
-- | test-anonymous-access | false     | private      | <null>               |
-- +-----------------------+-----------+--------------+----------------------+
select
  sb.name,
  rpa.is_public,
  access_level,
  public_statement_ids
from
  aws_s3_bucket as sb
  left join aws_resource_policy_analysis rpa on rpa.policy = sb.policy
  and rpa.account_id = sb.account_id;

-- +-------------------------------------------+-----------+--------------+----------------------+
-- | name                                      | is_public | access_level | public_statement_ids |
-- +-------------------------------------------+-----------+--------------+----------------------+
-- | elasticbeanstalk-us-east-1-111122223333   | false     | private      | <null>               |
-- | test5666666                               | false     | private      | <null>               |
-- | aws-cloudtrail-logs-111122223333-1247fc6c | false     | private      | <null>               |
-- | aws-cloudtrail-logs-111122223333-28c5861b | false     | private      | <null>               |
-- | turbot-111122223333-ap-south-1            | false     | shared       | <null>               |
-- | turbot-111122223333-ap-southeast-1        | false     | shared       | <null>               |
-- | aws-cloudtrail-logs-111122223333-ffd9c689 | false     | private      | <null>               |
-- | aws-cloudtrail-logs-111122223333-d0709feb | false     | private      | <null>               |
-- | turbot-111122223333-eu-west-2             | false     | shared       | <null>               |
-- | config-bucket-111122223333                | false     | private      | <null>               |
-- | turbot-111122223333-ap-northeast-2        | false     | shared       | <null>               |
-- | turbot-111122223333-ap-southeast-2        | false     | shared       | <null>               |
-- | aws-cloudtrail-logs-111122223333-c03f999f | false     | private      | <null>               |
-- | turbot-111122223333-ap-northeast-1        | false     | shared       | <null>               |
-- | turbot-111122223333-eu-central-1          | false     | shared       | <null>               |
-- | turbot-111122223333-eu-west-3             | false     | shared       | <null>               |
-- | turbot-111122223333-ca-central-1          | false     | shared       | <null>               |
-- | aws-cloudtrail-logs-111122223333-4e174ee2 | false     | private      | <null>               |
-- | aws-logs-111122223333-us-east-1           | false     | private      | <null>               |
-- | turbot-111122223333-us-east-1             | false     | shared       | <null>               |
-- | aws-glue-scripts-111122223333-us-east-2   | false     | private      | <null>               |
-- | aws-cloudtrail-logs-111122223333-756cec4f | false     | private      | <null>               |
-- | elasticbeanstalk-us-east-2-111122223333   | false     | private      | <null>               |
-- | aws-logs-111122223333-us-east-2           | <null>    | <null>       | <null>               |
-- | osborn-shaktiman-bucket-share             | false     | shared       | <null>               |
-- | smyth-test-trusted-access                 | false     | private      | <null>               |
-- | sd-test-s3-bucket                         | false     | private      | <null>               |
-- | turbot-111122223333-us-west-1             | false     | shared       | <null>               |
-- | turbot-111122223333-eu-west-1             | false     | shared       | <null>               |
-- | turbot-111122223333-us-west-2             | false     | shared       | <null>               |
-- | turbot-111122223333-sa-east-1             | false     | shared       | <null>               |
-- | cf-templates-4kbzu7qn81qq-us-east-1       | <null>    | <null>       | <null>               |
-- | aws-cloudtrail-logs-111122223333-739b1d4b | false     | private      | <null>               |
-- | turbot-111122223333-eu-north-1            | false     | shared       | <null>               |
-- +-------------------------------------------+-----------+--------------+----------------------+
PREPARE aws_perimeter_s3_bucket_policy_prohibit_shared_access_c4048 AS (
  select
    r.arn as resource,
    case
      when a.access_level is not null
      and a.is_public then 'alarm'
      when a.access_level is not null
      and a.access_level = 'shared'
      and jsonb_array_length(allowed_principal_account_ids - ($ 1)::text[]) > 0 then 'alarm'
      else ' ok '
    end as status,
    case
      when a.access_level is null
      or not a.is_public then title || ' policy allows public access.'
      when a.access_level is not null
      and a.access_level = 'shared'
      and jsonb_array_length(allowed_principal_account_ids - ($1)::text[]) > 0 then title || ' policy allows sharing with ' || jsonb_array_length(allowed_principal_account_ids - ($1)::text[]) :: text || ' untrusted accounts.'
      else title || ' does not allow untrusted access.'
    end as reason,
    r.region,
    r.account_id
  from
    aws_s3_bucket as r
    left join aws_resource_policy_analysis as a on a.policy = r.policy
    and a.account_id = r.account_id
);

PREPARE aws_perimeter_s3_bucket_policy_prohibit_shared_access_c4048 AS (
  select
    r.arn as resource,
    case
      when a.access_level is not null
      and a.is_public then 'alarm'
      when a.access_level is not null
      and a.access_level = 'shared'
      and (
        jsonb_array_length(allowed_principal_account_ids - ($1)::text[]) > 0
        or jsonb_array_length(allowed_principal_services - ($2)::text[]) > 0
        or jsonb_array_length(allowed_organization_ids - ($3)::text[]) > 0
      ) then 'alarm'
      else ' ok '
    end as status,
    case
      when a.access_level is not null
      and a.is_public then title || ' policy allows public access.'
      when a.access_level is not null
      and a.access_level = 'shared'
      and (
        jsonb_array_length(allowed_principal_account_ids - ($1)::text[]) > 0
        or jsonb_array_length(allowed_principal_services - ($2)::text[]) > 0
        or jsonb_array_length(allowed_organization_ids - ($3)::text[]) > 0
      ) then title || ' policy allows sharing with ' || CONCAT_WS(
        ',',
        case
          when jsonb_array_length(allowed_principal_account_ids - ($1)::text[]) > 0 then ' ' jsonb_array_length(allowed_principal_account_ids - ($1)::text[]) :: text || ' untrusted account(s)'
        end,
        case
          when jsonb_array_length(allowed_principal_services - ($2)::text[]) > 0 then jsonb_array_length(allowed_principal_services - ($2)::text[]) :: text || ' untrusted service(s)'
        end,
        case
          when jsonb_array_length(allowed_organization_ids - ($3)::text[]) > 0 then jsonb_array_length(allowed_organization_ids - ($3)::text[]) :: text || ' untrusted organization(s)'
        end
      ) || '.'
      else title || ' does not allow untrusted access.'
    end as reason,
    -- ($1)::text[] as trusted_accounts,
    -- (allowed_principal_account_ids - ($1)::text[]) as untrusted_account,
    -- ($2)::text[] as trusted_services,
    -- (allowed_principal_services - ($2)::text[]) as untrusted_services,
    -- ($3)::text[] as trusted_orgs,
    -- (allowed_organization_ids - ($3)::text[]) as untrusted_orgs,
    -- a.access_level,
    -- a.is_public,
    r.region,
    r.account_id
  from
    aws_s3_bucket as r
    left join aws_resource_policy_analysis as a on a.policy = r.policy
    and a.account_id = r.account_id
  order by
    status
)