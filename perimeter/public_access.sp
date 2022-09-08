benchmark "public_access" {
  title         = "Public Access"
  description   = "Resources should not be publicly accessible as they could expose sensitive data to bad actors."
  documentation = file("./perimeter/docs/public_access.md")
  children = [
    benchmark.public_access_settings,
    benchmark.resource_policy_public_access
  ]

  tags = merge(local.aws_perimeter_common_tags, {
    type = "Benchmark"
  })
}

benchmark "public_access_settings" {
  title         = "Public Access Settings"
  description   = "Resources should not be publicly accessible or exposed to the internet through configurations and settings."
  documentation = file("./perimeter/docs/public_access_settings.md")
  children = [
    control.api_gateway_rest_api_prohibit_public_access,
    control.dms_replication_instance_not_publicly_accessible,
    control.ebs_snapshot_not_publicly_accessible,
    control.ec2_instance_ami_prohibit_public_access,
    control.eks_cluster_endpoint_prohibit_public_access,
    control.rds_db_cluster_snapshot_prohibit_public_access,
    control.rds_db_instance_prohibit_public_access,
    control.rds_db_snapshot_prohibit_public_access,
    control.redshift_cluster_prohibit_public_access,
    control.s3_bucket_acl_prohibit_public_read_access,
    control.s3_bucket_acl_prohibit_public_write_access,
    control.s3_public_access_block_account,
    control.s3_public_access_block_bucket,
    control.sagemaker_notebook_instance_direct_internet_access_disabled
  ]

  tags = merge(local.aws_perimeter_common_tags, {
    type = "Benchmark"
  })
}

control "api_gateway_rest_api_prohibit_public_access" {
  title       = "API Gateway APIs should prohibit public access"
  description = "This control checks whether AWS API Gateway APIs are only accessible through private API endpoints and not visible to the public Internet. A private API can be accessed only privately through the interface VPC endpoint."

  sql = <<-EOT
    select
      title as resource,
      case
        when endpoint_configuration_types != '["PRIVATE"]' then 'alarm'
        else 'ok'
      end status,
      case
        when endpoint_configuration_types != '["PRIVATE"]' then title || ' endpoint publicly accessible.'
        else title || ' endpoint not publicly accessible.'
      end reason,
      region,
      account_id
    from
      aws_api_gateway_rest_api;
  EOT

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/APIGateway"
  })
}

control "dms_replication_instance_not_publicly_accessible" {
  title       = "Database Migration Service (DMS) replication instances should not be public"
  description = "This control checks whether AWS DMS replication instances are public. A private replication instance has a private IP address that you cannot access outside of the replication network. A replication instance should have a private IP address when the source and target databases are in the same network, and the network is connected to the replication instance's VPC using a VPN, AWS Direct Connect, or VPC peering."

  sql = <<-EOT
    select
      arn as resource,
      case
        when publicly_accessible then 'alarm'
        else 'ok'
      end status,
      case
        when publicly_accessible then title || ' publicly accessible.'
        else title || ' not publicly accessible.'
      end reason,
      region,
      account_id
    from
      aws_dms_replication_instance;
  EOT

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/DMS"
  })
}

control "ebs_snapshot_not_publicly_accessible" {
  title       = "EBS snapshots should not be publicly restorable"
  description = "This control checks whether EBS snapshots are publicly restorable by everyone, which makes them public. EBS snapshots should not be publicly restorable by everyone unless you explicitly allow it, to avoid accidental exposure of your company’s sensitive data."

  sql = <<-EOT
    select
      'arn:' || partition || ':ec2:' || region || ':' || account_id || ':snapshot/' || snapshot_id as resource,
      case
        when create_volume_permissions @> '[{"Group": "all", "UserId": null}]' then 'alarm'
        else 'ok'
      end status,
      case
        when create_volume_permissions @> '[{"Group": "all", "UserId": null}]' then title || ' publicly restorable.'
        else title || ' not publicly restorable.'
      end reason,
      region,
      '123456789012' as account_id
    from
      aws_ebs_snapshot;
  EOT

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/EBS"
  })
}

control "ec2_instance_ami_prohibit_public_access" {
  title       = "EC2 AMIs should not be shared publicly"
  description = "A shared AMI is an AMI that a developer created and made available for other developers to use within organisation or carefully shared to other accounts. If AMIs have embedded information about the environment, it could pose a security risk if shared publicly."

  sql = <<-EOT
    select
      title as resource,
      case when public then
        'alarm'
      else
        'ok'
      end as status,
      case
        when public then title || ' publicly accessible.'
        else title || ' not publicly accessible.'
      end as reason,
      region,
      '123456789012' as account_id
    from
      aws_ec2_ami;
  EOT

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/EC2"
  })
}

control "eks_cluster_endpoint_prohibit_public_access" {
  title       = "EKS cluster endpoints should prohibit public access"
  description = "Ensure that Elastic Kubernetes Service (EKS) endpoints are not publicly accessible."

  sql = <<-EOT
    select
      arn as resource,
      case
        when resources_vpc_config ->> 'EndpointPublicAccess' = 'true' then 'alarm'
        else 'ok'
      end as status,
      case
        when resources_vpc_config ->> 'EndpointPublicAccess' = 'true' then title || ' endpoint publicly accessible.'
        else title || ' endpoint not publicly accessible.'
      end as reason,
      region,
      account_id
    from
      aws_eks_cluster;
  EOT

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/EKS"
  })
}

control "rds_db_instance_prohibit_public_access" {
  title       = "RDS DB instances should prohibit public accesss"
  description = "Manage access to resources in the AWS Cloud by ensuring that RDS instances are not public."

  sql = <<-EOT
    select
      arn as resource,
      case
        when publicly_accessible then 'alarm'
        else 'ok'
      end status,
      case
        when publicly_accessible then title || ' publicly accessible.'
        else title || ' not publicly accessible.'
      end reason,
      region,
      account_id
    from
      aws_rds_db_instance;
  EOT

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/RDS"
  })
}
control "rds_db_cluster_snapshot_prohibit_public_access" {
  title       = "RDS DB cluster snapshots should not be publicly restorable"
  description = "This control checks whether RDS DB cluster snapshots prohibit access to other accounts. It is recommended that your RDS cluster snapshots should not be public in order to prevent potential leak or misuse of sensitive data or any other kind of security threat. If your RDS cluster snapshot is public; then the data which is backed up in that snapshot is accessible to all other AWS accounts."

  sql = <<-EOT
    select
      arn as resource,
      case
        when cluster_snapshot -> 'AttributeValues' = '["all"]' then 'alarm'
        else 'ok'
      end status,
      case
        when cluster_snapshot -> 'AttributeValues' = '["all"]' then title || ' publicly restorable.'
        else title || ' not publicly restorable.'
      end reason,
      region,
      account_id
    from
      aws_rds_db_cluster_snapshot,
      jsonb_array_elements(db_cluster_snapshot_attributes) as cluster_snapshot;
  EOT

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/RDS"
  })
}

control "rds_db_snapshot_prohibit_public_access" {
  title       = "RDS DB snapshots should not be publicly restorable"
  description = "This control checks whether RDS DB snapshots prohibit access to other accounts. It is recommended that your RDS snapshots should not be public in order to prevent potential leak or misuse of sensitive data or any other kind of security threat. If your RDS snapshot is public; then the data which is backed up in that snapshot is accessible to all other AWS accounts."

  sql = <<-EOT
    select
      arn as resource,
      case
        when database_snapshot -> 'AttributeValues' = '["all"]' then 'alarm'
        else 'ok'
      end status,
      case
        when database_snapshot -> 'AttributeValues' = '["all"]' then title || ' publicly restorable.'
        else title || ' not publicly restorable.'
      end reason,
      region,
      account_id
    from
      aws_rds_db_snapshot,
      jsonb_array_elements(db_snapshot_attributes) as database_snapshot;
  EOT

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/RDS"
  })
}

control "redshift_cluster_prohibit_public_access" {
  title       = "Redshift clusters should prohibit public access"
  description = "This control checks whether Redshift clusters are publicly accessible. It is recommended that your Redshift clusters should not be public in order to prevent potential leak or misuse of sensitive data or any other kind of security threat."

  sql = <<-EOT
    select
      cluster_namespace_arn as resource,
      case
        when publicly_accessible then 'alarm'
        else 'ok'
      end status,
      case
        when publicly_accessible then title || ' publicly accessible.'
        else title || ' not publicly accessible.'
      end reason,
      region,
      account_id
    from
      aws_redshift_cluster;
  EOT

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/Redshift"
  })
}

control "sagemaker_notebook_instance_direct_internet_access_disabled" {
  title       = "SageMaker notebook instances should be prohibited from direct internet access"
  description = "Access to internet could provide an avenue for unauthorized access to your data. Ensure that SageMaker notebook instances do not allow direct internet access."

  sql = <<-EOT
    select
      arn as resource,
      case
        when direct_internet_access = 'Enabled' then 'alarm'
        else 'ok'
      end status,
      case
        when direct_internet_access = 'Enabled' then title || ' instance has direct internet access enabled.'
        else title || ' instance has direct internet access disabled.'
      end reason,
      region,
      account_id
    from
      aws_sagemaker_notebook_instance;
  EOT

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/SageMaker"
  })
}

control "s3_public_access_block_account" {
  title       = "S3 account settings should block public access"
  description = "Ensure S3 buckets block public policy and ACL access at the account level."

  sql = <<-EOT
    select
      'arn' || ':' || 'aws' || ':::' || account_id as resource,
      case
        when block_public_acls
          and block_public_policy
          and ignore_public_acls
          and restrict_public_buckets
          then 'ok'
        else 'alarm'
      end as status,
      case
        when block_public_acls
          and block_public_policy
          and ignore_public_acls
          and restrict_public_buckets
          then 'Account level public access blocks enabled.'
        else 'Account level public access not enabled for: ' ||
          concat_ws(', ',
            case when not (block_public_acls ) then 'block_public_acls' end,
            case when not (block_public_policy) then 'block_public_policy' end,
            case when not (ignore_public_acls ) then 'ignore_public_acls' end,
            case when not (restrict_public_buckets) then 'restrict_public_buckets' end
          ) || '.'
      end as reason,
      account_id
    from
      aws_s3_account_settings;
  EOT

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/S3"
  })
}

control "s3_public_access_block_bucket" {
  title       = "S3 buckets should block public access at bucket level"
  description = "Ensure S3 buckets block public policy and ACL access at the bucket level."

  sql = <<-EOT
    select
      arn as resource,
      case
        when block_public_acls
          and block_public_policy
          and ignore_public_acls
          and restrict_public_buckets
          then 'ok'
        else 'alarm'
      end as status,
      case
        when block_public_acls
          and block_public_policy
          and ignore_public_acls
          and restrict_public_buckets
          then name || ' all public access blocks enabled.'
        else name || ' not enabled for: ' ||
          concat_ws(', ',
            case when not block_public_acls then 'block_public_acls' end,
            case when not block_public_policy then 'block_public_policy' end,
            case when not ignore_public_acls then 'ignore_public_acls' end,
            case when not restrict_public_buckets then 'restrict_public_buckets' end
          ) || '.'
      end as reason,
      region,
      account_id
    from
      aws_s3_bucket;

  EOT

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/S3"
  })
}

control "s3_bucket_acl_prohibit_public_read_access" {
  title       = "S3 bucket ACLs should prohibit public read access"
  description = "This control checks if S3 bucket ACLs allow public read access to objects in the bucket."

  sql = <<-EOT
    with data as (
      select
        distinct name
      from
        aws_s3_bucket,
        jsonb_array_elements(acl -> 'Grants') as grants
      where
        grants -> 'Grantee' ->> 'URI' = 'http://acs.amazonaws.com/groups/global/AllUsers'
        and (
          grants ->> 'Permission' = 'FULL_CONTROL'
          or grants ->> 'Permission' = 'READ_ACP'
        )
    )
    select
      b.arn as resource,
      case
        when d.name is null then 'ok'
        else 'alarm'
      end status,
      case
        when d.name is null then b.title || ' not publicly readable.'
        else b.title || ' publicly readable.'
      end reason,
      b.region,
      b.account_id
    from
      aws_s3_bucket as b
      left join data as d on b.name = d.name;
  EOT

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/S3"
  })
}

control "s3_bucket_acl_prohibit_public_write_access" {
  title       = "S3 bucket ACLs should prohibit public write access"
  description = "This control checks if S3 bucket ACLs allow public write access to objects in the bucket."

  sql = <<-EOT
    with data as (
      select
        distinct name
      from
        aws_s3_bucket,
        jsonb_array_elements(acl -> 'Grants') as grants
      where
        grants -> 'Grantee' ->> 'URI' = 'http://acs.amazonaws.com/groups/global/AllUsers'
        and (
          grants ->> 'Permission' = 'FULL_CONTROL'
          or grants ->> 'Permission' = 'WRITE_ACP'
        )
        )
    select
      b.arn as resource,
      case
        when d.name is null then 'ok'
        else 'alarm'
      end status,
      case
        when d.name is null then b.title || ' not publicly writable.'
        else b.title || ' publicly writable.'
      end reason,
      b.region,
      b.account_id
    from
      aws_s3_bucket as b
      left join data as d on b.name = d.name;
  EOT

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/S3"
  })
}

locals {
  resource_policy_public_sql = <<-EOT
    select
      r.__ARN_COLUMN__ as resource,
      case
        when pa.is_public = true then 'alarm'
        else 'ok'
      end as status,
      case
        when pa.is_public = false then title || ' policy does not allow public access.'
        when jsonb_array_length(pa.public_statement_ids) = 1 then concat(
          title,
          ' policy contains 1 statement that allow public access: [',
          pa.public_statement_ids ->> 0,
          '].'
        )
        when jsonb_array_length(pa.public_statement_ids) = 2 then concat(
          title,
          ' policy contains 2 statement that allow public access: [',
          pa.public_statement_ids ->> 0,
          ', ',
          pa.public_statement_ids ->> 1,
          '].'
        )
        else concat(
          title,
          ' policy contains ',
          jsonb_array_length(pa.public_statement_ids),
          ' statement that allow public access: [',
          pa.public_statement_ids ->> 0,
          ', ',
          pa.public_statement_ids ->> 1,
          ', and ',
          jsonb_array_length(pa.public_statement_ids) - 2,
          ' more].'
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
      pa.public_statement_ids,
      __DIMENSIONS__
  EOT
}

locals {
  resource_policy_public_sql_account = replace(replace(local.resource_policy_public_sql, "__DIMENSIONS__", "r.account_id"), "__CRITERIA__", "and pa.policy = r.assume_role_policy_std")
  resource_policy_public_sql_region  = replace(replace(local.resource_policy_public_sql, "__DIMENSIONS__", "r.region, r.account_id"), "__CRITERIA__", "and pa.policy = r.policy_std")
  resource_policy_public_sql_for_kms = replace(replace(local.resource_policy_public_sql, "__DIMENSIONS__", "r.region, r.account_id"), "__CRITERIA__", "and pa.policy = r.policy_std and key_manager = 'CUSTOMER'")
}

benchmark "resource_policy_public_access" {
  title         = "Resource Policy Public Access"
  description   = "Resources should not be publicly accessible through statements in their resource policies."
  documentation = file("./perimeter/docs/resource_policy_public_access.md")
  children = [
    control.ecr_repository_policy_prohibit_public_access,
    control.glacier_vault_policy_prohibit_public_access,
    control.iam_role_trust_policy_prohibit_public_access,
    control.kms_key_policy_prohibit_public_access,
    control.lambda_function_policy_prohibit_public_access,
    control.s3_bucket_policy_prohibit_public_access,
    control.sns_topic_policy_prohibit_public_access,
    control.sqs_queue_policy_prohibit_public_access
  ]

  tags = merge(local.aws_perimeter_common_tags, {
    type = "Benchmark"
  })
}

control "ecr_repository_policy_prohibit_public_access" {
  title       = "ECR repository policies should prohibit public access"
  description = "Check if ECR repository policies allow public access."
  sql         = replace(replace(local.resource_policy_public_sql_region, "__TABLE_NAME__", "aws_ecr_repository"), "__ARN_COLUMN__", "arn")

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/ECR"
  })
}

control "glacier_vault_policy_prohibit_public_access" {
  title       = "Glacier vault policies should prohibit public access"
  description = "Check if Glacier vault policies allow public access."
  sql         = replace(replace(local.resource_policy_public_sql_region, "__TABLE_NAME__", "aws_glacier_vault"), "__ARN_COLUMN__", "vault_arn")

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/Glacier"
  })
}

control "iam_role_trust_policy_prohibit_public_access" {
  title       = "IAM role trust policies should prohibit public access"
  description = "Check if IAM role trust policies provide public access, allowing any principal to assume the role."
  sql         = replace(replace(local.resource_policy_public_sql_account, "__TABLE_NAME__", "aws_iam_role"), "__ARN_COLUMN__", "arn")

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/IAM"
  })
}

control "kms_key_policy_prohibit_public_access" {
  title       = "KMS key policies should prohibit public access"
  description = "Check if KMS key policies allow public access."
  sql         = replace(replace(local.resource_policy_public_sql_for_kms, "__TABLE_NAME__", "aws_kms_key"), "__ARN_COLUMN__", "arn")

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/KMS"
  })
}

control "lambda_function_policy_prohibit_public_access" {
  title       = "Lambda function policies should prohibit public access"
  description = "Check if Lambda function policies allow public access."
  sql         = replace(replace(local.resource_policy_public_sql_region, "__TABLE_NAME__", "aws_lambda_function"), "__ARN_COLUMN__", "arn")

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/Lambda"
  })
}

control "s3_bucket_policy_prohibit_public_access" {
  title       = "S3 bucket policies should prohibit public access"
  description = "Check if S3 bucket policies allow public access."
  sql         = replace(replace(local.resource_policy_public_sql_region, "__TABLE_NAME__", "aws_s3_bucket"), "__ARN_COLUMN__", "arn")

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/S3"
  })
}

control "sns_topic_policy_prohibit_public_access" {
  title       = "SNS topic policies should prohibit public access"
  description = "Check if SNS topic policies allow public access."
  sql         = replace(replace(local.resource_policy_public_sql_region, "__TABLE_NAME__", "aws_sns_topic"), "__ARN_COLUMN__", "topic_arn")

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/SNS"
  })
}

control "sqs_queue_policy_prohibit_public_access" {
  title       = "SQS queue policies should prohibit public access"
  description = "Check if SQS queue policies allow public access."
  sql         = replace(replace(local.resource_policy_public_sql_region, "__TABLE_NAME__", "aws_sqs_queue"), "__ARN_COLUMN__", "queue_arn")

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/SQS"
  })
}
