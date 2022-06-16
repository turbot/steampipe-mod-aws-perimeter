benchmark "public_access" {
  title         = "Public Access"
  description   = "Publicly accessible services could expose sensitive data to bad actors. The AWS Public Access is a set of controls that identifies resources that may be publicly accessible."
  documentation = file("./perimeter/docs/public_access.md")
  children = [
    benchmark.public_ips,
    benchmark.resource_config_public_access,
    benchmark.resource_policy_public_access
  ]

  tags = merge(local.aws_perimeter_common_tags, {
    type = "Benchmark"
  })
}

benchmark "public_ips" {
  title         = "Public IPs"
  description   = "The public IPs benchmark includes a set of controls that detect if your deployed resources have associated public IPs, which can expose the resources to direct access from internet."
  documentation = file("./perimeter/docs/public_ips.md")
  children = [
    control.autoscaling_launch_config_public_ip_disabled,
    control.ec2_instance_not_publicly_accessible,
    control.ec2_network_interface_not_publicly_accessible,
    control.ecs_service_not_publicly_accessible,
    control.emr_cluster_master_nodes_no_public_ip,
    control.vpc_subnet_auto_assign_public_ip_disabled
  ]

  tags = merge(local.aws_perimeter_common_tags, {
    type = "Benchmark"
  })
}

control "autoscaling_launch_config_public_ip_disabled" {
  title       = "Auto Scaling launch configs should not have a public IP address"
  description = "Ensure that Amazon EC2 Auto Scaling groups have public IP addresses enabled through Launch Configurations. This rule is non compliant if the Launch Configuration for an Auto Scaling group has AssociatePublicIpAddress set to 'true'."

  sql = <<-EOT
    select
      launch_configuration_arn as resource,
      case
        when associate_public_ip_address then 'alarm'
        else 'ok'
      end as status,
      case
        when associate_public_ip_address then title || ' public IP enabled.'
        else title || ' public IP disabled.'
      end as reason,
      region,
      account_id
    from
      aws_ec2_launch_configuration;
  EOT

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/AutoScaling"
  })
}

control "ec2_instance_not_publicly_accessible" {
  title       = "EC2 instances should not have a public IP address"
  description = "This control checks whether EC2 instances have a public IP address. The control fails if the publicIp field is present in the EC2 instance configuration item. This control applies to IPv4 addresses only."

  sql = <<-EOT
    select
      arn as resource,
      case
        when public_ip_address is null then 'ok'
        else 'alarm'
      end status,
      case
        when public_ip_address is null then instance_id || ' not publicly accessible.'
        else instance_id || ' publicly accessible.'
      end reason,
      region,
      account_id
    from
      aws_ec2_instance;
  EOT

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/EC2"
  })
}

control "ec2_network_interface_not_publicly_accessible" {
  title       = "EC2 network interfaces should not have a public IP address"
  description = "This control check if Amazon EC2 network interface is associated with any public IP."

  sql = <<-EOT
    select
      network_interface_id as resource,
      case
        when association_public_ip is null then 'ok'
        else 'alarm'
      end status,
      case
        when association_public_ip is null then network_interface_id || ' not publicly accessible.'
        else network_interface_id || ' publicly accessible.'
      end reason,
      region,
      account_id
    from
      aws_ec2_network_interface;
  EOT

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/EC2"
  })
}

control "ecs_service_not_publicly_accessible" {
  title       = "Amazon ECS services should not have public IP addresses assigned to them automatically"
  description = "This control checks whether Amazon ECS services are configured to automatically assign public IP addresses. This control fails if AssignPublicIP is enabled. This control passes if AssignPublicIP is disabled."

  sql = <<-EOT
    with service_awsvpc_mode_task_definition as (
      select
        a.service_name as service_name,
        b.task_definition_arn as task_definition
      from
        aws_ecs_service as a
        left join aws_ecs_task_definition as b on a.task_definition = b.task_definition_arn
      where
        b.network_mode = 'awsvpc'
    )
    select
      a.arn as resource,
      case
        when b.service_name is null then 'skip'
        when network_configuration -> 'AwsvpcConfiguration' ->> 'AssignPublicIp' = 'DISABLED' then 'ok'
        else 'alarm'
      end as status,
      case
        when b.service_name is null then a.title || ' task definition not host network mode.'
        when network_configuration -> 'AwsvpcConfiguration' ->> 'AssignPublicIp' = 'DISABLED' then a.title || ' not publicly accessible.'
        else a.title || ' publicly accessible.'
      end as reason,
      region,
      account_id
    from
      aws_ecs_service as a
      left join service_awsvpc_mode_task_definition as b on a.service_name = b.service_name;
  EOT

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/ECS"
  })
}

control "emr_cluster_master_nodes_no_public_ip" {
  title       = "EMR cluster master nodes should not have a public IP address"
  description = "This control checks whether master nodes on Amazon EMR clusters have public IP addresses. The control fails if the master node has public IP addresses that are associated with any of its instances. Public IP addresses are designated in the PublicIp field of the NetworkInterfaces configuration for the instance. This control only checks Amazon EMR clusters that are in RUNNING or WAITING state."

  sql = <<-EOT
    select
      c.cluster_arn as resource,
      case
        when c.status ->> 'State' not in ('RUNNING', 'WAITING') then 'skip'
        when s.map_public_ip_on_launch then 'alarm'
        else 'ok'
      end as status,
      case
        when c.status ->> 'State' not in ('RUNNING', 'WAITING') then c.title || ' is in ' || (c.status ->> 'State') || ' state.'
        when s.map_public_ip_on_launch then c.title || ' master nodes assigned with public IP.'
        else c.title || ' master nodes not assigned with public IP.'
      end as reason,
      c.region,
      c.account_id
    from
      aws_emr_cluster as c
      left join aws_vpc_subnet as s on c.ec2_instance_attributes ->> 'Ec2SubnetId' = s.subnet_id;
  EOT

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/EMR"
  })
}

control "vpc_subnet_auto_assign_public_ip_disabled" {
  title       = "VPC subnets should not auto-assign public IP addresses"
  description = "Ensure if Amazon Virtual Private Cloud (Amazon VPC) subnets are assigned a public IP address. The control is compliant if Amazon VPC does not have subnets that are assigned a public IP address. The control is non compliant if Amazon VPC has subnets that are assigned a public IP address."

  sql = <<-EOT
    select
      subnet_id as resource,
      case
        when map_public_ip_on_launch = 'false' then 'ok'
        else 'alarm'
      end as status,
      case
        when map_public_ip_on_launch = 'false' then title || ' auto assign public IP disabled.'
        else title || ' auto assign public IP enabled.'
      end as reason,
      region,
      account_id
    from
      aws_vpc_subnet;
  EOT

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/VPC"
  })
}

benchmark "resource_config_public_access" {
  title         = "Resource Config Public Access"
  description   = "The resource config public access is a set of controls that identifies if your deployed resources exposed to internet by any means of configurational changes in the resources."
  documentation = file("./perimeter/docs/resource_config_public_access.md")
  children = [
    control.dms_replication_instance_not_publicly_accessible,
    control.ebs_snapshot_not_publicly_accessible,
    control.ec2_instance_ami_prohibit_public_access,
    control.eks_cluster_endpoint_prohibit_public_access,
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

control "dms_replication_instance_not_publicly_accessible" {
  title       = "Database Migration Service (DMS) replication instances should not be public"
  description = "This control checks whether AWS DMS replication instances are public. To do this, it examines the value of the PubliclyAccessible field. A private replication instance has a private IP address that you cannot access outside of the replication network. A replication instance should have a private IP address when the source and target databases are in the same network, and the network is connected to the replication instance's VPC using a VPN, AWS Direct Connect, or VPC peering."

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
  description = "This control checks whether Amazon Elastic Block Store snapshots are not publicly restorable by everyone, which makes them public. Amazon EBS snapshots should not be publicly restorable by everyone unless you explicitly allow it, to avoid accidental exposure of your company’s sensitive data."

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
      account_id
    from
      aws_ebs_snapshot;
  EOT

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/EBS"
  })
}

control "ec2_instance_ami_prohibit_public_access" {
  title       = "EC2 AMIs should prohibit public access"
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
      account_id
    from
      aws_ec2_ami;
  EOT

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/EC2"
  })
}

control "eks_cluster_endpoint_prohibit_public_access" {
  title       = "EKS cluster endpoints should prohibit public access"
  description = "Ensure that Amazon Elastic Kubernetes Service (Amazon EKS) endpoints are not publicly accessible. The rule is non compliant if the endpoints are publicly accessible."

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
  description = "Manage access to resources in the AWS Cloud by ensuring that Amazon Relational Database Service (Amazon RDS) instances are not public."

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

control "rds_db_snapshot_prohibit_public_access" {
  title       = "RDS DB snapshots should not be publicly restorable"
  description = "This control checks whether Amazon RDS DB snapshots prohibit access to other accounts. It is recommended that your RDS snapshots should not be public in order to prevent potential leak or misuse of sensitive data or any other kind of security threat. If your RDS snapshot is public; then the data which is backed up in that snapshot is accessible to all other AWS accounts."

  sql = <<-EOT
    (
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
      jsonb_array_elements(db_cluster_snapshot_attributes) as cluster_snapshot
    )
    union
    (
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
      jsonb_array_elements(db_snapshot_attributes) as database_snapshot
    );

  EOT

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/RDS"
  })
}

control "redshift_cluster_prohibit_public_access" {
  title       = "Redshift clusters should prohibit public access"
  description = "This control checks whether Amazon Redshift clusters prohibit access to other accounts. It is recommended that your Redshift clusters should not be public in order to prevent potential leak or misuse of sensitive data or any other kind of security threat."

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
  description = "Access to internet could provide an avenue for unauthorized access to your data. Ensure that Amazon SageMaker notebook instances do not allow direct internet access."

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
  description = "Manage access to resources in the AWS Cloud by ensuring that Amazon Simple Storage Service (Amazon S3) buckets cannot be publicly accessed."

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
  description = "Ensure Amazon Simple Storage Service (Amazon S3) buckets are not publicly accessible. This rule is non compliant if an Amazon S3 bucket is not listed in the excludedPublicBuckets parameter and bucket level settings are public."

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
  description = "Manage access to resources in the AWS Cloud by only allowing authorized users, processes, and devices access to Amazon Simple Storage Service (Amazon S3) buckets."

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
  description = "Manage access to resources in the AWS Cloud by only allowing authorized users, processes, and devices access to Amazon Simple Storage Service (Amazon S3) buckets."

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

benchmark "resource_policy_public_access" {
  title         = "Resource Policy Public Access"
  description   = "The resource policy public access is a set of controls that identifies if your deployed resources exposed to internet by any means of configurational changes in the resources policy."
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
  description = "Ensure there are no ECR repositories set as public."

  sql = <<-EOT
    with open_access_ecr_repo as(
      select
        distinct arn
      from
        aws_ecr_repository,
        jsonb_array_elements(policy_std -> 'Statement') as s,
        jsonb_array_elements_text(s -> 'Principal' -> 'AWS') as p,
        string_to_array(p, ':') as pa,
        jsonb_array_elements_text(s -> 'Action') as a
      where
        s ->> 'Effect' = 'Allow'
        and p = '*'
    )
    select
      r.arn as resource,
      case
        when o.arn is not null then 'alarm'
        else 'ok'
      end as status,
      case
        when o.arn is not null then r.title || ' allows public accesss.'
        else r.title || ' does not allow public access.'
      end as reason,
      r.region,
      r.account_id
    from
      aws_ecr_repository as r
      left join open_access_ecr_repo as o on r.arn = o.arn
    group by
      resource, status, reason, r.region, r.account_id;
  EOT

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/ECR"
  })
}

control "lambda_function_policy_prohibit_public_access" {
  title       = "Lambda function policies should prohibit public access"
  description = "Manage access to resources in the AWS Cloud by ensuring AWS Lambda functions cannot be publicly accessed."

  sql = <<-EOT
    select
      arn as resource,
      case
        when policy_std -> 'Statement' ->> 'Effect' = 'Allow'
        and (
          policy_std -> 'Statement' ->> 'Principal' = '*'
          or ( policy_std -> 'Principal' -> 'AWS' ) :: text = '*'
        ) then 'alarm'
        else 'ok'
      end status,
      case
        when policy_std is null then title || ' has no policy.'
        when policy_std -> 'Statement' ->> 'Effect' = 'Allow'
        and (
          policy_std -> 'Statement' ->> 'Principal' = '*'
          or ( policy_std -> 'Principal' -> 'AWS' ) :: text = '*'
        ) then title || ' allows public access.'
        else title || ' does not allow public access.'
      end reason,
      region,
      account_id
    from
      aws_lambda_function;
  EOT

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/Lambda"
  })
}

control "s3_bucket_policy_prohibit_public_access" {
  title       = "S3 bucket policies should prohibit public access"
  description = "Manage access to resources in the AWS Cloud by ensuring AWS S3 buckets cannot be publicly accessed."

  sql = <<-EOT
    with wildcard_action_policies as (
      select
        arn,
        count(*) as statements_num
      from
        aws_s3_bucket,
        jsonb_array_elements(policy_std -> 'Statement') as s
      where
        s ->> 'Effect' = 'Allow'
        and( s -> 'Principal' -> 'AWS') = '["*"]'
      group by
        arn
    )
    select
      s.arn as resource,
      case
        when p.arn is null then 'ok'
        else 'alarm'
      end status,
      case
        when p.arn is null then name || ' does not allow public access.'
        else name || ' contains ' || coalesce(p.statements_num,0) ||
        ' statements that allows public access.'
      end as reason,
      s.region,
      s.account_id
    from
      aws_s3_bucket as s
      left join wildcard_action_policies as p on p.arn = s.arn;
  EOT

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/S3"
  })
}

control "sns_topic_policy_prohibit_public_access" {
  title       = "SNS topic policies should prohibit public access"
  description = "Manage access to resources in the AWS Cloud by ensuring AWS SNS topics cannot be publicly accessed."

  sql = <<-EOT
    with wildcard_action_policies as (
      select
        topic_arn,
        count(*) as statements_num
      from
        aws_sns_topic,
        jsonb_array_elements(policy_std -> 'Statement') as s
      where
        s ->> 'Effect' = 'Allow'
        and (
          ( s -> 'Principal' -> 'AWS') = '["*"]'
          or s ->> 'Principal' = '*'
        )
      group by
        topic_arn
    )
    select
      t.topic_arn as resource,
      case
        when p.topic_arn is null then 'ok'
        else 'alarm'
      end status,
      case
        when p.topic_arn is null then title || ' does not allow public access.'
        else title || ' contains ' || coalesce(p.statements_num,0) ||
        ' statements that allows public access.'
      end as reason,
      t.region,
      t.account_id
    from
      aws_sns_topic as t
      left join wildcard_action_policies as p on p.topic_arn = t.topic_arn;
  EOT

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/SNS"
  })
}

control "sqs_queue_policy_prohibit_public_access" {
  title       = "SQS queue policies should prohibit public access"
  description = "Manage access to resources in the AWS Cloud by ensuring AWS SQS queues cannot be publicly accessed."

  sql = <<-EOT
    with wildcard_action_policies as (
      select
        queue_arn,
        count(*) as statements_num
      from
        aws_sqs_queue,
        jsonb_array_elements(policy_std -> 'Statement') as s
      where
        s ->> 'Effect' = 'Allow'
        and (
          ( s -> 'Principal' -> 'AWS') = '["*"]'
          or s ->> 'Principal' = '*'
        )
      group by
        queue_arn
    )
    select
      q.queue_arn as resource,
      case
        when p.queue_arn is null then 'ok'
        else 'alarm'
      end status,
      case
        when p.queue_arn is null then title || ' does not allow public access.'
        else title || ' contains ' || coalesce(p.statements_num,0) ||
        ' statements that allows public access.'
      end as reason,
      q.region,
      q.account_id
    from
      aws_sqs_queue as q
      left join wildcard_action_policies as p on q.queue_arn = p.queue_arn;
  EOT

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/SQS"
  })
}

control "glacier_vault_policy_prohibit_public_access" {
  title       = "Glacier vault policies should prohibit public access"
  description = "Manage access to resources in the AWS Cloud by ensuring AWS Glacier vaults cannot be publicly accessed."

  sql = <<-EOT
    with wildcard_action_policies as (
      select
        vault_arn,
        count(*) as statements_num
      from
        aws_glacier_vault,
        jsonb_array_elements(policy_std -> 'Statement') as s
      where
        s ->> 'Effect' = 'Allow'
        and (
          ( s -> 'Principal' -> 'AWS') = '["*"]'
          or s ->> 'Principal' = '*'
        )
      group by
        vault_arn
    )
    select
      v.vault_arn as resource,
      case
        when p.vault_arn is null then 'ok'
        else 'alarm'
      end status,
      case
        when p.vault_arn is null then title || ' does not allow public access.'
        else title || ' contains ' || coalesce(p.statements_num,0) ||
        ' statements that allows public access.'
      end as reason,
      v.region,
      v.account_id
    from
      aws_glacier_vault as v
      left join wildcard_action_policies as p on v.vault_arn = p.vault_arn;
  EOT

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/Glacier"
  })
}

control "iam_role_trust_policy_prohibit_public_access" {
  title       = "IAM role trust policies should prohibit public access"
  description = "Role trust policies can provide access to roles in external AWS accounts."

  sql = <<-EOT
    with assume_role as (
      select
        arn,
         count(*) as statements_num
      from
        aws_iam_role,
        jsonb_array_elements(assume_role_policy_std -> 'Statement') as stmt,
        jsonb_array_elements_text(stmt -> 'Principal' -> 'AWS') as trust
      where
        trust = '*'
      group by
        arn
    )
    select
      r.arn as resource,
      case
        when a.arn is null then 'ok'
        else 'alarm'
      end status,
      case
        when a.arn is null then title || ' trust policy does not allow public access.'
        else title || ' contains ' || coalesce(a.statements_num,0) ||
        ' trust policy allows public access.'
      end as reason,
      r.account_id
    from
      aws_iam_role as r
      left join assume_role as a on r.arn = a.arn;
  EOT

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/IAM"
  })
}

control "kms_key_policy_prohibit_public_access" {
  title       = "KMS key policies should prohibit public access"
  description = "Manage access to resources in the AWS Cloud by ensuring AWS KMS keys cannot be publicly accessed."

  sql = <<-EOT
    with wildcard_action_policies as (
      select
        arn,
        count(*) as statements_num
      from
        aws_kms_key,
        jsonb_array_elements(policy_std -> 'Statement') as s
      where
        s ->> 'Effect' = 'Allow'
        and (
          ( s -> 'Principal' -> 'AWS') = '["*"]'
          or  s ->> 'Principal' = '*'
        )
        and key_manager = 'CUSTOMER'
      group by
        arn
    )
    select
      k.arn as resource,
      case
        when p.arn is null then 'ok'
        else 'alarm'
      end status,
      case
        when p.arn is null then title || ' does not allow public access.'
        else title || ' contains ' || coalesce(p.statements_num,0) ||
        ' statements that allows public access.'
      end as reason,
      k.region,
      k.account_id
    from
      aws_kms_key as k
      left join wildcard_action_policies as p on p.arn = k.arn
    where
      key_manager = 'CUSTOMER';
  EOT

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/KMS"
  })
}

