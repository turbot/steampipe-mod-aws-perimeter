benchmark "network_access" {
  title         = "Network Access"
  description   = "The AWS network access is a set of controls that detect if your deployed resources are exposed to internet through any VPC's network settings such as security group ingress, public subnet."
  documentation = file("./perimeter/docs/network_access.md")
  children = [
    benchmark.network_general_access,
    benchmark.network_security_group_access
  ]

  tags = merge(local.aws_perimeter_common_tags, {
    type = "Benchmark"
  })
}

benchmark "network_general_access" {
  title         = "Network General Access"
  description   = "The AWS network general access is a set of controls that detect if  your deployed resources do not follow recommended general best practices to safeguard from exposure to public access."
  documentation = file("./perimeter/docs/network_general_access.md")
  children = [
    control.ec2_instance_in_vpc,
    control.elb_application_lb_waf_enabled,
    control.es_domain_in_vpc,
    control.opensearch_domain_in_vpc,
    control.rds_db_instance_in_vpc,
    control.sagemaker_model_in_vpc,
    control.sagemaker_notebook_instance_in_vpc,
    control.sagemaker_training_job_in_vpc,
    control.vpc_peering_connection_cross_account_shared,
    control.vpc_route_table_restrict_public_access_to_igw
  ]

  tags = merge(local.aws_perimeter_common_tags, {
    type = "Benchmark"
  })
}

control "ec2_instance_in_vpc" {
  title       = "EC2 instances should be in a VPC"
  description = "Deploy Amazon Elastic Compute Cloud (Amazon EC2) instances within an Amazon Virtual Private Cloud (Amazon VPC) to enable secure communication between an instance and other services within the amazon VPC, without requiring an internet gateway, NAT device, or VPN connection."

  sql = <<-EOT
    select
      arn as resource,
      case
        when vpc_id is null then 'alarm'
        else 'ok'
      end as status,
      case
        when vpc_id is null then title || ' not in VPC.'
        else title || ' in VPC.'
      end as reason,
      region,
      account_id
    from
      aws_ec2_instance;
  EOT

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/EC2"
  })
}

control "elb_application_lb_waf_enabled" {
  title       = "ELB application load balancers should have Web Application Firewall (WAF) enabled"
  description = "Ensure AWS WAF is enabled on Elastic Load Balancers (ELB) to help protect web applications."

  sql = <<-EOT
    select
      arn as resource,
      case
        when load_balancer_attributes @> '[{"Key":"waf.fail_open.enabled","Value":"true"}]' then 'ok'
        else 'alarm'
      end as status,
      case
        when load_balancer_attributes @> '[{"Key":"waf.fail_open.enabled","Value":"true"}]' then title || ' WAF enabled.'
        else title || ' WAF disabled.'
      end as reason,
      region,
      account_id
    from
      aws_ec2_application_load_balancer;
  EOT

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/ELB"
  })
}

control "es_domain_in_vpc" {
  title       = "Elasticsearch Service domains should be in a VPC"
  description = "This control checks whether Amazon Elasticsearch Service domains are in VPC. It does not evaluate the VPC subnet routing configuration to determine public access. You should ensure that Amazon ES domains are not attached to public subnets."

  sql = <<-EOT
    select
      arn as resource,
      case
        when vpc_options ->> 'VPCId' is null then 'alarm'
        else 'ok'
      end status,
      case
        when vpc_options ->> 'VPCId' is null then title || ' not in VPC.'
        else title || ' in VPC ' || (vpc_options ->> 'VPCId') || '.'
      end reason,
      region,
      account_id
    from
      aws_elasticsearch_domain;
  EOT

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/ES"
  })
}

control "opensearch_domain_in_vpc" {
  title       = "Amazon OpenSearch domains should be in a VPC without public subnet"
  description = "This control checks whether Amazon OpenSearch domains are in a VPC with no public subnet associated to it."

  sql = <<-EOT
    with public_subnets as (
      select
        distinct a -> 'SubnetId' as SubnetId
      from
        aws_vpc_route_table as t,
        jsonb_array_elements(associations) as a,
        jsonb_array_elements(routes) as r
      where
        r ->> 'DestinationCidrBlock' = '0.0.0.0/0'
        and r ->> 'GatewayId' like 'igw-%'
    ), opensearch_domain_with_public_subnet as (
      select
        arn
      from
        aws_opensearch_domain ,
        jsonb_array_elements(vpc_options -> 'SubnetIds') as s
      where
        s in (select SubnetId from public_subnets)
    )
    select
      d.arn as resource,
      case
        when d.vpc_options ->> 'VPCId' is null then 'alarm'
        when d.vpc_options ->> 'VPCId' is not null and p.arn is not null then 'alarm'
        else 'ok'
      end status,
      case
        when vpc_options ->> 'VPCId' is null then title || ' not in VPC.'
        when d.vpc_options ->> 'VPCId' is not null and p.arn is not null then title || ' attached to public subnet.'
        else title || ' in VPC ' || (vpc_options ->> 'VPCId') || '.'
      end reason,
      d.region,
      d.account_id
    from
      aws_opensearch_domain as d
      left join opensearch_domain_with_public_subnet as p on d.arn = p.arn;
  EOT

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/OpenSearch"
  })
}

control "rds_db_instance_in_vpc" {
  title       = "RDS DB instances should be deployed in a VPC"
  description = "This control checks whether RDS DB instances are deployed in a VPC(EC2-VPC)."

  sql = <<-EOT
    select
      arn as resource,
      case
        when vpc_id is null then 'alarm'
        else 'ok'
      end as status,
      case
        when vpc_id is null then title || ' not in VPC.'
        else title || ' in VPC ' || vpc_id || '.'
      end as reason,
      region,
      account_id
    from
      aws_rds_db_instance;
  EOT

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/RDS"
  })
}

control "sagemaker_model_in_vpc" {
  title       = "SageMaker models should be in a VPC"
  description = "This control checks whether SageMaker models are deployed in a VPC (EC2-VPC)."

  sql = <<-EOT
    select
      arn as resource,
      case
        when vpc_config is not null then 'ok'
        else 'alarm'
      end as status,
      case
        when vpc_config is not null then title || ' in VPC.'
        else title || ' not in VPC.'
      end as reason,
      region,
      account_id
    from
      aws_sagemaker_model;
  EOT

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/SageMaker"
  })
}

control "sagemaker_notebook_instance_in_vpc" {
  title       = "SageMaker notebook instances should be in a VPC"
  description = "This control checks whether SageMaker Notebook instances are deployed in a VPC (EC2-VPC)."

  sql = <<-EOT
    select
      arn as resource,
      case
        when subnet_id is not null then 'ok'
        else 'alarm'
      end as status,
      case
        when subnet_id is not null then title || ' in VPC.'
        else title || ' not in VPC.'
      end as reason,
      region,
      account_id
    from
      aws_sagemaker_notebook_instance;
  EOT

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/SageMaker"
  })
}

control "sagemaker_training_job_in_vpc" {
  title       = "SageMaker training jobs should be in a VPC"
  description = "This control checks whether SageMaker training jobs are deployed in a VPC (EC2-VPC)."

  sql = <<-EOT
    select
      arn as resource,
      case
        when vpc_config is not null then 'ok'
        else 'alarm'
      end status,
      case
        when vpc_config is not null then title || ' in VPC.'
        else title || ' not in VPC.'
      end reason,
      region,
      account_id
    from
      aws_sagemaker_training_job;
  EOT

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/SageMaker"
  })
}

control "vpc_peering_connection_cross_account_shared" {
  title       = "VPC peering should only be restricted to trusted accounts"
  description = "This control checks whether VPC peering connections are only restricted to trusted accounts."

  sql = <<-EOT
    select
      id as resource,
      case
        when accepter_owner_id = requester_owner_id or accepter_owner_id = any (($1)::text[]) then 'ok'
        else 'info'
      end status,
      case
        when accepter_owner_id = requester_owner_id or accepter_owner_id = any (($1)::text[]) then title || ' cross account sharing disabled with any untrusted accounts.'
        else title || ' cross account sharing with ' || accepter_owner_id || '.'
      end reason,
      region,
      account_id
    from
      aws_vpc_peering_connection;
  EOT

  param "trusted_accounts" {
    description = "Trusted Accounts"
    default     = var.trusted_accounts
  }

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/VPC"
  })
}

control "vpc_route_table_restrict_public_access_to_igw" {
  title       = "Public routes in the route table to an Internet Gateway (IGW) should be prohibited"
  description = "Ensure if there are public routes in the route table to an Internet Gateway (IGW). The rule is non compliant if a route to an IGW has a destination CIDR block of '0.0.0.0/0' or '::/0'."

  sql = <<-EOT
    with route_with_public_access as (
      select
        route_table_id,
        count(*) as num
      from
        aws_vpc_route_table,
        jsonb_array_elements(routes) as r
      where
        ( r ->> 'DestinationCidrBlock' = '0.0.0.0/0'
          or r ->> 'DestinationCidrBlock' = '::/0'
        )
        and r ->> 'GatewayId' like 'igw%'
      group by
        route_table_id
    )
    select
      a.route_table_id as resource,
      case
        when b.route_table_id is null then 'ok'
        else 'alarm'
      end as status,
      case
        when b.route_table_id is null then a.title || ' does not have public routes to an Internet Gateway (IGW).'
        else a.title || ' contains ' || b.num || ' rule(s) which have public routes to an Internet Gateway (IGW).'
      end as reason,
      a.region,
      a.account_id
    from
      aws_vpc_route_table as a
      left join route_with_public_access as b on b.route_table_id = a.route_table_id;

  EOT

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/VPC"
  })
}

benchmark "network_security_group_access" {
  title         = "Network Security Group Access"
  description   = "AWS Network Security Groups (SGs) restrict access to certain IP addresses or resources. It guards your AWS security perimeter, provided you configure them in the right way."
  documentation = file("./perimeter/docs/network_security_group_access.md")
  children = [
    control.vpc_security_group_restrict_ingress_common_ports_all,
    control.vpc_security_group_restrict_ingress_tcp_udp_all
  ]

  tags = merge(local.aws_perimeter_common_tags, {
    type = "Benchmark"
  })
}

control "vpc_security_group_restrict_ingress_tcp_udp_all" {
  title       = "VPC security groups should restrict ingress TCP and UDP access from 0.0.0.0/0"
  description = "This control checks whether any security groups with inbound 0.0.0.0/0 have TCP or UDP ports accessible. The rule is non compliant when a security group with inbound 0.0.0.0/0 have a TCP or UDP ports accessible."

  sql = <<-EOT
    with bad_rules as (
      select
        group_id,
        count(*) as num_bad_rules
      from
        aws_vpc_security_group_rule
      where
        type = 'ingress'
        and cidr_ipv4 = '0.0.0.0/0'
        and (
          ip_protocol in ('tcp', 'udp')
          or (
            ip_protocol = '-1'
            and from_port is null
          )
        )
      group by
        group_id
    )
    select
      arn as resource,
      case
        when bad_rules.group_id is null then 'ok'
        else 'alarm'
      end as status,
      case
        when bad_rules.group_id is null then sg.group_id || ' does not allow ingress to TCP or UDP ports from 0.0.0.0/0.'
        else sg.group_id || ' contains ' || bad_rules.num_bad_rules || ' rule(s) that allow ingress to TCP or UDP ports from 0.0.0.0/0.'
      end as reason,
      sg.region,
      sg.account_id
    from
      aws_vpc_security_group as sg
      left join bad_rules on bad_rules.group_id = sg.group_id;
  EOT

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/VPC"
  })
}

control "vpc_security_group_restrict_ingress_common_ports_all" {
  title       = "VPC security groups should restrict ingress access on ports 20, 21, 22, 3306, 3389, 4333 from 0.0.0.0/0"
  description = "Manage access to resources in the AWS Cloud by ensuring common ports are restricted on Amazon Elastic Compute Cloud (Amazon EC2) security groups."

  sql = <<-EOT
    with ingress_ssh_rules as (
      select
        group_id,
        count(*) as num_ssh_rules
      from
        aws_vpc_security_group_rule
      where
        type = 'ingress'
        and (
          cidr_ipv4 = '0.0.0.0/0'
          or cidr_ipv6 = '::/0'
        )
        and (
        ( ip_protocol = '-1'
          and from_port is null
          )
          or (
            from_port >= 22
            and to_port <= 22
          )
          or (
            from_port >= 3389
            and to_port <= 3389
          )
          or (
            from_port >= 21
            and to_port <= 21
          )
          or (
            from_port >= 20
            and to_port <= 20
          )
          or (
            from_port >= 3306
            and to_port <= 3306
          )
          or (
            from_port >= 4333
            and to_port <= 4333
          )
          or (
            from_port >= 23
            and to_port <= 23
          )
          or (
            from_port >= 25
            and to_port <= 25
          )
          or (
            from_port >= 445
            and to_port <= 445
          )
          or (
            from_port >= 110
            and to_port <= 110
          )
          or (
            from_port >= 135
            and to_port <= 135
          )
          or (
            from_port >= 143
            and to_port <= 143
          )
          or (
            from_port >= 1433
            and to_port <= 3389
          )
          or (
            from_port >= 3389
            and to_port <= 1434
          )
          or (
            from_port >= 5432
            and to_port <= 5432
          )
          or (
            from_port >= 5500
            and to_port <= 5500
          )
          or (
            from_port >= 5601
            and to_port <= 5601
          )
          or (
            from_port >= 9200
            and to_port <= 9300
          )
          or (
            from_port >= 8080
            and to_port <= 8080
          )
      )
      group by
        group_id
    )
    select
      arn as resource,
      case
        when ingress_ssh_rules.group_id is null then 'ok'
        else 'alarm'
      end as status,
      case
        when ingress_ssh_rules.group_id is null then sg.group_id || ' ingress restricted for common ports from 0.0.0.0/0.'
        else sg.group_id || ' contains ' || ingress_ssh_rules.num_ssh_rules || ' ingress rule(s) allowing access for common ports from 0.0.0.0/0.'
      end as reason,
      sg.region,
      sg.account_id
    from
      aws_vpc_security_group as sg
      left join ingress_ssh_rules on ingress_ssh_rules.group_id = sg.group_id;
  EOT

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/VPC"
  })
}
