benchmark "network_access" {
  title         = "Network Access"
  description   = "Resources should not be exposed to the internet through VPC settings, security group rules, or public IP addresses."
  documentation = file("./perimeter/docs/network_access.md")
  children = [
    benchmark.network_general_access,
    benchmark.security_group_access,
    benchmark.public_ips
  ]

  tags = merge(local.aws_perimeter_common_tags, {
    type = "Benchmark"
  })
}

benchmark "network_general_access" {
  title         = "Network General Access"
  description   = "Resources should follow general best practices to safeguard from exposure to public access."
  documentation = file("./perimeter/docs/network_general_access.md")
  children = [
    control.ec2_instance_in_vpc,
    control.elb_application_lb_waf_enabled,
    control.es_domain_in_vpc,
    control.lambda_function_in_vpc,
    control.opensearch_domain_in_vpc,
    control.rds_db_instance_in_vpc,
    control.sagemaker_model_in_vpc,
    control.sagemaker_notebook_instance_in_vpc,
    control.sagemaker_training_job_in_vpc,
    control.vpc_peering_connection_cross_account_shared
  ]

  tags = merge(local.aws_perimeter_common_tags, {
    type = "Benchmark"
  })
}

control "ec2_instance_in_vpc" {
  title       = "EC2 instances should be in a VPC"
  description = "Deploy EC2 instances within a VPC to enable secure communication between an instance and other services within the VPC, without requiring an internet gateway, NAT device, or VPN connection."

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
      end as reason
      ${local.tag_dimensions_sql}
      ${local.common_dimensions_sql}
    from
      aws_ec2_instance;
  EOT

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/EC2"
  })
}

control "elb_application_lb_waf_enabled" {
  title       = "ELB application load balancers should have Web Application Firewall (WAF) enabled"
  description = "Ensure AWS WAF is enabled on application load balancers to help protect web applications."

  sql = <<-EOT
    with associated_resource as (
      select 
        arns
      from
        aws_wafv2_web_acl,
        jsonb_array_elements_text(associated_resources) as arns  
    )
    select
      arn as resource,
      case
        when ar.arns is not null then 'ok'
        else 'alarm'
      end as status,
      case
        when ar.arns is not null then title || ' WAF enabled.'
        else title || ' WAF disabled.'
      end as reason
      ${local.tag_dimensions_sql}
      ${local.common_dimensions_sql}
    from
      aws_ec2_application_load_balancer as lb
      left join associated_resource as ar on lb.arn = ar.arns;
  EOT

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/ELB"
  })
}

control "es_domain_in_vpc" {
  title       = "Elasticsearch Service domains should be in a VPC"
  description = "This control checks whether Elasticsearch domains are in a VPC. It does not evaluate the VPC subnet routing configuration to determine public access. You should ensure that Amazon ES domains are not attached to public subnets."

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
      end reason
      ${local.tag_dimensions_sql}
      ${local.common_dimensions_sql}
    from
      aws_elasticsearch_domain;
  EOT

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/ES"
  })
}

control "lambda_function_in_vpc" {
  title       = "Lambda functions should be in a VPC"
  description = "This control checks whether Lambda functions are in a VPC. It does not evaluate the VPC subnet routing configuration to determine public access. You should ensure that Amazon Lambda functions are not attached to public subnets."

  sql = <<-EOT
    select
      arn as resource,
      case
        when vpc_id is null then 'alarm'
        else 'ok'
      end status,
      case
        when vpc_id is null then title || ' is not in VPC.'
        else title || ' is in VPC ' || vpc_id || '.'
      end reason
      ${local.tag_dimensions_sql}
      ${local.common_dimensions_sql}
    from
      aws_lambda_function;
  EOT

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/Lambda"
  })
}

control "opensearch_domain_in_vpc" {
  title       = "Amazon OpenSearch domains should be in a VPC private subnet"
  description = "This control checks whether Amazon OpenSearch domains are in a VPC with no public subnets associated to it."

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
      end reason
      ${local.tag_dimensions_sql}
      ${replace(local.common_dimensions_qualifier_sql, "__QUALIFIER__", "d.")}
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
  description = "This control checks whether RDS DB instances are deployed in a VPC."

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
      end as reason
      ${local.tag_dimensions_sql}
      ${local.common_dimensions_sql}
    from
      aws_rds_db_instance;
  EOT

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/RDS"
  })
}

control "sagemaker_model_in_vpc" {
  title       = "SageMaker models should be in a VPC"
  description = "This control checks whether SageMaker models are deployed in a VPC."

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
      end as reason
      ${local.tag_dimensions_sql}
      ${local.common_dimensions_sql}
    from
      aws_sagemaker_model;
  EOT

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/SageMaker"
  })
}

control "sagemaker_notebook_instance_in_vpc" {
  title       = "SageMaker notebook instances should be in a VPC"
  description = "This control checks whether SageMaker Notebook instances are deployed in a VPC."

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
      end as reason
      ${local.tag_dimensions_sql}
      ${local.common_dimensions_sql}
    from
      aws_sagemaker_notebook_instance;
  EOT

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/SageMaker"
  })
}

control "sagemaker_training_job_in_vpc" {
  title       = "SageMaker training jobs should be in a VPC"
  description = "This control checks whether SageMaker training jobs are deployed in a VPC."

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
      end reason
      ${local.tag_dimensions_sql}
      ${local.common_dimensions_sql}
    from
      aws_sagemaker_training_job;
  EOT

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/SageMaker"
  })
}

control "vpc_peering_connection_cross_account_shared" {
  title       = "VPCs should only be peered with trusted accounts"
  description = "This control checks if VPCs are only peered with trusted accounts."

  sql = <<-EOT
    select
      id as resource,
      case
        when accepter_owner_id = requester_owner_id or accepter_owner_id = any (($1)::text[]) then 'ok'
        else 'info'
      end status,
      case
        when accepter_owner_id = requester_owner_id or accepter_owner_id = any (($1)::text[]) then title || ' is peered with a trust account.'
        else title || ' is peered with untrusted account ' || accepter_owner_id || '.'
      end reason
      ${local.tag_dimensions_sql}
      ${local.common_dimensions_sql}
    from
      aws_vpc_peering_connection;
  EOT

  param "trusted_accounts" {
    description = "A list of trusted accounts."
    default     = var.trusted_accounts
  }

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/VPC"
  })
}

benchmark "security_group_access" {
  title         = "Security Group Access"
  description   = "Security groups should restrict ingress and egress access to certain IP addresses and resources to prevent unwanted access."
  documentation = file("./perimeter/docs/security_group_access.md")
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
  description = "This control checks if any security groups allow inbound 0.0.0.0/0 to TCP or UDP ports."

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
      end as reason
      ${local.tag_dimensions_sql}
      ${replace(local.common_dimensions_qualifier_sql, "__QUALIFIER__", "sg.")}
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
  description = "This control checks if any security groups allow inbound 0.0.0.0/0 or ::/0 to ports 20, 21, 22, 3306, 3389, 4333."

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
        when ingress_ssh_rules.group_id is null then sg.group_id || ' ingress restricted for common ports from 0.0.0.0/0 and ::/0.'
        else sg.group_id || ' contains ' || ingress_ssh_rules.num_ssh_rules || ' ingress rule(s) allowing access for common ports from 0.0.0.0/0 and ::/0.'
      end as reason
      ${local.tag_dimensions_sql}
      ${replace(local.common_dimensions_qualifier_sql, "__QUALIFIER__", "sg.")}
    from
      aws_vpc_security_group as sg
      left join ingress_ssh_rules on ingress_ssh_rules.group_id = sg.group_id;
  EOT

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/VPC"
  })
}

benchmark "public_ips" {
  title         = "Public IPs"
  description   = "Resources should not have public IP addresses, as these can expose them to the internet."
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
  title       = "Auto Scaling launch configs should not associate public IP addresses to instances"
  description = "Ensure that EC2 Auto Scaling launch configurations do not associate public IP addresses to Auto Scaling group instances."

  sql = <<-EOT
    select
      launch_configuration_arn as resource,
      case
        when associate_public_ip_address then 'alarm'
        else 'ok'
      end as status,
      case
        when associate_public_ip_address then title || ' associate public IP addresses.'
        else title || ' do not associate public IP addresses.'
      end as reason
      ${local.common_dimensions_sql}
    from
      aws_ec2_launch_configuration;
  EOT

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/AutoScaling"
  })
}

control "ec2_instance_not_publicly_accessible" {
  title       = "EC2 instances should not have a public IP address"
  description = "This control checks whether EC2 instances have a public IPv4 address."

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
      end reason
      ${local.tag_dimensions_sql}
      ${local.common_dimensions_sql}
    from
      aws_ec2_instance;
  EOT

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/EC2"
  })
}

control "ec2_network_interface_not_publicly_accessible" {
  title       = "EC2 network interfaces should not have a public IP address"
  description = "This control checks if EC2 network interfaces are associated with any public IP."

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
      end reason
      ${local.tag_dimensions_sql}
      ${local.common_dimensions_sql}
    from
      aws_ec2_network_interface;
  EOT

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/EC2"
  })
}

control "ecs_service_not_publicly_accessible" {
  title       = "Amazon ECS services should not have public IP addresses assigned to them automatically"
  description = "This control checks whether Amazon ECS services are configured to automatically assign public IP addresses."

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
      end as reason
      ${local.tag_dimensions_sql}
      ${local.common_dimensions_sql}
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
  description = "This control checks whether master nodes on Amazon EMR clusters have public IP addresses. This control only checks Amazon EMR clusters that are in RUNNING or WAITING state."

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
      end as reason
      ${replace(local.tag_dimensions_qualifier_sql, "__QUALIFIER__", "c.")}
      ${replace(local.common_dimensions_qualifier_sql, "__QUALIFIER__", "c.")}
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
  description = "This control checks whether VPC subnets automatically assign public IPv4 addresses."

  sql = <<-EOT
    select
      subnet_id as resource,
      case
        when map_public_ip_on_launch = 'false' then 'ok'
        else 'alarm'
      end as status,
      case
        when map_public_ip_on_launch = 'false' then title || ' auto-assign public IP addresses disabled.'
        else title || ' auto-assign public IP addresses enabled.'
      end as reason
      ${local.tag_dimensions_sql}
      ${local.common_dimensions_sql}
    from
      aws_vpc_subnet;
  EOT

  tags = merge(local.aws_perimeter_common_tags, {
    service = "AWS/VPC"
  })
}
