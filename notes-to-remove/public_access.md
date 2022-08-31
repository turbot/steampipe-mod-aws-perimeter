# Public Access

control "api_gateway_rest_api_prohibit_public_access" - aws_api_gateway_rest_api
control "dms_replication_instance_not_publicly_accessible" - aws_dms_replication_instance
control "ebs_snapshot_not_publicly_accessible" - aws_ebs_snapshot
control "ec2_instance_ami_prohibit_public_access" - aws_ec2_ami
control "eks_cluster_endpoint_prohibit_public_access" - aws_eks_cluster
control "rds_db_instance_prohibit_public_access" - aws_rds_db_instance
control "rds_db_cluster_snapshot_prohibit_public_access" - aws_rds_db_cluster_snapshot
control "rds_db_snapshot_prohibit_public_access" - aws_rds_db_snapshot
control "redshift_cluster_prohibit_public_access" - aws_redshift_cluster
control "sagemaker_notebook_instance_direct_internet_access_disabled" - aws_sagemaker_notebook_instance
control "s3_public_access_block_account" - aws_s3_account_settings
control "s3_public_access_block_bucket" - aws_s3_bucket
control "s3_bucket_acl_prohibit_public_read_access" - aws_s3_bucket
control "s3_bucket_acl_prohibit_public_write_access" - aws_s3_bucket

Benchmark we are interested in:

```hcl
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
```

## Currently busy with

control "ecr_repository_policy_prohibit_public_access" - aws_ecr_repository
