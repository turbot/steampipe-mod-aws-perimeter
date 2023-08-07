This benchmark answers the following questions:

- What resources have resource policies that grant access to AWS services, accounts, identity providers or organizations?
- Which services, accounts, identity providers or organizations that have been granted access are not trusted?

> **Important Note:** 
> 
> When evaluating policies only a subset of Conditions/Operators are checked, see the [table documentation for known limitations](https://hub.steampipe.io/plugins/turbot/aws/tables/aws_resource_policy_analysis#limitations).

This benchmark defines shared as a policy having at least one `Allow` statement that grants one or more permission to a principal.
The benchmark exposes variables which can be used to set which accounts, services, identity providers or organizations are trusted.
The benchmark will use these variables to check if the principals of the policy are trusted and alarm if they are untrusted.

For example:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowPublicAccess1",
      "Effect": "Allow",
      "Principal": {
        "AWS": "111122223333"
      },
      "Action": ["s3:PutObject", "s3:PutObjectAcl"],
      "Resource": "arn:aws:s3:::EXAMPLE-BUCKET/*"
    }
  ]
}
```

The above policy grants the principal `111122223333` access to a resource.
If the `111122223333` is a trusted account, the benchmark will report that access has been granted to the account and that it is trusted.
Otherwise, the benchmark will alarm and report that account `111122223333` is untrusted.

The benchmark analyses policies for:

- [Shared Accounts Access](./resource_policy_shared_accounts_access.md)
- [Identity Providers Access](./resource_policy_shared_identity_providers_access.md)
- [Shared Organizations Access](./resource_policy_shared_organizations_access.md)
- [Shared Service Access](./resource_policy_shared_services_access.md)