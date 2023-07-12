This benchmark answers the following questions:

- What resources have resource policies that grant access to AWS accounts?
- Which accounts have been granted access are not trusted?

> **Important Note:** 
> 
> When evaluating policies only a subset of Conditions/Operators are checked, see the [table documentation for known limitations](https://hub.steampipe.io/plugins/turbot/aws/tables/aws_resource_policy_analysis#limitations).

This benchmark defines shared as a policy having at least one `Allow` statement that grants one or more permission to a principal.
The benchmark exposes the variable `trusted_accounts` which can be used to set which accounts are trusted.
The benchmark will use the variable `trusted_accounts` to check if the accounts that are granted access by the policy are trusted accounts and alarm if they are untrusted.

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
If the `111122223333` is a trusted account, the benchmark will report that access has been given to the account and that it is trusted.
Otherwise, the benchmark will alarm and report that account `111122223333` is untrusted.

For each statement, if there are any condition keys then these condition keys will be evaluated as follows:

The benchmark uses principals conditions, `aws:PrincipalAccount` and `aws:PrincipalArn` in its evaluation of the policy by checking the values in the conditions against the values set by the Principal element of the policy.

If there is a condition that reduces the number of principals that allow access to a resource, the benchmark will calculate the reduced scope and use this value when running the benchmark controls.

The following example policy restricts access to account `111122223333` and the benchmark will check if account `111122223333` is trusted:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowPublicAccess1",
      "Effect": "Allow",
      "Principal": {
        "AWS": "*"
      },
      "Action": ["s3:PutObject", "s3:PutObjectAcl"],
      "Resource": "arn:aws:s3:::EXAMPLE-BUCKET/*",
      "Condition": {
        "StringEquals": {
          "aws:PrincipalAccount": "111122223333"
        }
      }
    }
  ]
}
```
