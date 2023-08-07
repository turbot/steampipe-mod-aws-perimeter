This benchmark answers the following questions:

- What resources have resource policies that grant access to AWS organizations?
- Which organizations have been granted access are not trusted?

> **Important Note:** 
> 
> When evaluating policies only a subset of Conditions/Operators are checked, see the [table documentation for known limitations](https://hub.steampipe.io/plugins/turbot/aws/tables/aws_resource_policy_analysis#limitations).

This benchmark defines shared as a policy having at least one `Allow` statement that grants one or more permission to a principal.
The benchmark exposes the variable `trusted_organizations` which can be used to set which organizations are trusted.
The benchmark will use the variable `trusted_organizations` to check if the organizations that are granted access by the policy are trusted organizations and alarm if they are untrusted.

For example:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowPublicAccess1",
      "Effect": "Allow",
      "Principal": {
        "AWS": "111122221111"
      },
      "Action": ["s3:PutObject", "s3:PutObjectAcl"],
      "Resource": "arn:aws:s3:::EXAMPLE-BUCKET/*",
      "Condition": {
        "StringEquals": {
          "aws:PrincipalOrgID": ["o-12341234"]
        }
      }
    }
  ]
}
```

The above policy grants access to account `111122221111` provided the account is part of the organization `o-12341234`.
If `o-12341234` is a trusted organization, the benchmark will report that access has been granted to the organization and that it is trusted.
Otherwise, the benchmark will alarm and report that organization `o-12341234` is untrusted.

For each statement, if there are any condition keys then these condition keys will be evaluated as follows:

The benchmark uses principals conditions, `aws:PrincipalAccount`, `aws:PrincipalArn` or `PrincipalOrgID` in its evaluation of the policy by checking the values set in the conditions against the values set by the Principal element of the policy.

If there is a condition that reduces the number of principals that allow access to a resource, the benchmark will calculate the reduced scope and use this value when running the benchmark controls.

The following example policy restricts access to account `111122223333` and organization `o-12341234`.
The benchmark will use the value to test if the organization is a trusted organization:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowPublicAccess1",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::111122223333:user/user_name"
      },
      "Action": ["s3:PutObject", "s3:PutObjectAcl"],
      "Resource": "arn:aws:s3:::EXAMPLE-BUCKET/*",
      "Condition": {
        "StringEquals": {
          "aws:PrincipalOrgID": ["o-12341234"],
          "aws:PrincipalAccount": "111122223333"
        }
      }
    }
  ]
}
```