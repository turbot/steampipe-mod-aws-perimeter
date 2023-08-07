This benchmark answers the following questions:

- What resources have resource policies that allow public access?

> **Important Note:** 
> 
> When evaluating policies only a subset of Conditions/Operators are checked, see the [table documentation for known limitations](https://hub.steampipe.io/plugins/turbot/aws/tables/aws_resource_policy_analysis#limitations).

This benchmark defines public as a policy having at least one `Allow` statement that grants one or more permission to the `*` principal, e.g.

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
      "Resource": "arn:aws:s3:::EXAMPLE-BUCKET/*"
    }
  ]
}
```

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowPublicAccess2",
      "Effect": "Allow",
      "Principal": "*",
      "Action": ["s3:PutObject", "s3:PutObjectAcl"],
      "Resource": "arn:aws:s3:::EXAMPLE-BUCKET/*"
    }
  ]
}
```

This benchmark also defines public as a policy that has an AWS service as the principal and _missing_ the condition which restricts the service access to a resource or account, such as `aws:SourceArn`, `aws:SourceOwner` or `aws:SourceAccount`, with at least one `Allow` statement that grants one or more permissions, e.g.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "cloudtrail.amazonaws.com"
      },
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:cloudtrail:us-east-1:111122221111:trail/example-cloudtrail"
    }
  ]
}
```

This benchmark finally defines public as a policy that has a SAML Identity Provider as the principal and _missing_ the condition which restricts the Identity Providers audience, such as `SAML:aud`, `SAML:iss`, `SAML:sub`, `SAML:sub_type` or `SAML:eduPersonOrgDN`, with at least one `Allow` statement that grants one or more permissions, e.g.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "sts:AssumeRoleWithSAML",
      "Principal": { "Federated": "arn:aws:iam::111122223333:saml-provider-1/provider-name" }
    }
  ]
}
```

For each statement, if there are any condition keys then these condition keys will be evaluated as follows:

The benchmark uses principals conditions, `aws:PrincipalAccount`, `aws:PrincipalArn` or `aws:PrincipalOrgID` in its evaluation of the policy by checking the values in the conditions against the values set by the Principal element of the policy.

If there is a condition that reduces the number of principals that allow access to a resource, the benchmark will calculate the reduced scope and use this value when running the benchmark controls.

The following policy is not considered public since the condition has restricted its access to account `111122223333`:

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

Similarly, for source conditions, `aws:SourceAccount`, `aws:SourceOwner`, `aws:SourceArn`.
The benchmark evaluates the values in the source conditions against the values set by the Principal element of the policy.
The benchmark will check to see that the Principal is an AWS service before applying these conditions as they are used to restrict the scope of AWS services.

The following policy is not considered public since the condition restricts service access to account `111122223333`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "cloudtrail.amazonaws.com"
      },
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:cloudtrail:us-east-1:111122221111:trail/example-cloudtrail",
      "Condition": {
        "StringEquals": {
          "aws:SourceAccount": "111122223333"
        }
      }
    }
  ]
}
```