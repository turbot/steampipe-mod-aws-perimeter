This benchmark answers the following questions:

- What resources have resource policies that allow untrusted identity providers access?

This benchmark defines shared as a policy having at least one `Allow` statement that grants one or more permissions to trusted identity providers, e.g.,

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::AWS-account-ID:saml-provider-1/provider-name"
      },
      "Action": ["s3:PutObject", "s3:PutObjectAcl"],
      "Resource": "*"
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
      "Principal": {
        "Federated": "accounts.google.com"
      },
      "Action": ["s3:PutObject", "s3:PutObjectAcl"],
      "Resource": "arn:aws:s3:::EXAMPLE-BUCKET/*",
      "Condition": {
        "StringEquals": {
          "accounts.google.com:aud": "test"
        }
      }
    }
  ]
}
```

When evaluating statements for shared access, the following [condition keys](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html) are checked:

- `aws:PrincipalAccount`
- `aws:PrincipalArn`
- `aws:PrincipalOrgID`
- `aws:SourceAccount`
- `aws:SourceArn`
- `aws:SourceOwner`

And the following [condition operators](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html) are checked:

- `ArnLike`
- `ArnEquals`
- `StringEquals`
- `StringEqualsIgnoreCase`
- `StringLike`

For each statement, if there are any condition keys then these condition keys will be evaluated as follows:

Principals conditions are checked against the Policy Principals.
If Principals conditions have smaller scope that the Policy Principals then the analyzer will reduce the scopeage.
If Principals conditions have larger scope that the Policy Principals then the analyzer will leave the Policy Principals unchanged.
If Principals conditions have a scope that doesn't contain the the Policy Principals then the analyzer will return this as invalid.

Source conditions are used to reduce AWS services, which are public in nature, to limit their scopeage to specified Principals.
The policy analyser will use these conditions to determine if the service is public and has no valid Source conditions or shared where valid Source conditions exist.

Inverse condition operators, like `StringNotEquals` and `ArnNotLike`, are not currently evaluated.
