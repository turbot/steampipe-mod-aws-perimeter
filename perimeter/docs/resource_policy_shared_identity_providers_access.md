This benchmark answers the following questions:

- What resources have resource policies that grant access to AWS identity providers?
- Which identity providers have been granted access are not trusted?

This benchmark defines shared as a policy having at least one `Allow` statement that grants one or more permission to a principal.
The benchmark exposes the variable `trusted_identity_providers` which can be used to set which identity providers are trusted.
The benchmark will use the variable `trusted_identity_providers` to check if the identity providers that are granted access by the policy are trusted identity providers and alarm if they are untrusted.

For example:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "sts:AssumeRoleWithSAML",
      "Principal": { "Federated": "arn:aws:iam::111122223333:saml-provider-1/provider-name" },
      "Condition": { "StringEquals": { "SAML:aud": ["test"] } }
    }
  ]
}
```

The above policy grants access based on the SAML identity provider `provider-name`.
If `arn:aws:iam::111122223333:saml-provider-1/provider-name` is a trusted identity provider, the benchmark will report that access has been granted to the identity provider and that it is trusted.
Otherwise, the benchmark will alarm and report that identity provider `arn:aws:iam::111122223333:saml-provider-1/provider-name` is untrusted.

When evaluating statements for public access, the following [condition keys](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html) are checked:

- `aws:PrincipalAccount`
- `aws:PrincipalArn`

And the following [condition operators](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html) are checked:

- `ArnLike`
- `ArnEquals`
- `StringEquals`
- `StringEqualsIgnoreCase`
- `StringLike`

For each statement, if there are any condition keys then these condition keys will be evaluated as follows:

The benchmark uses principals conditions, `aws:PrincipalAccount` and `aws:PrincipalArn` in its evaulation of the policy by checking the values in the principals conditions against the values set by the Principal element of the policy.

If there is a condition reduces the number of principals that allow access to a resource, the benchmark will calculate the reduced scope and use this value when running the benchmark controls.

The following example policy restricts access to account `111122223333` and identity provider `arn:aws:iam::111122223333:saml-provider-1/provider-name`.
The benchmark will use the value to test if the identity provider is a trusted identity provider:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowPublicAccess1",
      "Effect": "Allow",
      "Principal": { "Federated": "arn:aws:iam::111122223333:saml-provider-1/provider-name" },
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
