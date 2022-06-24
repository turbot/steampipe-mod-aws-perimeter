This benchmark answers the following questions:

- What resources have resource policies that allow public access?

This benchmark defines public as a policy having at least one `Allow` statement that grants one or more permission to the `*` principal, e.g.,

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
            "Action": [
                "s3:PutObject",
                "s3:PutObjectAcl"
            ],
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
            "Action": [
                "s3:PutObject",
                "s3:PutObjectAcl"
            ],
            "Resource": "arn:aws:s3:::EXAMPLE-BUCKET/*"
        }
    ]
}
```

When evaluating statements for public access, the following [condition keys](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html) are checked:
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

For each statement, if there are any condition keys with any of the condition operators present then the statement is not considered to be granting public access. An extra check is performed for the `ArnLike` and `StringLike` operators to ensure that the condition key values do not contain `*`.

The inverse condition operators, like `StringNotEquals` and `ArnNotLike`, are not currently evaluated.
