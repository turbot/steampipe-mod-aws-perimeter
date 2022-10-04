This benchmark answers the following questions:

- What resources have resource policies that grant access to AWS services?
- Which services have been granted access and are not trusted?

This benchmark defines shared as a policy having at least one `Allow` statement that grants one or more permission to a principal.
The benchmark exposes the variable `trusted_services` which can be used to set which services are trusted.
The benchmark will use the variable `trusted_services` to check if the services that are granted access by the policy are trusted services and alarm if they are untrusted.

For example:

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

The above policy grants service access to AWS service `cloudtrail.amazonaws.com` from any account.
If `cloudtrail.amazonaws.com` is a trusted service, the benchmark will report that access has been granted to the service and that it is trusted.
Otherwise, the benchmark will alarm and report that the service `cloudtrail.amazonaws.com` is untrusted.

When evaluating statements for public access, the following [condition keys](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html) are checked:

- `aws:SourceAccount`
- `aws:SourceArn`
- `aws:SourceOwner`

And the following [condition operators](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html) are checked:

- `ArnLike`
- `ArnEquals`
- `StringEquals`
- `StringEqualsIgnoreCase`
- `StringLike`

Inverse condition operators, like `StringNotEquals` and `ArnNotLike`, are not currently evaluated.

For each statement, if there are any condition keys then these condition keys will be evaluated as follows:

The benchmark uses source conditions, `aws:SourceAccount`, `aws:SourceOwner`, `aws:SourceArn`.
The benchmark evaluates the values in the source conditions against the values set by the Principal element of the policy.
The benchmark will check to see that the Principal is an AWS service before applying these conditions as they are used to restrict the scope of AWS services.

The following policy is not considered public since the condition restricts service access to account `111122223333`.
The benchmark will use the value to test if the service is a trusted service:

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
