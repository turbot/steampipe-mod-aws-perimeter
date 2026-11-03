This benchmark answers the following questions:

- Which member accounts can leave the organization?
- Which member accounts have an unrestricted root user?
- Which member accounts are not restricted to approved regions, and which regions does each account allow?
- Which member accounts can stop or delete CloudTrail, AWS Config, GuardDuty, Security Hub or IAM Access Analyzer?
- Which member accounts can change their S3 account-level Block Public Access settings?
- Which member accounts have resources that can be accessed from outside the organization or without TLS?

A policy counts when it is attached to the root, to any OU on the account's path, or to the account itself. A deny statement satisfies a control when it applies to all resources and its only conditions exempt specific principals (for example `ArnNotLike` on `aws:PrincipalArn` for a break-glass role). A deny statement that only covers some resources or has other conditions is reported as `info`.
