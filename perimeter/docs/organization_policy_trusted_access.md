This benchmark answers the following questions:

- Which SCPs and RCPs reference accounts that are not in the organization or in the `trusted_accounts` variable?
- Which SCPs and RCPs reference organizations other than this one or those in the `trusted_organizations` variable?
- Which SCPs exempt whole accounts or all roles instead of specific principals?

For example, an RCP copied from another organization with `"aws:PrincipalOrgID": "o-abcdhqk8mns"` would deny your own principals, and an SCP exemption such as `"ArnNotLike": {"aws:PrincipalArn": "arn:aws:iam::123456789012:*"}` turns the statement off for every principal in that account.
