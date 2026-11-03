## Organization Policy Access

Service control policies (SCPs) and resource control policies (RCPs) set the outer boundary of what principals in member accounts can do and who can access their resources. The organization policy access benchmark checks that every member account inherits a baseline of SCPs and RCPs, that those policies only trust known accounts and organizations, and that they are attached, unique and within AWS Organizations quotas.

The controls in this benchmark query AWS Organizations, so they must be run with credentials for the organization's management account or a delegated administrator account. SCPs and RCPs do not apply to the management account, so account-level controls skip it.
