# Cloud IAM Policy Audit Report

- **Source:** sample_policies/privesc_vectors_example.json
- **Findings:** 3 HIGH, 2 MEDIUM

| Severity | Statement | Reason | Recommendation |
|---|---|---|---|
| HIGH | AttachAnyManagedPolicy | Privilege escalation vector: "iam:attachuserpolicy" on Resource "*" — can attach an administrator-level managed policy directly to any user, including itself. | Restrict the resource to specific ARNs and/or add a Condition to limit blast radius. |
| HIGH | CreateAccessKeyForAnyUser | Privilege escalation vector: "iam:createaccesskey" on Resource "*" — can create a new access key for any IAM user, including privileged ones. | Restrict the resource to specific ARNs and/or add a Condition to limit blast radius. |
| HIGH | iam:PassRole + ec2:runinstances (both on Resource "*") | "iam:PassRole" combined with "ec2:runinstances" lets a caller launch an EC2 instance with an attached instance profile role and retrieve its credentials from the metadata service. | Restrict iam:PassRole to specific role ARNs (Resource) and/or an iam:PassedToService condition. |
| MEDIUM | EverythingExceptBilling | "NotAction" with Effect Allow implicitly grants every action except the ones listed — broad and hard to audit. | Prefer an explicit "Action" allowlist instead of "NotAction". |
| MEDIUM | FullS3Access | Full access to all "s3" actions on all resources ("s3:*" + Resource "*"). | Scope down to only the s3 actions and resource ARNs actually required. |
