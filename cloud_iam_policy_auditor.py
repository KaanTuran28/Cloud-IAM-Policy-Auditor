#!/usr/bin/env python3
"""Static audit of an AWS IAM policy JSON document.

Flags overly permissive statements (wildcard actions/resources, NotAction/
NotResource, public trust-policy principals) and known IAM privilege-
escalation vectors (e.g. iam:PassRole + ec2:RunInstances). Purely offline —
no AWS API calls, no credentials required. Works on identity policies,
resource policies, and role trust ("assume role") policies, since they all
share the same {"Version", "Statement": [...]} document shape.
"""

import argparse
import fnmatch
import json
import sys

# Actions that, granted alone on a broad resource, let a caller escalate
# their own privileges. Non-exhaustive but covers the most common vectors
# documented by AWS security researchers (see README for references).
PRIVESC_SINGLE_ACTIONS = {
    "iam:createpolicyversion": "can create a new default version of any attached managed policy with arbitrary permissions",
    "iam:setdefaultpolicyversion": "can roll back to a previously saved policy version that may grant broader permissions",
    "iam:createaccesskey": "can create a new access key for any IAM user, including privileged ones",
    "iam:createloginprofile": "can set a console password for a user that doesn't have one, enabling console takeover",
    "iam:updateloginprofile": "can reset the console password of any IAM user, enabling account takeover",
    "iam:attachuserpolicy": "can attach an administrator-level managed policy directly to any user, including itself",
    "iam:attachgrouppolicy": "can attach an administrator-level managed policy to any group the caller belongs to",
    "iam:attachrolepolicy": "can attach an administrator-level managed policy to any role, then assume or pass it",
    "iam:putuserpolicy": "can embed an inline administrator-level policy directly on any user, including itself",
    "iam:putgrouppolicy": "can embed an inline administrator-level policy on any group the caller belongs to",
    "iam:putrolepolicy": "can embed an inline administrator-level policy on any role",
    "iam:addusertogroup": "can add itself (or any user) to a privileged IAM group",
    "iam:updateassumerolepolicy": "can rewrite a role's trust policy to allow the caller to assume it",
}

# iam:PassRole is only exploitable paired with a service action that attaches
# the passed role to a new resource and lets the caller retrieve/use its
# credentials.
PASSROLE_PIVOTS = {
    "ec2:runinstances": "launch an EC2 instance with an attached instance profile role and retrieve its credentials from the metadata service",
    "lambda:createfunction": "create a Lambda function with an attached execution role and invoke it to use those credentials",
    "glue:createdevendpoint": "create a Glue dev endpoint with an attached role and reach it (e.g. via SSH) for its credentials",
    "datapipeline:createpipeline": "create a Data Pipeline with an attached role to run arbitrary commands as that role",
    "cloudformation:createstack": "create a CloudFormation stack with an attached role to provision resources under that identity",
    "sagemaker:createnotebookinstance": "create a SageMaker notebook with an attached role and reach its credentials via the Jupyter terminal",
}

# Full-service wildcards (e.g. "iam:*") on Resource "*" for these services
# are treated as HIGH rather than MEDIUM — they're effectively account takeover.
SENSITIVE_SERVICE_WILDCARDS = {"iam", "organizations", "sts", "kms"}


def as_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def statement_actions(stmt: dict) -> list:
    return [a.lower() for a in as_list(stmt.get("Action")) if isinstance(a, str)]


def describe_statement(stmt: dict) -> str:
    if stmt.get("Sid"):
        return stmt["Sid"]
    actions = as_list(stmt.get("Action")) or as_list(stmt.get("NotAction"))
    resources = as_list(stmt.get("Resource")) or as_list(stmt.get("NotResource"))
    return f"Action={actions} Resource={resources}"


def finding(severity: str, statement_label: str, reason: str, recommendation: str) -> dict:
    return {
        "severity": severity,
        "statement": statement_label,
        "reason": reason,
        "recommendation": recommendation,
    }


def audit(policy: dict) -> list:
    findings = []
    statements = as_list(policy.get("Statement"))
    allow_statements = [s for s in statements if isinstance(s, dict) and s.get("Effect") == "Allow"]

    for stmt in allow_statements:
        actions = statement_actions(stmt)
        resources = as_list(stmt.get("Resource"))
        label = describe_statement(stmt)

        if "*" in actions and "*" in resources:
            # Blanket admin already implies every check below — report it once
            # and move on instead of enumerating dozens of redundant vectors.
            findings.append(finding(
                "HIGH", label,
                'Full administrator access: Action "*" + Resource "*" in a single Allow statement.',
                'Scope the statement to specific actions and resource ARNs; never grant blanket "*"/"*".',
            ))
            continue
        if "*" in actions:
            findings.append(finding(
                "HIGH", label,
                'Wildcard action ("*") grants every AWS API action, even though Resource is scoped.',
                "Enumerate only the specific actions this statement actually needs.",
            ))
            continue

        if "*" in resources:
            for action in actions:
                if action.endswith(":*"):
                    service = action.split(":")[0]
                    severity = "HIGH" if service in SENSITIVE_SERVICE_WILDCARDS else "MEDIUM"
                    findings.append(finding(
                        severity, label,
                        f'Full access to all "{service}" actions on all resources ("{action}" + Resource "*").',
                        f"Scope down to only the {service} actions and resource ARNs actually required.",
                    ))

        if "NotAction" in stmt:
            findings.append(finding(
                "MEDIUM", label,
                '"NotAction" with Effect Allow implicitly grants every action except the ones listed — broad and hard to audit.',
                'Prefer an explicit "Action" allowlist instead of "NotAction".',
            ))
        if "NotResource" in stmt:
            findings.append(finding(
                "MEDIUM", label,
                '"NotResource" with Effect Allow implicitly grants access to every resource except the ones listed.',
                'Prefer an explicit "Resource" allowlist instead of "NotResource".',
            ))

        if "*" in resources:
            for target, description in PRIVESC_SINGLE_ACTIONS.items():
                if any(fnmatch.fnmatch(target, pattern) for pattern in actions):
                    findings.append(finding(
                        "HIGH", label,
                        f'Privilege escalation vector: "{target}" on Resource "*" — {description}.',
                        "Restrict the resource to specific ARNs and/or add a Condition to limit blast radius.",
                    ))

    resource_star_actions = set()
    for stmt in allow_statements:
        if "*" in as_list(stmt.get("Resource")):
            resource_star_actions.update(a for a in statement_actions(stmt) if a != "*")

    def is_granted(target: str) -> bool:
        return any(fnmatch.fnmatch(target, pattern) for pattern in resource_star_actions)

    if is_granted("iam:passrole"):
        for pivot_action, description in PASSROLE_PIVOTS.items():
            if is_granted(pivot_action):
                findings.append(finding(
                    "HIGH", f'iam:PassRole + {pivot_action} (both on Resource "*")',
                    f'"iam:PassRole" combined with "{pivot_action}" lets a caller {description}.',
                    "Restrict iam:PassRole to specific role ARNs (Resource) and/or an iam:PassedToService condition.",
                ))

    for stmt in statements:
        if not isinstance(stmt, dict) or stmt.get("Effect") != "Allow":
            continue
        principal = stmt.get("Principal")
        if principal is None:
            continue
        is_wildcard_principal = principal == "*" or (
            isinstance(principal, dict) and as_list(principal.get("AWS")) == ["*"]
        )
        if is_wildcard_principal and "Condition" not in stmt:
            findings.append(finding(
                "HIGH", describe_statement(stmt),
                'Principal "*" with no Condition allows ANY AWS account (or an anonymous caller) to assume/use this role.',
                "Restrict Principal to specific account/role ARNs, or add a Condition "
                "(e.g. sts:ExternalId, aws:PrincipalOrgID).",
            ))

    return findings


def build_report(findings: list, source: str) -> str:
    high = [f for f in findings if f["severity"] == "HIGH"]
    medium = [f for f in findings if f["severity"] == "MEDIUM"]

    lines = [
        "# Cloud IAM Policy Audit Report",
        "",
        f"- **Source:** {source}",
        f"- **Findings:** {len(high)} HIGH, {len(medium)} MEDIUM",
        "",
    ]
    if findings:
        lines += ["| Severity | Statement | Reason | Recommendation |", "|---|---|---|---|"]
        ordered = sorted(findings, key=lambda f: (f["severity"] != "HIGH", f["statement"]))
        for f in ordered:
            statement = f["statement"].replace("|", "\\|")
            reason = f["reason"].replace("|", "\\|")
            recommendation = f["recommendation"].replace("|", "\\|")
            lines.append(f"| {f['severity']} | {statement} | {reason} | {recommendation} |")
    else:
        lines.append("No issues found — this policy looks tightly scoped.")
    lines.append("")
    return "\n".join(lines)


def build_json_report(findings: list, source: str) -> str:
    high = sum(1 for f in findings if f["severity"] == "HIGH")
    medium = sum(1 for f in findings if f["severity"] == "MEDIUM")
    payload = {
        "source": source,
        "summary": {"high": high, "medium": medium},
        "findings": findings,
    }
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


def main():
    parser = argparse.ArgumentParser(
        description="Static audit of an AWS IAM policy JSON document for overly permissive "
                    "statements and privilege-escalation vectors."
    )
    parser.add_argument("--policy", required=True, help="Path to an IAM policy JSON document.")
    parser.add_argument("--output", default="sample_report.md", help="Path to write the report.")
    parser.add_argument(
        "--format", choices=["markdown", "json"], default="markdown", help="Output report format."
    )
    parser.add_argument(
        "--fail-on",
        choices=["none", "medium", "high"],
        default="none",
        help="Exit with code 1 if findings at/above this severity are present (for CI gating).",
    )
    args = parser.parse_args()

    with open(args.policy, "r", encoding="utf-8") as fh:
        policy = json.load(fh)

    findings = audit(policy)
    report = (
        build_json_report(findings, args.policy)
        if args.format == "json"
        else build_report(findings, args.policy)
    )

    with open(args.output, "w", encoding="utf-8") as fh:
        fh.write(report)

    high_count = sum(1 for f in findings if f["severity"] == "HIGH")
    medium_count = sum(1 for f in findings if f["severity"] == "MEDIUM")
    print(f"Audited {args.policy}: {high_count} HIGH, {medium_count} MEDIUM finding(s).")
    print(f"Report written to {args.output}")

    if args.fail_on == "high" and high_count > 0:
        return 1
    if args.fail_on == "medium" and (high_count > 0 or medium_count > 0):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
