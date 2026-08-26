import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cloud_iam_policy_auditor import audit, build_json_report, build_report, main

SAMPLES = Path(__file__).resolve().parent.parent / "sample_policies"


def load(name):
    with open(SAMPLES / name, "r", encoding="utf-8") as f:
        return json.load(f)


def test_full_admin_statement_flagged_high_and_not_duplicated():
    findings = audit(load("full_admin_example.json"))
    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"
    assert "Full administrator access" in findings[0]["reason"]


def test_passrole_ec2_pair_flagged_high():
    findings = audit(load("privesc_vectors_example.json"))
    assert any("iam:PassRole" in f["statement"] and "ec2:runinstances" in f["statement"] for f in findings)


def test_create_access_key_privesc_flagged():
    findings = audit(load("privesc_vectors_example.json"))
    assert any("iam:createaccesskey" in f["reason"] for f in findings)


def test_attach_user_policy_privesc_flagged():
    findings = audit(load("privesc_vectors_example.json"))
    assert any("iam:attachuserpolicy" in f["reason"] for f in findings)


def test_full_service_wildcard_flagged_medium_for_s3():
    findings = audit(load("privesc_vectors_example.json"))
    s3_findings = [f for f in findings if "s3" in f["reason"] and "Full access" in f["reason"]]
    assert s3_findings
    assert s3_findings[0]["severity"] == "MEDIUM"


def test_not_action_flagged_medium():
    findings = audit(load("privesc_vectors_example.json"))
    assert any(f["severity"] == "MEDIUM" and "NotAction" in f["reason"] for f in findings)


def test_wildcard_trust_policy_principal_flagged_high():
    findings = audit(load("trust_policy_public.json"))
    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"
    assert "Principal" in findings[0]["reason"]


def test_wildcard_principal_with_condition_not_flagged():
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"sts:ExternalId": "unique-id-123"}},
            }
        ],
    }
    assert audit(policy) == []


def test_least_privilege_policy_has_no_findings():
    findings = audit(load("least_privilege_example.json"))
    assert findings == []


def test_iam_service_wildcard_is_high_not_medium():
    policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "iam:*", "Resource": "*"}],
    }
    findings = audit(policy)
    assert any(f["severity"] == "HIGH" and "iam" in f["reason"] for f in findings)


def test_deny_statements_are_ignored():
    policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}],
    }
    assert audit(policy) == []


def test_build_report_lists_all_findings_in_markdown_table():
    findings = audit(load("privesc_vectors_example.json"))
    report = build_report(findings, "privesc_vectors_example.json")
    assert "HIGH" in report
    assert "MEDIUM" in report
    for f in findings:
        assert f["reason"].replace("|", "\\|") in report


def test_build_report_clean_policy_says_no_issues():
    report = build_report([], "least_privilege_example.json")
    assert "No issues found" in report


def test_json_report_is_valid_and_matches_findings():
    findings = audit(load("full_admin_example.json"))
    payload = json.loads(build_json_report(findings, "full_admin_example.json"))
    assert payload["source"] == "full_admin_example.json"
    assert payload["summary"]["high"] == len(findings)
    assert len(payload["findings"]) == len(findings)


def run_main(monkeypatch, tmp_path, policy_name, extra_args):
    out = str(tmp_path / "out.md")
    policy_path = str(SAMPLES / policy_name)
    argv = ["cloud_iam_policy_auditor.py", "--policy", policy_path, "--output", out] + extra_args
    monkeypatch.setattr(sys, "argv", argv)
    return main()


def test_fail_on_high_exits_nonzero_for_full_admin_policy(monkeypatch, tmp_path):
    assert run_main(monkeypatch, tmp_path, "full_admin_example.json", ["--fail-on", "high"]) == 1


def test_fail_on_high_exits_zero_for_least_privilege_policy(monkeypatch, tmp_path):
    assert run_main(monkeypatch, tmp_path, "least_privilege_example.json", ["--fail-on", "high"]) == 0


def test_fail_on_none_always_exits_zero(monkeypatch, tmp_path):
    assert run_main(monkeypatch, tmp_path, "full_admin_example.json", []) == 0
