# Cloud IAM Policy Auditor

![CI](https://github.com/KaanTuran28/Cloud-IAM-Policy-Auditor/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

<p align="center"><b><a href="#english">English</a></b> · <b><a href="#türkçe">Türkçe</a></b></p>

---

## English

A static audit tool for AWS IAM policy JSON documents. It flags overly permissive statements and known IAM **privilege-escalation vectors** — entirely offline, with no AWS credentials or API calls involved.

### Overview

Given an IAM policy document (identity policy, resource policy, or role trust policy — they all share the same `{"Version", "Statement": [...]}` shape), the tool checks every `Allow` statement for the patterns a cloud security engineer would look for in a manual review:

- Blanket admin access (`Action: "*"` + `Resource: "*"`)
- Full-service wildcards (`iam:*`, `s3:*`, ...) on `Resource: "*"`
- `NotAction` / `NotResource` (implicit, hard-to-audit broad grants)
- Known **single-action privilege-escalation vectors** (e.g. `iam:CreateAccessKey`, `iam:AttachUserPolicy`, `iam:PutRolePolicy`, `iam:UpdateAssumeRolePolicy`, ...)
- The classic **`iam:PassRole` + pivot** combination (e.g. `+ ec2:RunInstances`, `+ lambda:CreateFunction`, `+ glue:CreateDevEndpoint`) that lets a caller attach a privileged role to a new resource and harvest its credentials
- A wildcard `Principal` (`"*"` or `{"AWS": "*"}`) with no `Condition` on a trust policy — anyone can assume the role

These are the same escalation paths documented in AWS IAM security research (see [Rhino Security Labs' AWS privilege escalation methods](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/)) and covered by tools like Prowler / ScoutSuite / PMapper.

### Installation

Requires Python 3.9+. No external dependencies.

```bash
git clone <this-repo>
cd Cloud-IAM-Policy-Auditor
pip install -e .
```

This installs a `cloud-iam-policy-auditor` command. You can also run the script directly with `python cloud_iam_policy_auditor.py` without installing.

### Usage

```bash
cloud-iam-policy-auditor --policy sample_policies/privesc_vectors_example.json --output report.md
cloud-iam-policy-auditor --policy sample_policies/privesc_vectors_example.json --format json --output report.json
```

| Flag | Default | Description |
|---|---|---|
| `--policy` | *(required)* | Path to an IAM policy JSON document |
| `--output` | `sample_report.md` | Path to write the report |
| `--format` | `markdown` | `markdown` or `json` |
| `--fail-on` | `none` | `none`, `medium`, or `high` — exit code `1` if a finding at/above this severity exists |

### CI Integration

Run this against every policy change in a Terraform/CloudFormation/CDK repo before it's applied:

```bash
cloud-iam-policy-auditor --policy iam/policies/deploy-role.json --fail-on high
```

```yaml
# GitHub Actions step
- name: Audit IAM policy changes
  run: cloud-iam-policy-auditor --policy iam/policies/deploy-role.json --fail-on high
```

Default is `none` (always exits `0`) so ad-hoc audits are unaffected.

### Sample Policies

| File | What it demonstrates | Findings |
|---|---|---|
| [`full_admin_example.json`](./sample_policies/full_admin_example.json) | `Action: "*"` + `Resource: "*"` | 1 HIGH |
| [`privesc_vectors_example.json`](./sample_policies/privesc_vectors_example.json) | `PassRole`+`RunInstances`, `CreateAccessKey`, `AttachUserPolicy`, `s3:*`, `NotAction` | 3 HIGH, 2 MEDIUM |
| [`trust_policy_public.json`](./sample_policies/trust_policy_public.json) | Wildcard `Principal` with no `Condition` on a role trust policy | 1 HIGH |
| [`least_privilege_example.json`](./sample_policies/least_privilege_example.json) | Tightly-scoped resource ARNs + a `Condition` | 0 findings |

See [`sample_report.md`](./sample_report.md) — real output from running the tool against `privesc_vectors_example.json`.

### Limitations

This is a **static**, heuristic analyzer — it does not call the AWS API, does not resolve policy variables (`${aws:userid}`), and does not evaluate the *effective* permissions across multiple attached/inherited policies (that requires a full IAM policy simulator). A statement scoped to a specific resource ARN is treated as intentionally restricted and is not flagged, even if that ARN happens to be sensitive.

### Testing

```bash
pip install -r requirements-dev.txt
ruff check .
pytest -v
```

### Project Structure

```
Cloud-IAM-Policy-Auditor/
├── cloud_iam_policy_auditor.py
├── pyproject.toml
├── sample_policies/
│   ├── full_admin_example.json
│   ├── privesc_vectors_example.json
│   ├── trust_policy_public.json
│   └── least_privilege_example.json
├── sample_report.md
├── tests/
│   └── test_cloud_iam_policy_auditor.py
├── .github/workflows/ci.yml
├── requirements.txt
├── requirements-dev.txt
├── LICENSE
└── DURUM.md
```

### License

MIT — see [LICENSE](./LICENSE).

---

## Türkçe

AWS IAM policy JSON belgeleri için statik bir denetim aracı. Aşırı izinli statement'ları ve bilinen IAM **yetki yükseltme (privilege-escalation) vektörlerini** işaretler — tamamen çevrimdışı çalışır, AWS kimlik bilgisi veya API çağrısı gerektirmez.

### Genel Bakış

Bir IAM policy belgesi verildiğinde (identity policy, resource policy veya role trust policy — hepsi aynı `{"Version", "Statement": [...]}` yapısını paylaşır), araç her `Allow` statement'ını, bir bulut güvenlik mühendisinin manuel incelemede arayacağı kalıplar açısından kontrol eder:

- Toptan yönetici erişimi (`Action: "*"` + `Resource: "*"`)
- `Resource: "*"` üzerinde tam servis wildcard'ları (`iam:*`, `s3:*`, ...)
- `NotAction` / `NotResource` (örtük, denetlenmesi zor geniş yetkiler)
- Bilinen **tek eylemlik yetki yükseltme vektörleri** (ör. `iam:CreateAccessKey`, `iam:AttachUserPolicy`, `iam:PutRolePolicy`, `iam:UpdateAssumeRolePolicy`, ...)
- Bir çağıranın ayrıcalıklı bir rolü yeni bir kaynağa bağlayıp kimlik bilgilerini toplamasına izin veren klasik **`iam:PassRole` + pivot** kombinasyonu (ör. `+ ec2:RunInstances`, `+ lambda:CreateFunction`, `+ glue:CreateDevEndpoint`)
- Bir trust policy'de `Condition` olmadan wildcard `Principal` (`"*"` veya `{"AWS": "*"}`) — herkes rolü assume edebilir

Bunlar, AWS IAM güvenlik araştırmalarında belgelenen (bkz. [Rhino Security Labs'ın AWS privilege escalation yöntemleri](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/)) ve Prowler / ScoutSuite / PMapper gibi araçlarca kapsanan aynı yükseltme yollarıdır.

### Kurulum

Python 3.9+ gerektirir. Harici bağımlılık yoktur.

```bash
git clone <this-repo>
cd Cloud-IAM-Policy-Auditor
pip install -e .
```

Bu, bir `cloud-iam-policy-auditor` komutu kurar. Kurulum yapmadan da doğrudan `python cloud_iam_policy_auditor.py` ile çalıştırabilirsiniz.

### Kullanım

```bash
cloud-iam-policy-auditor --policy sample_policies/privesc_vectors_example.json --output report.md
cloud-iam-policy-auditor --policy sample_policies/privesc_vectors_example.json --format json --output report.json
```

| Flag | Varsayılan | Açıklama |
|---|---|---|
| `--policy` | *(zorunlu)* | Bir IAM policy JSON belgesinin yolu |
| `--output` | `sample_report.md` | Raporun yazılacağı yol |
| `--format` | `markdown` | `markdown` veya `json` |
| `--fail-on` | `none` | `none`, `medium` veya `high` — bu önem derecesinde/üzerinde bir bulgu varsa çıkış kodu `1` |

### CI Entegrasyonu

Bunu, bir Terraform/CloudFormation/CDK deposundaki her policy değişikliğine karşı, uygulanmadan önce çalıştırın:

```bash
cloud-iam-policy-auditor --policy iam/policies/deploy-role.json --fail-on high
```

```yaml
# GitHub Actions step
- name: Audit IAM policy changes
  run: cloud-iam-policy-auditor --policy iam/policies/deploy-role.json --fail-on high
```

Varsayılan `none`'dır (her zaman `0` ile çıkar), böylece ad-hoc denetimler etkilenmez.

### Örnek Policy'ler

| Dosya | Gösterdiği | Bulgular |
|---|---|---|
| [`full_admin_example.json`](./sample_policies/full_admin_example.json) | `Action: "*"` + `Resource: "*"` | 1 HIGH |
| [`privesc_vectors_example.json`](./sample_policies/privesc_vectors_example.json) | `PassRole`+`RunInstances`, `CreateAccessKey`, `AttachUserPolicy`, `s3:*`, `NotAction` | 3 HIGH, 2 MEDIUM |
| [`trust_policy_public.json`](./sample_policies/trust_policy_public.json) | Bir role trust policy'de `Condition` olmadan wildcard `Principal` | 1 HIGH |
| [`least_privilege_example.json`](./sample_policies/least_privilege_example.json) | Sıkı kapsamlı kaynak ARN'leri + bir `Condition` | 0 bulgu |

Aracın `privesc_vectors_example.json`'a karşı çalıştırılmasından elde edilen gerçek çıktı için [`sample_report.md`](./sample_report.md) dosyasına bakın.

### Sınırlamalar

Bu, **statik**, sezgisel (heuristic) bir analiz aracıdır — AWS API'sini çağırmaz, policy değişkenlerini (`${aws:userid}`) çözümlemez ve birden fazla ekli/miras alınmış policy arasındaki *etkin (effective)* izinleri değerlendirmez (bunun için tam bir IAM policy simülatörü gerekir). Belirli bir kaynak ARN'ine kapsamlanmış bir statement, o ARN hassas olsa bile kasıtlı olarak kısıtlanmış kabul edilir ve işaretlenmez.

### Test

```bash
pip install -r requirements-dev.txt
ruff check .
pytest -v
```

### Proje Yapısı

```
Cloud-IAM-Policy-Auditor/
├── cloud_iam_policy_auditor.py
├── pyproject.toml
├── sample_policies/
│   ├── full_admin_example.json
│   ├── privesc_vectors_example.json
│   ├── trust_policy_public.json
│   └── least_privilege_example.json
├── sample_report.md
├── tests/
│   └── test_cloud_iam_policy_auditor.py
├── .github/workflows/ci.yml
├── requirements.txt
├── requirements-dev.txt
├── LICENSE
└── DURUM.md
```

### Lisans

MIT — bkz. [LICENSE](./LICENSE).

---
