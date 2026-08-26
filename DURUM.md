# Durum Günlüğü

> En üstteki kayıt en güncelidir. Her çalışma sonrası buraya kısa bir not düşülür.

---

## 2026-08-21 — Proje oluşturuldu, test edildi, CI eklendi

- Konu: AWS IAM policy JSON dokümanlarını statik olarak denetleyen, bilinen privilege-escalation vektörlerini (iam:PassRole + ec2:RunInstances gibi) ve aşırı izinli statement'ları (Action:*/Resource:*, NotAction, wildcard trust-policy Principal) tespit eden CLI aracı. Portföydeki "cloud security" boşluğunu dolduruyor — diğer 11 proje ağ/log/LLM odaklıyken bu ilk bulut/IAM projesi.
- Dosya: `cloud_iam_policy_auditor.py`, 4 örnek policy (`full_admin_example.json`, `privesc_vectors_example.json`, `trust_policy_public.json`, `least_privilege_example.json`), `tests/test_cloud_iam_policy_auditor.py` (17 test), `pyproject.toml`, `.github/workflows/ci.yml`.
- Baştan itibaren eklenenler: `--format json`, `--fail-on {none,medium,high}` (portföydeki diğer projelerle tutarlı CI-gating deseni).
- Durum: ✅ 17/17 test gerçekten çalıştırılıp geçti, `ruff check .` temiz. CLI 4 örnek policy'ye karşı gerçekten çalıştırıldı: `full_admin_example.json` → 1 HIGH, `privesc_vectors_example.json` → 3 HIGH + 2 MEDIUM, `trust_policy_public.json` → 1 HIGH, `least_privilege_example.json` → 0 bulgu (temiz). `sample_report.md` bu gerçek çalıştırmalardan (`privesc_vectors_example.json`) üretildi. Henüz push edilmedi (repo local).

**Sıradaki iş:** GitHub'da `Cloud-IAM-Policy-Auditor` adıyla repo aç, git init + push.
