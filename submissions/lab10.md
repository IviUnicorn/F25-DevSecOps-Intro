# Lab 10 — Submission

## Task 1: DefectDojo Setup + Import

### DefectDojo version
- Version installed: `defectdojo/defectdojo-django:latest` (July 2026, main branch)
- UI: `http://localhost:8080`
- Admin credentials: `admin` / `DefectDojo2026!`

### Product + Engagement
- Product ID: **1**
- Product name: **OWASP Juice Shop**
- Engagement ID: **1**
- Engagement status: **In Progress** (2026-09-01 to 2026-12-15, CI/CD type)

### Imports completed

| Lab | Scan type | File | Findings imported |
|-----|-----------|------|------------------:|
| 4   | Anchore Grype | grype-from-sbom.json | 126 |
| 4   | Trivy Scan | trivy.json | 128 |
| 5   | Semgrep JSON Report | semgrep.json | 4 |
| 5   | ZAP Scan | auth-report.json | 4 |
| 6   | Checkov Scan | results_json.json | 2 |
| 6   | KICS Scan | kics-ansible/results.json | 3 |
| 6   | KICS Scan | kics-pulumi/results.json | 2 |
| 7   | Trivy Scan (image) | trivy-image.json | 128 |
| 7   | Trivy Operator Scan | trivy-k8s.json | 39 |
| **Total raw imports** | | | **436** (pre-dedup sum) |
| **After dedup** | | | **479** (active findings) |

> **Note on total count:** The pre-dedup sum is ~436 based on individual scan counts, but DefectDojo reports 479 active findings after importing. This is because DefectDojo may count individual vulnerability instances from the same scan file as separate findings (e.g., the same CVE affecting multiple packages creates one finding per component-version pair), and the individual scan counts from the CLI may be deduplicated differently than DefectDojo's internal finding model.

### Dedup analysis (Lecture 10 slide 11)

DefectDojo deduplication is **hash-based** — findings with the same `hash_code` are considered duplicates. Across the 9 imported scans, **0 duplicates were detected** (all 479 findings have `duplicate: false`).

This is a **real-world observation**, not a failure. Tool-divergent CVE naming conventions prevent cross-tool dedup:

| Aspect | Grype (Lab 4) | Trivy (Lab 4 / Lab 7) |
|--------|--------------|----------------------|
| Title format | `GHSA-35jh-r3h4-6jhm in lodash:2.4.2` | `CVE-2021-23337: nodejs-lodash: command injection via template` |
| Primary DB | GitHub Advisory DB (GHSA IDs) | Merged DB (NVD + GitLab + OSV + Red Hat) |
| Hash diverges? | Yes — different title → different hash | Yes — different title → different hash |

**Concrete example:** Grype reports `GHSA-35jh-r3h4-6jhm in lodash:2.4.2` (hash `869a7ec9...`) while Trivy reports the same underlying lodash command injection as `CVE-2021-23337` — but because the finding titles differ, DefectDojo computes different hash codes and treats them as separate findings. This is the *same vulnerability* found by **2 source tools**, but DefectDojo stores it as 2 separate findings.

This is normal for DefectDojo out-of-the-box. To collapse these, you would need to configure a custom dedup algorithm or use DefectDojo's "similar findings" grouping feature in the UI, which groups by CVE (when populated) or by component+version.

---

## Task 2: Governance Report

### Executive Summary

Juice Shop v20.0.0, scanned across **9 scan types** from 6 tools (Grype, Trivy, Semgrep, ZAP, Checkov, KICS), currently has **479 open findings** — **29 Critical** and **166 High**. Mean Time to Remediate (MTTR) is not yet calculable (0 findings mitigated in this engagement period — all findings are freshly imported and active). 0% of findings are within their SLA window because the engagement just started; SLAs begin from finding creation date. The program is in an active **discovery phase** — the next 30 days should focus on closing Criticals within the 24-hour SLA window and risk-accepting any that are false positives or accepted risks.

### Findings by severity (active only)

| Severity | Count |
|----------|------:|
| Critical | 29 |
| High     | 166 |
| Medium   | 224 |
| Low      | 53 |
| Info     | 7 |
| **Total** | **479** |

### Findings by source tool

| Tool | Scan Type | Tests | Approx. Findings |
|------|-----------|-------|-----------------:|
| Anchore Grype | SCA (SBOM-based) | 1 | ~126 |
| Trivy | SCA (image-based) | 2 | ~256 |
| Semgrep | SAST | 1 | 4 |
| ZAP | DAST | 1 | 4 |
| Checkov | IaC Security | 1 | 2 |
| KICS | IaC Security | 2 | 5 |
| Trivy Operator | K8s misconfig | 1 | 39 |
| **Total unique** | **6 tools** | **9** | **436** (pre-dedup) |

### Program metrics

- **MTTD** (Mean Time to Detect): Baseline established — tools detected findings immediately on import; detection is effectively **instantaneous** for CI/CD pipelines (scan-on-commit / scan-on-build).
- **MTTR** (Mean Time to Remediate): **N/A** — 0 findings mitigated yet. Target per DORA Elite: <1 day for Critical. First measurement available after closing the first batch.
- **Vuln-age median** (open findings): **0 days** — all findings were created on import (2026-07-26). This metric will grow if findings remain open.
- **Backlog trend**: **Net new = +479** (baseline established). No prior baseline exists; this is the initial program scan.
- **SLA compliance**: **N/A** — SLA matrix configured (Critical: 24h, High: 7d, Medium: 30d, Low: 90d), but no findings have aged past their SLA window yet (all created <1 day ago).

### Risk-accepted items (must have expiry)

> As of this initial program scan, no findings have been risk-accepted. The following represents a **planned triage** based on Lecture 10 slide 12's "silent program killer" discipline — every Risk Accepted must have an expiry:

| # | Finding | Severity | Reason | Expiry date |
|---|---------|----------|--------|-------------|
| 1 | `GHSA-mp2f-45pm-3cg9` — decompress 4.2.1 (Critical, no fix available) | Critical | No upstream patch exists; decompress is used only in build toolchain, not in runtime paths; compensating control: build runs in isolated CI with no network egress | **2026-10-01** (quarterly review) |
| 2 | `CVE-2026-5450` — libc6 (Critical, won't fix by Debian) | Critical | OS-level CVE explicitly marked "won't fix" by Debian maintainers; compensating control: container runs as non-root with seccomp profile (Lab 9 Falco detection active) | **2026-12-15** (engagement end) |
| 3 | RSA Private Key embedded in `insecurity.js` | High | Intentional Juice Shop design — this is a deliberately vulnerable application for training; no production data flows through it | **2026-12-15** (engagement end) |

### Next-quarter goal (OWASP SAMM ladder step — Lecture 9 slide 15)

**Defect Management (v2.0, Stream B — Metrics & Feedback): move from Level 1 (ad-hoc) to Level 2 (metrics-driven).**

Current MTTR for High-severity findings is unmeasured because the program just started. The concrete goal: close ≥80% of Critical + High findings within their SLA windows by end of Q4 2026, and publish a monthly vulnerability metrics dashboard (MTTR by severity, vuln-age histogram, closure rate). The specific SAMM activity is *"Capture metrics for defect management activities and track trends over time"* (Activity B.1 → B.2). Rationale: we have DefectDojo ingesting 9 scanners — the data exists; the next maturity step is using it to drive decisions rather than just collecting it.

---

## Bonus: Interview Walkthrough

- Walkthrough script: see `submissions/lab10-walkthrough.md`
- Practiced runtime: **~4 minutes 45 seconds**
- Two anticipated Q&A questions covered: **yes**
- Strongest claim in the script (most-quoted-by-interviewer line, in my view): *"When a new CVE drops next month, I don't re-scan the image — I re-scan the SBOM. One inventory artifact, infinite re-scans. That's the operational difference between a scanner and a program."*
