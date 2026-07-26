# 5-Minute DevSecOps Program Walkthrough — Juice Shop

## (0:00–0:30) Context

> "I built an end-to-end DevSecOps program around OWASP Juice Shop as the target application — it's an intentionally vulnerable Node.js app that's the industry standard for security training. Across the pipeline I deployed 6 tools — Syft, Grype, Trivy, Semgrep, ZAP, Checkov, KICS, Falco, and Cosign — all feeding into DefectDojo as the unified vulnerability management plane. Every commit is SSH-signed, every image has an SBOM, every finding has an SLA."

## (0:30–2:00) Layers

> "Let me walk you through the layers from left to right — pre-commit through runtime.

> **Pre-commit** — I have Gitleaks blocking secrets before they hit the repo, and SSH-signed commits for non-repudiation. If a developer accidentally commits an AWS key, it never reaches GitHub.

> **Build** — Syft generates both CycloneDX and SPDX SBOMs from the container image. Grype scans that SBOM for CVEs — the decoupled pattern, so one SBOM serves infinite re-scans without re-pulling the image. Semgrep runs SAST on the source tree. Between them, I'm catching both dependency vulnerabilities and code-level flaws.

> **Pre-deploy** — Checkov and KICS scan the Terraform, Ansible, and Pulumi IaC for misconfigurations: overly permissive security groups, missing encryption, containers running as root. Cosign signs the image and Conftest gates the deploy — if the image isn't signed or the pod spec violates policy, it doesn't reach the cluster.

> **Runtime** — Falco with eBPF monitors for terminal shells in containers, unexpected process spawning, and cryptominer indicators. If someone shells into the Juice Shop container at 3am, I get an alert in seconds.

> **Program** — DefectDojo aggregates all of this: 479 findings across 9 scan types, deduplicated by hash, triaged by severity, tracked against an SLA matrix — Critical: 24 hours, High: 7 days. One dashboard, one source of truth."

## (2:00–3:00) Findings + Closures

> "Here's what actually mattered. We found 29 Critical findings. The top one — jsonwebtoken at version 0.1.0 — that's a critical auth bypass vulnerability. The fix is clear: upgrade to 4.2.2+. But not everything is patchable — decompress at 4.2.1 has a Critical CVE with *no fix available*, and libc6 has a Critical marked 'won't fix' by Debian. For those, the answer isn't upgrading — it's compensating controls: runtime Falco detection, seccomp profiles, and explicit risk acceptance with an expiry date.

> I risk-accepted 3 findings: the two no-fix Criticals with documented compensating controls, and the RSA private key embedded in `insecurity.js` — that's intentional Juice Shop design, not a real vulnerability. Each has an expiry date — the 'silent program killer' rule from Lecture 10: every risk acceptance must expire or you're just ignoring problems forever.

> The strongest correlated finding across tools was lodash 2.4.2 — caught by both Grype and Trivy, with prototype pollution and command injection vectors. Semgrep didn't catch it because it's a dependency-level issue, not a code pattern — which is exactly why we layer SCA and SAST."

## (3:00–4:00) Metrics

> "Here are the numbers. MTTD is effectively zero — every scan runs on commit, so detection is instantaneous. MTTR is not yet measurable — we're in the discovery phase, 479 findings, 0 closed. But the target is DORA Elite: less than one day for Criticals.

> Vulnerability age median is zero days right now — everything was discovered on the initial scan. That number will grow and that's exactly what we track: if median age trends up month-over-month, the program is losing. SLA compliance is 0% because the engagement just started, but the matrix is in place — 24 hours, 7 days, 30 days, 90 days — and DefectDojo's breach notifications will flag overdue findings automatically.

> Backlog is our baseline: +479 from the initial scan. The trend from here tells the story."

## (4:00–4:30) Next Steps

> "If I had another quarter, I'd ship one thing: SAMM Level 2 Defect Management — moving from collecting data to acting on it. That means publishing a monthly metrics dashboard — MTTR by severity, vuln-age histogram, closure rate — and setting a concrete target: 80% of Critical+High findings closed within their SLA by end of quarter. Second priority: adding a custom DefectDojo parser for Falco alerts, so runtime findings flow into the same triage pipeline as build-time findings. Right now Falco alerts are separate — unifying them means one SLA matrix for everything."

## (4:30–5:00) Q&A Anticipation

**Q1: "How would you handle a Log4Shell scenario?"**

> "Log4Shell is exactly why the decoupled SBOM model matters. Here's the timeline: a new Critical CVE drops — say another Log4j RCE. I don't re-scan the image. I don't re-build. I run `grype sbom:juice-shop.cdx.json` against the already-committed SBOM. In under 30 seconds, I know whether my 3,069 components include log4j and what version. If affected, I check the SBOM for *where* it's used — is it a direct dependency or transitive? — and patch accordingly. The response time difference is: pull image + scan + analyze vs. scan SBOM + analyze. The SBOM is the difference between 'we're checking' and 'we know.'"

**Q2: "Why didn't you use IAST or paid enterprise tools?"**

> "Honest answer: this is an open-source pipeline by design. Every tool — Syft, Grype, Trivy, Semgrep, ZAP, Checkov, KICS, Falco, Cosign, DefectDojo — is free and open-source. That's the DevSecOps philosophy I'm demonstrating: you don't need a six-figure license to have a real program. IAST would add runtime code analysis depth, and in a production environment with real traffic I'd absolutely evaluate Contrast or similar. But for a capstone project, the open-source stack proves the architecture: SBOM → SCA → SAST → DAST → IaC → Sign → Runtime Detect → Unified Triage. Add IAST and paid DAST as budget allows — the pipeline shape doesn't change."
