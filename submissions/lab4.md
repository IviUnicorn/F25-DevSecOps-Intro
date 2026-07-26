# Lab 4 — Submission

## Task 1: Syft + Grype on Juice Shop

### SBOM stats
- `juice-shop.cdx.json` component count: **3,069**
- `juice-shop.cdx.json` size: **1.8 MB**
- `juice-shop.spdx.json` package count: **909**
- `juice-shop.spdx.json` size: **3.1 MB**

### Grype severity breakdown

| Severity | Count |
|----------|------:|
| Critical | 11 |
| High     | 58 |
| Medium   | 43 |
| Low      | 7 |
| Negligible | 7 |
| **Total** | **126** |

### Top 10 CVEs (by severity)

| CVE | Severity | Package | Installed | Fix |
|-----|----------|---------|-----------|-----|
| GHSA-c7hr-j4mj-j2w6 | Critical | jsonwebtoken | 0.1.0 | 4.2.2 |
| GHSA-c7hr-j4mj-j2w6 | Critical | jsonwebtoken | 0.4.0 | 4.2.2 |
| GHSA-jf85-cpcp-j695 | Critical | lodash | 2.4.2 | 4.17.12 |
| GHSA-xwcq-pm8m-c4vf | Critical | crypto-js | 3.3.0 | 4.2.0 |
| GHSA-mp2f-45pm-3cg9 | Critical | decompress | 4.2.1 | — |
| CVE-2026-5450 | Critical | libc6 | 2.41-12+deb13u2 | *(won't fix)* |
| GHSA-23hp-3jrh-7fpw | Critical | tar | 4.4.19 | 7.5.19 |
| GHSA-23hp-3jrh-7fpw | Critical | tar | 6.2.1 | 7.5.19 |
| GHSA-23hp-3jrh-7fpw | Critical | tar | 7.5.15 | 7.5.19 |
| CVE-2026-34182 | Critical | libssl3t64 | 3.5.5-1~deb13u2 | 3.5.6-1~deb13u2 |

### Fix-available rate

Out of the top 10 CVE entries (8 unique CVEs), **6 have a fix available** (75%). The two without fixes are `GHSA-mp2f-45pm-3cg9` (decompress — no fix published) and `CVE-2026-5450` (libc6 — explicitly marked "won't fix" by Debian). 

Following Lecture 4's triage shortcut — *sort by fix-available AND severity ≥ HIGH first* — the actionable items are the jsonwebtoken, lodash, crypto-js, and tar Critical CVEs. These all have clear upgrade paths (e.g., jsonwebtoken → 4.2.2+, lodash → 4.17.12+, crypto-js → 4.2.0+, tar → 7.5.19). The libc6 "won't fix" Critical warrants a compensating control (e.g., seccomp profile or runtime detection), since OS-level patches aren't coming for that package in this Debian release. The decompress CVE (Critical, no fix) is the highest-risk outlier — if decompress is used on untrusted input, it should be replaced or sandboxed, since no patched version exists.

---

## Task 2: Trivy Comparison

### Side-by-side counts

| Severity | Grype | Trivy | Δ |
|----------|------:|------:|--:|
| Critical | 11 | 9 | −2 |
| High     | 58 | 50 | −8 |
| Medium   | 43 | 46 | +3 |
| Low      | 7 | 23 | +16 |
| Negligible | 7 | 0 | −7 |
| **Total** | **126** | **128** | **+2** |

> Note: Trivy does not report a "Negligible" severity tier. Those 7 findings appear under Trivy's LOW or are filtered out entirely depending on DB mapping.

### Why the difference?

**CVE 1: GHSA-35jh-r3h4-6jhm — Grype found it, Trivy missed it**

- **Grype:** Reports `GHSA-35jh-r3h4-6jhm` as **High** severity — "Command Injection in lodash" affecting lodash 2.4.2, fixed in 4.17.21.
- **Trivy:** Does not list this GHSA ID. Instead, Trivy reports `CVE-2021-23337` for the same lodash version with the title "nodejs-lodash: command injection via template" — a different CVE ID mapping the same underlying vulnerability.
- **Why:** Grype uses the GitHub Advisory Database (GHSA) as its primary identifier namespace and maps CVEs to GHSA IDs. Trivy uses its own merged vulnerability database that cross-references multiple sources (NVD, GitLab, Red Hat, etc.) but may map the same flaw to a different primary CVE ID. This is a **CVE mapping divergence**, not a detection gap — both tools see the vulnerability but label it differently.

**CVE 2: CVE-2018-16487 — Trivy found it, Grype missed it**

- **Trivy:** Reports `CVE-2018-16487` as **HIGH** — "lodash: Prototype pollution in utilities function" affecting lodash 2.4.2.
- **Grype:** Does not list CVE-2018-16487 at all for lodash 2.4.2.
- **Why:** This is a **database coverage and matching rules** difference. CVE-2018-16487 is an older CVE (published 2018) that Grype's matching logic may consider superseded by newer GHSA advisories covering the same code paths (e.g., GHSA-jf85-cpcp-j695 for lodash prototype pollution). Trivy's DB retains and reports older CVE IDs more aggressively, while Grype tends to deduplicate toward the most recent advisory. Additionally, Trivy's broader scope includes CVEs from multiple ecosystems (it scans NVD, GitLab Advisory DB, OSV, and others), whereas Grype is anchored primarily on the GitHub Advisory Database + NVD.

### When would you pick each?

**Syft + Grype (decoupled model) wins when:** You need an SBOM as a long-lived attestation artifact (Lab 8 cosign signing, compliance audits, supply chain transparency). The decoupled pattern means you generate the SBOM once with Syft, store it, and re-scan it with Grype whenever a new CVE drops — no re-pulling the image, no CI rebuild. This is the "one SBOM → many scans over time" model from Lecture 4, and it's the foundation for SBOM-as-attestation workflows. Also preferred when you need both CycloneDX and SPDX formats for different consumers (e.g., compliance teams want SPDX, engineering wants CycloneDX).

**Trivy (all-in-one) wins when:** You need a single CI step that covers vulnerability scanning *plus* misconfigurations, secrets, and IaC scanning in one tool. Trivy's broader target coverage (image, filesystem, git repo, K8s cluster, SBOM, VM) means one tool for the entire pipeline, simpler maintenance, and a unified report format. It's the pragmatic choice for teams that want "good enough" coverage with minimal toolchain complexity — one install, one command, one report. Trivy's built-in secret scanning also catches things Grype doesn't (e.g., the RSA private key Trivy found embedded in `insecurity.js`).

---

## Bonus: Sign-Ready SBOM for Lab 8

### CycloneDX schema version
- `specVersion`: **1.6**
- `bomFormat`: **CycloneDX**

### Image digest captured
- `docker inspect ... RepoDigests`: `bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`

### Attestation predicate (first 35 lines of juice-shop-attestation.json)

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "bkimminich/juice-shop:v20.0.0",
      "digest": {
        "sha256": "sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0"
      }
    }
  ],
  "predicateType": "https://cyclonedx.org/bom/v1.5",
  "predicate": {
    "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "serialNumber": "urn:uuid:e51563ad-7751-4fb9-bc20-6120bfb27273",
    "version": 1,
    "metadata": {
      "timestamp": "2026-07-23T00:25:24+03:00",
      "tools": {
        "components": [
          {
            "type": "application",
            "author": "anchore",
            "name": "syft",
            "version": "1.44.0"
          }
        ]
      },
      "component": {
        "bom-ref": "73ec537d8d158676",
        "type": "container",
        "name": "bkimminich/juice-shop",
        "version": "v20.0.0"
      },
      ...
```

### What this enables in Lab 8

When Lab 8 runs `cosign attest --type cyclonedx --predicate juice-shop-attestation.json bkimminich/juice-shop:v20.0.0`, Cosign will create an in-toto attestation that **cryptographically binds the CycloneDX SBOM to the exact container image digest**. What's being signed is the *statement*: "Image `bkimminich/juice-shop@sha256:fd58bd...` has this specific SBOM (predicate) at the time of attestation." The claim being proven is twofold: (1) **provenance of inventory** — the 3,069 components listed in the SBOM were present in the image at attestation time, and (2) **non-repudiation** — anyone with the public key can verify that the CI pipeline (the private key holder) asserted this SBOM belongs to this image. This is the foundation for supply chain policy enforcement: a Kubernetes admission controller (like Sigstore Policy Controller) can reject images that lack a signed SBOM attestation, enforcing that every deployed workload has a verified, cryptographically-backed inventory of its dependencies — directly implementing Lecture 8 slide 9's in-toto attestation model.
