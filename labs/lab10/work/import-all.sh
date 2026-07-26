#!/usr/bin/env bash
set -euo pipefail

DD_URL="http://localhost:8080"
DD_TOKEN="58b55869a7e20bb81ab9096e7b567c9d3896ddc5"
REPO="/home/ucat/Learn/F25-DevSecOps-Intro"

# Helper: import a scan
import_scan() {
  local scan_type="$1" file_path="$2" label="$3"
  if [ ! -f "$file_path" ]; then
    echo "[SKIP] $label: file not found at $file_path"
    return
  fi
  echo "--- Importing: $label ($scan_type) ---"
  curl -s -X POST "$DD_URL/api/v2/import-scan/" \
    -H "Authorization: Token $DD_TOKEN" \
    -F "scan_type=$scan_type" \
    -F "engagement=1" \
    -F "file=@$file_path" | jq '{id: .id, scan_type: .scan_type, verified: .verified, active: .active, findings: (.findings | length)}' 2>/dev/null || echo "Import failed for $label"
}

echo "=== Creating Engagement ==="
ENG_ID=$(curl -s -X POST "$DD_URL/api/v2/engagements/" \
  -H "Authorization: Token $DD_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"Course Semester Run","product":1,"target_start":"2026-09-01","target_end":"2026-12-15","engagement_type":"CI/CD","status":"In Progress"}' | jq -r .id)
echo "Engagement ID: $ENG_ID"

echo ""
echo "=== Importing all scan reports ==="

# Lab 4
import_scan "Anchore Grype" "$REPO/labs/lab4/grype-from-sbom.json" "Lab4-Grype"
import_scan "Trivy Scan" "$REPO/labs/lab4/trivy.json" "Lab4-Trivy"

# Lab 5
import_scan "Semgrep JSON Report" "$REPO/labs/lab5/results/semgrep.json" "Lab5-Semgrep"
import_scan "ZAP Scan" "$REPO/labs/lab5/results/auth-report.json" "Lab5-ZAP"

# Lab 6
import_scan "Checkov Scan" "$REPO/labs/lab6/results/checkov-terraform/results_json.json" "Lab6-Checkov"
import_scan "KICS Scan" "$REPO/labs/lab6/results/kics-ansible/results.json" "Lab6-KICS-Ansible"
import_scan "KICS Scan" "$REPO/labs/lab6/results/kics-pulumi/results.json" "Lab6-KICS-Pulumi"

# Lab 7
import_scan "Trivy Scan" "$REPO/labs/lab7/results/trivy-image.json" "Lab7-Trivy-Image"
import_scan "Trivy Operator Scan" "$REPO/labs/lab7/results/trivy-k8s.json" "Lab7-Trivy-K8s"

# Lab 8 — Cosign verify is not a vulnerability scan, just note it
echo "[NOTE] Lab 8 cosign verify output exists but is not a vulnerability scan format"

# Lab 9 — Falco log is custom, note it
echo "[NOTE] Lab 9 Falco alerts are runtime events, not direct-scan imports"

echo ""
echo "=== Done. Checking finding counts... ==="
curl -s -H "Authorization: Token $DD_TOKEN" "$DD_URL/api/v2/findings/?engagement=$ENG_ID&limit=1" | jq .count
