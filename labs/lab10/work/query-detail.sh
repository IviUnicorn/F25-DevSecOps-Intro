#!/usr/bin/env bash
DD_URL="http://localhost:8080"
DD_TOKEN="58b55869a7e20bb81ab9096e7b567c9d3896ddc5"

echo "=== Tests in engagement ==="
curl -s -H "Authorization: Token $DD_TOKEN" "$DD_URL/api/v2/tests/?engagement=1" | jq '[.results[] | {id, title, test_type_name: .test_type_name, findings_count: (.findings | length)}]'

echo ""
echo "=== Finding detail (id=1) full ==="
curl -s -H "Authorization: Token $DD_TOKEN" "$DD_URL/api/v2/findings/1/" | jq '{id, title, severity, test, found_by, cve, cwe, cvssv3, file_path, component_name, component_version, hash_code, duplicate, out_of_scope, false_p, mitigated, risk_accepted}'

echo ""
echo "=== Active vs mitigated ==="
curl -s -H "Authorization: Token $DD_TOKEN" "$DD_URL/api/v2/findings/?engagement=1&active=true&limit=1" | jq .count
echo "Mitigated:"
curl -s -H "Authorization: Token $DD_TOKEN" "$DD_URL/api/v2/findings/?engagement=1&is_mitigated=true&limit=1" | jq .count
