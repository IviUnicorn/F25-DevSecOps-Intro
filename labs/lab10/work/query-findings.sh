#!/usr/bin/env bash
DD_URL="http://localhost:8080"
DD_TOKEN="58b55869a7e20bb81ab9096e7b567c9d3896ddc5"

echo "=== Findings by test_type ==="
curl -s -H "Authorization: Token $DD_TOKEN" "$DD_URL/api/v2/findings/?engagement=1&active=true&limit=500" | jq '[.results[].test_type] | group_by(.) | map({test_type: .[0], count: length})'

echo ""
echo "=== Sample finding ==="
curl -s -H "Authorization: Token $DD_TOKEN" "$DD_URL/api/v2/findings/?engagement=1&limit=1" | jq '.results[0] | {id, title, severity, test_type, cve: .cve, unique_id_from_tool, duplicate, hash_code}'

echo ""
echo "=== Dedup check: duplicate findings ==="
curl -s -H "Authorization: Token $DD_TOKEN" "$DD_URL/api/v2/findings/?engagement=1&duplicate=true&limit=1" | jq .count
echo "= Unique (non-duplicate) ="
curl -s -H "Authorization: Token $DD_TOKEN" "$DD_URL/api/v2/findings/?engagement=1&duplicate=false&limit=1" | jq .count

echo ""
echo "=== Top 5 findings by severity ==="
curl -s -H "Authorization: Token $DD_TOKEN" "$DD_URL/api/v2/findings/?engagement=1&severity=Critical&limit=5" | jq '[.results[] | {title, severity, cve, test_type, found_by: (.found_by | join(","))}]'

echo ""
echo "=== Test types available ==="
curl -s -H "Authorization: Token $DD_TOKEN" "$DD_URL/api/v2/test_types/?limit=200" | jq '[.results[] | .name]'
