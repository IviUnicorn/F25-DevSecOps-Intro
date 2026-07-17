# Lab 11 — BONUS — Submission

## Task 1: TLS + Security Headers

### nginx.conf (SSL + header sections)

```nginx
  # HTTP server (redirect to HTTPS)
  server {
    listen 80;
    listen [::]:80;
    server_name _;

    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "camera=(), geolocation=(), microphone=()" always;
    add_header Cross-Origin-Opener-Policy "same-origin" always;
    add_header Cross-Origin-Resource-Policy "same-origin" always;
    add_header Content-Security-Policy-Report-Only "default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'" always;

    return 308 https://$host$request_uri;
  }

  # HTTPS server
  server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name _;

    ssl_certificate     /etc/nginx/certs/localhost.crt;
    ssl_certificate_key /etc/nginx/certs/localhost.key;

    ssl_protocols TLSv1.3;
    ssl_prefer_server_ciphers off;

    ssl_conf_command Ciphersuites TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256;
    ssl_ecdh_curve X25519:secp384r1;

    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;

    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
    add_header Content-Security-Policy-Report-Only "default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'" always;
```

### A. HTTPS redirect proof

```
HTTP/1.1 308 Permanent Redirect
Server: nginx
Date: Fri, 17 Jul 2026 19:05:34 GMT
Content-Type: text/html
Content-Length: 164
Connection: keep-alive
Location: https://localhost/
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), geolocation=(), microphone=()
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Content-Security-Policy-Report-Only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
```

### B. TLS 1.3 proof

```
Connecting to ::1
Can't use SSL_get_servername
depth=0 CN=juice.local
verify error:num=18:self-signed certificate
CONNECTION ESTABLISHED
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
Peer certificate: CN=juice.local
```

### C. Security headers proof (all 6 present)

```
HTTP/2 200
server: nginx
date: Fri, 17 Jul 2026 19:05:35 GMT
content-type: text/html; charset=UTF-8
content-length: 9903
strict-transport-security: max-age=63072000; includeSubDomains; preload
x-frame-options: DENY
x-content-type-options: nosniff
referrer-policy: strict-origin-when-cross-origin
permissions-policy: camera=(), microphone=(), geolocation=()
content-security-policy-report-only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
```

### What each header defends against (1 sentence each)

- **HSTS**: Forces browsers to only connect via HTTPS for 2 years, preventing protocol-downgrade and cookie-hijacking attacks.
- **X-Content-Type-Options: nosniff**: Prevents browsers from MIME-sniffing a response away from the declared Content-Type, stopping drive-by downloads and code injection.
- **X-Frame-Options: DENY**: Blocks the page from being embedded in iframes, preventing clickjacking attacks.
- **Referrer-Policy: strict-origin-when-cross-origin**: Sends only the origin (not the full URL) in cross-origin Referer headers, preventing URL leakage of sensitive paths.
- **Permissions-Policy: camera=(), microphone=(), geolocation=()**: Explicitly disables browser APIs for camera, microphone, and geolocation, reducing the attack surface from compromised scripts.
- **Content-Security-Policy-Report-Only**: Defines trusted content sources and reports policy violations without enforcing, allowing iterative tightening without breaking the app.

---

## Task 2: Production Posture

### Rate limit proof

| HTTP code | Count out of 60 |
|-----------|----------------:|
| 429 | 54 |
| 5xx | 6 |

### Timeout enforced

```
Connection closed after 10s
# Nginx closed the connection after 10s (client_header_timeout 10s)
```

### Cipher hardening

```
Peer Temp Key: X25519, 253 bits
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
```

### Cert rotation runbook (7 steps)

1. **Detect expiry**: Monitor cert expiry with a cron job (`openssl x509 -enddate -noout -in cert.pem`) or a tool like Prometheus + blackbox_exporter; alert at 30 days before expiry.
2. **Order new cert**: Submit a CSR to the CA (e.g., Let's Encrypt via `certbot renew`, or an internal PKI); for Let's Encrypt this is fully automated via the ACME protocol.
3. **Validate**: Verify the new cert's CN/SAN matches the domain, check the issuer chain, and confirm it is not expired with `openssl verify -CAfile ca.pem new.pem`.
4. **Atomic swap**: Copy new cert and key to a staging path, then use `nginx -s reload` (or symlink swap + reload) so Nginx picks up the new cert in-place without dropping connections.
5. **Verify**: After reload, confirm the new cert is served with `openssl s_client -connect host:443` and check the `Not After` date; also confirm no errors in Nginx error log.
6. **Rollback plan**: Keep the old cert/key backed up; if the new cert causes issues, restore the backup files and run `nginx -s reload` again to revert.
7. **Audit**: Log the rotation event (who, when, old serial, new serial) in an audit trail; update the CMDB or certificate inventory; close the monitoring alert.

### What OCSP stapling buys you (2-3 sentences)

OCSP stapling lets the server fetch and "staple" its own revocation status into the TLS handshake, so the client doesn't need to contact the CA's OCSP responder separately. This eliminates an extra round-trip to a third-party server (improving latency and privacy) and prevents OCSP responder outages from blocking user connections. In production with a publicly-trusted cert this is critical; in our self-signed lab cert it has no effect because no CA operates an OCSP responder for it.

---

## Bonus: WAF Sidecar with OWASP CRS

### Setup choice

- **WAF used**: ModSecurity v3 (via `owasp/modsecurity-crs:nginx-alpine` image)
- **OWASP CRS version**: v3.3.10
- **Paranoia level**: 1

> Note: The lab suggested Coraza as the modern Go-based alternative; I chose ModSecurity v3 because the OWASP CRS documentation has richer ModSec examples and the `owasp/modsecurity-crs` Docker image provides a ready-made integration with Nginx. Coraza is a viable alternative with ~70% feature parity as of 2026.

### Attack payload sent

```
GET /rest/products/search?q=' OR 1=1-- (URL-encoded: %27%20OR%201%3D1--)
```

### Before WAF (Nginx alone)

```
no-waf: HTTP 500
```

Juice Shop returns a 500 error (internal application error) — the SQL injection payload reaches the backend without any blocking.

### After WAF

```
with-waf: HTTP 403
```

ModSecurity + OWASP CRS blocks the request before it reaches Nginx or Juice Shop.

### Audit log excerpt (the rule that fired)

```
2026/07/17 19:18:47 [error] 526#526: *3 [client 172.18.0.1] ModSecurity: Access denied with code 403 (phase 2). Matched "Operator `Ge' with parameter `5' against variable `TX:ANOMALY_SCORE' (Value: `5' ) [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf"] [line "81"] [id "949110"] [msg "Inbound Anomaly Score Exceeded (Total Score: 5)"] [severity "2"] [ver "OWASP_CRS/3.3.10"] [hostname "localhost"] [uri "/rest/products/search"]

Rule 942100: SQL Injection Attack Detected via libinjection
  Match: detected SQLi using libinjection.
  Data: Matched Data: s&1c found within ARGS:q: ' OR 1=1--
  File: /etc/modsecurity.d/owasp-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf
  Line: 46
  Severity: 2
  Tags: attack-sqli, paranoia-level/1, OWASP_CRS, capec/1000/152/248/66, PCI/6.5.2
```

**Rule ID: 942100** — OWASP CRS rule name: **SQL Injection Attack Detected via libinjection**

### Tradeoff analysis (3 sentences)

The WAF catches entire categories of attack patterns (SQLi, XSS, path traversal) at the network edge before they reach application code, which SAST/DAST only find during development or scheduled scans and L7 Conftest gates only validate at deploy time. The cost is operational complexity (maintaining CRS rule updates, tuning paranoia levels to avoid false positives on legitimate traffic like Juice Shop's search queries, and managing cert/config sprawl across the WAF and proxy layers). You would NOT deploy a WAF in front of a low-traffic internal microservice with strong input validation already built in, where the overhead outweighs the marginal security gain.
