# Lab 9 — Submission

## Task 1: Runtime Detection with Falco

### Baseline alert A — Terminal shell in container
JSON alert from Falco logs:
```json
{
    "hostname": "6e60392e6b7d",
    "output": "2026-07-22T19:02:54.081387346+0000: Notice A shell was spawned in a container with an attached terminal | evt_type=execve user=root user_uid=0 user_loginuid=-1 process=sh proc_exepath=/bin/busybox parent=containerd-shim command=sh -lc echo shell-in-container terminal=34816 exe_flags=EXE_WRITABLE|EXE_LOWER_LAYER container_id=efccd9b43968 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20",
    "output_fields": {
        "container.id": "efccd9b43968",
        "container.image.repository": "alpine",
        "container.image.tag": "3.20",
        "container.name": "lab9-target",
        "evt.type": "execve",
        "proc.cmdline": "sh -lc echo shell-in-container",
        "proc.exepath": "/bin/busybox",
        "proc.name": "sh",
        "proc.pname": "containerd-shim",
        "proc.tty": 34816,
        "user.name": "root",
        "user.uid": 0
    },
    "priority": "Notice",
    "rule": "Terminal shell in container",
    "source": "syscall",
    "tags": ["T1059", "container", "maturity_stable", "mitre_execution", "shell"],
    "time": "2026-07-22T19:02:54.081387346Z"
}
```

### Baseline alert B — Read sensitive file untrusted (`cat /etc/shadow`)
```json
{
    "hostname": "6e60392e6b7d",
    "output": "2026-07-22T19:01:29.874191979+0000: Warning Sensitive file opened for reading by non-trusted program | file=/etc/shadow evt_type=open user=root process=cat proc_exepath=/bin/busybox parent=systemd command=cat /etc/shadow terminal=0 container_id=efccd9b43968 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20",
    "output_fields": {
        "container.id": "efccd9b43968",
        "container.image.repository": "alpine",
        "container.image.tag": "3.20",
        "container.name": "lab9-target",
        "evt.type": "open",
        "fd.name": "/etc/shadow",
        "proc.cmdline": "cat /etc/shadow",
        "proc.exepath": "/bin/busybox",
        "proc.name": "cat",
        "proc.pname": "systemd",
        "proc.tty": 0,
        "user.name": "root",
        "user.uid": 0
    },
    "priority": "Warning",
    "rule": "Read sensitive file untrusted",
    "source": "syscall",
    "tags": ["T1555", "container", "filesystem", "host", "maturity_stable", "mitre_credential_access"],
    "time": "2026-07-22T19:01:29.874191979Z"
}
```

### Custom rule (pasted from labs/lab9/falco/rules/custom-rules.yaml)
```yaml
- rule: "Write to /tmp by container"
  desc: "Detect any file write to /tmp inside a container"
  condition: >
    open_write
    and container.id != host
    and fd.name startswith /tmp/
  output: >
    "Write to /tmp detected (container=%container.name user=%user.name
     file=%fd.name cmdline=%proc.cmdline)"
  priority: WARNING
  tags: [container, drift]
```

### Custom rule fired
Falco log line showing the custom rule:
```json
{
    "hostname": "6e60392e6b7d",
    "output": "2026-07-22T19:03:44.528226717+0000: Warning \"Write to /tmp detected (container=lab9-target user=root file=/tmp/my-write.txt cmdline=sh -lc echo \"test\" > /tmp/my-write.txt)\" container_id=efccd9b43968 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20",
    "output_fields": {
        "container.id": "efccd9b43968",
        "container.image.repository": "alpine",
        "container.image.tag": "3.20",
        "container.name": "lab9-target",
        "fd.name": "/tmp/my-write.txt",
        "proc.cmdline": "sh -lc echo \"test\" > /tmp/my-write.txt",
        "user.name": "root"
    },
    "priority": "Warning",
    "rule": "Write to /tmp by container",
    "source": "syscall",
    "tags": ["container", "drift"],
    "time": "2026-07-22T19:03:44.528226717Z"
}
```

### Tuning consideration (Lecture 9 slide 8)

The "Write to /tmp" rule will fire on many legitimate workloads — logging frameworks write temp files,
build tools stage artifacts in /tmp, and package managers create lock files there.
Using an `exceptions:` block would be preferable over `and not proc.name=...` because exceptions
provide structured, documented carve-outs with `comps:` (component), `name:`, and `values:` fields,
making it auditable _why_ a process was excluded. For example, you could add an exception for
`proc.name=java` (JVM tmp files) with a note that JVM-based apps use /tmp for internal IPC,
whereas the `and not` approach scatters the same logic across the condition line and becomes
unmaintainable as the allowlist grows.

---

## Task 2: Conftest Policy-as-Code

### My policy file (labs/lab9/policies/extra/hardening.rego)
```rego
package main

# Lab 9 — Conftest hardening policies for K8s manifests
# Each deny contains msg if { ... } enforces one hardening requirement (Lecture 9 slide 10)
# Rego v1 syntax (Conftest dev / OPA 1.15+)

# 1. runAsNonRoot must be true (pod-level OR container-level securityContext)
deny contains msg if {
    container := input.spec.template.spec.containers[_]
    not container.securityContext.runAsNonRoot == true
    not input.spec.template.spec.securityContext.runAsNonRoot == true
    msg := sprintf("container %q must set runAsNonRoot: true in securityContext", [container.name])
}

# 2. allowPrivilegeEscalation must be false for every container
deny contains msg if {
    container := input.spec.template.spec.containers[_]
    not container.securityContext.allowPrivilegeEscalation == false
    msg := sprintf("container %q must set allowPrivilegeEscalation: false in securityContext", [container.name])
}

# 3. capabilities.drop must include "ALL" for every container
deny contains msg if {
    container := input.spec.template.spec.containers[_]
    not container.securityContext.capabilities.drop
    msg := sprintf("container %q must drop all capabilities (capabilities.drop must include ALL)", [container.name])
}

deny contains msg if {
    container := input.spec.template.spec.containers[_]
    not "ALL" in container.securityContext.capabilities.drop
    msg := sprintf("container %q capabilities.drop must include ALL", [container.name])
}

# 4. resources.limits.memory must be set for every container
deny contains msg if {
    container := input.spec.template.spec.containers[_]
    not container.resources.limits.memory
    msg := sprintf("container %q must set resources.limits.memory", [container.name])
}

# 5. image must use sha256: digest, not a :tag (optional hardening)
deny contains msg if {
    container := input.spec.template.spec.containers[_]
    not contains(container.image, "@sha256:")
    msg := sprintf("container %q image must use a sha256 digest, found %q", [container.name, container.image])
}
```

### Compliant manifest passes (juice-hardened.yaml)
```
$ conftest test labs/lab9/manifests/k8s/juice-hardened.yaml --policy labs/lab9/policies/extra/

6 tests, 6 passed, 0 warnings, 0 failures, 0 exceptions
```

### Non-compliant manifest fails (juice-unhardened.yaml)
```
$ conftest test labs/lab9/manifests/k8s/juice-unhardened.yaml --policy labs/lab9/policies/extra/

FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice-shop" image must use a sha256 digest, found "bkimminich/juice-shop:latest"
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice-shop" must drop all capabilities (capabilities.drop must include ALL)
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice-shop" must set allowPrivilegeEscalation: false in securityContext
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice-shop" must set resources.limits.memory
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice-shop" must set runAsNonRoot: true in securityContext

6 tests, 1 passed, 0 warnings, 5 failures, 0 exceptions
```

### Compose policy generalizes (shipped compose-security.rego)
```
$ conftest test labs/lab9/manifests/compose/juice-compose.yml \
    --policy labs/lab9/policies/compose-security.rego --namespace compose.security

3 tests, 3 passed, 0 warnings, 0 failures, 0 exceptions

$ conftest test /tmp/bad-compose.yml \
    --policy labs/lab9/policies/compose-security.rego --namespace compose.security

FAIL - /tmp/bad-compose.yml - compose.security - service "app" must drop all capabilities (cap_drop: [ALL])
FAIL - /tmp/bad-compose.yml - compose.security - service "app" must set read_only: true
FAIL - /tmp/bad-compose.yml - compose.security - service "app" must specify a non-root user

3 tests, 0 passed, 0 warnings, 3 failures, 0 exceptions
```

### Why CI-time vs admission-time (Lecture 9 slide 9)

Running Conftest at both CI time and admission time creates defense in depth: CI-time gates
catch misconfigurations before they reach the cluster, giving developers fast feedback in the
PR review without blocking production workloads. Admission-time gates provide a second,
unavoidable enforcement point — even if someone bypasses CI (e.g., a direct `kubectl apply`
from a compromised workstation), the validating webhook still rejects the non-compliant manifest.
This follows the "two-person rule" principle from Lecture 9: no single control point is trusted
alone, and the operational benefit is that CI keeps velocity high while admission prevents
configuration drift at deploy time.

---

## Bonus: Cryptominer Detection Rule

### Rule (paste)
```yaml
- rule: "Possible Cryptominer Activity"
  desc: "Detect known miner processes or network tools connecting to mining-pool ports"
  condition: >
    spawned_process
    and container.id != host
    and (proc.name in (xmrig, ethminer, cgminer, t-rex, claymore)
         or (proc.name in (nc, ncat, netcat, curl, wget)
             and (proc.cmdline contains "3333"
                  or proc.cmdline contains "4444"
                  or proc.cmdline contains "5555"
                  or proc.cmdline contains "7777"
                  or proc.cmdline contains "14444"
                  or proc.cmdline contains "19999"
                  or proc.cmdline contains "45700")))
  output: >
    "Possible cryptominer detected (container=%container.name
     proc=%proc.name cmdline=%proc.cmdline
     user=%user.name)"
  priority: CRITICAL
  tags: [container, mitre_execution, mitre_command_and_control]
```

### Triggered alert
```json
{
    "hostname": "6e60392e6b7d",
    "output": "2026-07-22T19:08:13.624587086+0000: Critical \"Possible cryptominer detected (container=lab9-target proc=nc cmdline=nc -w 2 127.0.0.1 3333 user=root)\" container_id=efccd9b43968 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20",
    "output_fields": {
        "container.id": "efccd9b43968",
        "container.image.repository": "alpine",
        "container.image.tag": "3.20",
        "container.name": "lab9-target",
        "proc.cmdline": "nc -w 2 127.0.0.1 3333",
        "proc.name": "nc",
        "user.name": "root"
    },
    "priority": "Critical",
    "rule": "Possible Cryptominer Activity",
    "source": "syscall",
    "tags": ["container", "mitre_command_and_control", "mitre_execution"],
    "time": "2026-07-22T19:08:13.624587086Z"
}
```

### Reflection

**Which 2 indicators and why:** I used (1) process name matching known miner binaries
(`xmrig`, `ethminer`, `cgminer`, `t-rex`, `claymore`) and (2) network tools
(`nc`, `ncat`, `netcat`, `curl`, `wget`) connecting to known mining-pool ports
(3333, 4444, 5555, 7777, 14444, 19999, 45700). Process name gives high-confidence
detection of known miners, while the port+network-tool pattern catches adversaries
who rename binaries or use legitimate tools for exfiltration.

**What this misses (false negatives):** Attackers can evade both indicators by
tunneling mining traffic over standard HTTPS (port 443) to pools that use common
ports, or by compiling custom miner binaries with names that don't match the
allowlist. Stratum protocol can be wrapped in TLS with domain fronting, making
port-based detection useless. Additionally, on kernels where connect tracepoints
aren't available (observed on Linux 7.1), the rule must rely on `spawned_process`
events, which means it catches tool invocation but not the actual socket
connection — an attacker who injects into an existing process would go undetected.

**SLA matrix integration:** This rule maps to the Lecture 9 SLA matrix as a
"Critical" priority rule with `mitre_execution` (TA0002) and `mitre_command_and_control`
(TA0011) tags. In the SLA framework, this would trigger a P1 response: immediate
alert to the SOC, container isolation within the orchestration platform, and an
automated forensic snapshot (process tree + network flows). The 5-minute detection
window from the matrix is achievable since Falco streams events in near-real-time
via the eBPF ring buffer.
