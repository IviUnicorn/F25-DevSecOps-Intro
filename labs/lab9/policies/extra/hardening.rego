package main

# Lab 9 — Conftest hardening policies for K8s manifests
# Each deny[msg] rule enforces one hardening requirement (Lecture 9 slide 10)
# Rego v1 syntax (deny contains msg if { ... })

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
