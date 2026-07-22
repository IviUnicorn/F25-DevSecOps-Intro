package k8s.security

# Starter K8s security policy — deny[msg] pattern (Lecture 9 slide 10)
# This checks the pod-level securityContext for runAsNonRoot.
# Extend this pattern for your own rules in policies/extra/hardening.rego.

deny contains msg if {
    container := input.spec.template.spec.containers[_]
    not container.securityContext.runAsNonRoot == true
    not input.spec.template.spec.securityContext.runAsNonRoot == true
    msg := sprintf("container %q must run as non-root (runAsNonRoot: true)", [container.name])
}
