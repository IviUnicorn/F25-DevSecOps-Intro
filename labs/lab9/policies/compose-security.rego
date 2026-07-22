package compose.security

# Starter compose security policy — same deny[msg] pattern, different input shape.
# input is the parsed docker-compose YAML; use input.services to iterate.
# Uses `some name` to get object keys (Rego v1).

deny contains msg if {
    some name
    svc := input.services[name]
    not svc.user
    msg := sprintf("service %q must specify a non-root user", [name])
}

deny contains msg if {
    some name
    svc := input.services[name]
    not svc.read_only == true
    msg := sprintf("service %q must set read_only: true", [name])
}

deny contains msg if {
    some name
    svc := input.services[name]
    not svc.cap_drop
    msg := sprintf("service %q must drop all capabilities (cap_drop: [ALL])", [name])
}
