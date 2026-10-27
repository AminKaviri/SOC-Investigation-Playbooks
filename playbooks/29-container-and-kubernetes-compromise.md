# 29 — Container and Kubernetes Compromise

**Default severity:** High–Critical  
**MITRE ATT&CK:** T1610 (Deploy Container), T1611 (Escape to Host), T1525 (Implant Internal Image), T1552 (Unsecured Credentials)

## Objective
Determine whether suspicious container execution, pod deployment, privileged access, secret access or image modification represents compromise of a workload, node or cluster control plane.

## Indicators that trigger this playbook
- Unexpected pod/deployment, privileged container, hostPath mount or new service account/cluster role.
- Untrusted image, image digest mismatch, shell inside production container or suspicious outbound traffic.
- Kubernetes audit event indicates secret listing, exec/attach, role binding or admission-policy bypass.
- Node telemetry shows container escape indicators or host-level process execution from a container runtime.

## Pre-triage evidence checklist
- [ ] Cluster/context, namespace, workload/pod, image and immutable digest, node, service account, actor and audit request ID.
- [ ] Kubernetes audit logs, control-plane events, runtime/EDR, container registry history, network policy and cloud IAM events.
- [ ] Deployment manifest, owner, CI/CD build, admission/policy result and approved release window.
- [ ] Mounted secrets, workload identity permissions, node criticality and affected namespaces.

## Tier 1 triage workflow
### Step 1 — Validate control-plane action
Review actor, verb, resource, namespace, source, response status and request object from Kubernetes audit.

### Step 2 — Inspect workload configuration
Check image source/digest, privilege settings, host mounts, capabilities, service account and unexpected entrypoint/command.

### Step 3 — Correlate runtime and node evidence
Review container runtime events, process/network telemetry, node logs, cloud identity and secret access.

### Step 4 — Determine blast radius
Search other workloads sharing image digest, service account, node, registry credential and cluster role.

### Step 5 — Contain carefully
Coordinate namespace/workload isolation, service-account/token revocation, network policy and image quarantine under cluster incident procedure.

### Step 6 — Recover from trusted sources
Rebuild from verified images/manifests, rotate exposed secrets, validate RBAC/admission controls and monitor for redeployment.

## Splunk SPL investigation pivot
Adapt the index, sourcetype, fields and time window. This is an investigation pivot, not a validated detection.

```spl
index=kube_audit earliest=-24h
| eval actor=coalesce(user.username, user, username), verb=coalesce(verb, operation), obj=coalesce(objectRef.resource, resource), ns=coalesce(objectRef.namespace, namespace)
| search verb="create" OR verb="patch" OR verb="update" OR verb="delete" OR verb="get"
| stats count values(obj) as resources values(verb) as verbs values(userAgent) as agents values(sourceIPs) as sources by actor ns
| sort - count
```

## Containment guidance
Use approved incident authority, preserve evidence where feasible, and coordinate high-impact actions with service owners.

- Capture audit events, manifests, image digest and runtime events before deleting a pod or image.
- Do not delete live resources before incident command confirms evidence-preservation requirements and service impact.
- Revoke service-account tokens/secrets and update policies via trusted control-plane credentials.
- If cluster admin/control plane is compromised, assume broader namespace and node exposure until scoped.

## Escalation criteria
- Privileged pod, hostPath/host namespace abuse, secret access, cluster-admin role change or host escape is suspected.
- Shared image/credential impacts many workloads or production/regulated data is present.
- CI/CD, registry or cluster control-plane compromise is suspected.

## Closure criteria
- Actor, image, workload and affected scope established.
- Workload is rebuilt from a trusted source, secrets rotated and RBAC/policy gap resolved.
- Cluster and node telemetry checked for persistence and related deployments.

## False-positive and validation notes
Kubernetes audit field names and source types vary. The SPL is a pivot; use runtime telemetry and normalized audit fields to confirm dangerous actions.

Correlate independent telemetry. An alert name or isolated query result does not prove compromise. Record sources not searched, retention gaps and unresolved hypotheses.
