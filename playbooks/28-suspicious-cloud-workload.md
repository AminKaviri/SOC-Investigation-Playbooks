# 28 — Suspicious Cloud Workload or Resource Abuse

**Default severity:** High–Critical  
**MITRE ATT&CK:** T1496 (Resource Hijacking), T1578 (Modify Cloud Compute Infrastructure), T1078.004 (Cloud Accounts)

## Objective
Determine whether an unexpected compute resource, scheduled job, serverless function or cloud workload was created/modified for unauthorized execution, persistence, data access or resource abuse.

## Indicators that trigger this playbook
- Unexpected VM/container/function/job creation or new instance type/region.
- Sudden compute utilization or billing spike, mining-like workload or unfamiliar external egress.
- Cloud workload changes tied to unusual identity/session, new role/key or security group modification.
- Unexpected startup script, user data, deployment image or service account identity.

## Pre-triage evidence checklist
- [ ] Cloud account/subscription/project, resource ID, region, creator identity, event ID and timestamps.
- [ ] Instance/container/function image, user-data/startup script, workload identity/role, tags, network policy and change record.
- [ ] Cloud audit, billing/usage, flow logs, DNS/proxy, endpoint/agent telemetry and deployment pipeline history.
- [ ] Whether resource handles production traffic, data or customer workloads.

## Tier 1 triage workflow
### Step 1 — Validate create/modify events
Identify which API action succeeded, who performed it, with what session/role and from where.

### Step 2 — Inspect workload content
Review image provenance, startup/user data, command/entrypoint, scheduled jobs, process/network telemetry and unexpected binaries.

### Step 3 — Trace identity and network
Check attached roles, metadata-service access, secrets access, inbound exposure, outbound destinations and cross-account communication.

### Step 4 — Assess cost and impact
Quantify runtime, resource size, billing exposure, data access and whether critical applications were modified.

### Step 5 — Contain with cloud owner
Preserve resource configuration/logs, snapshot when authorized, then stop/isolate or restrict resource according to impact and incident authority.

### Step 6 — Verify clean rebuild
Remove unauthorized resources/credentials, fix access path, and redeploy from trusted images/templates after persistence checks.

## Splunk SPL investigation pivot
Adapt the index, sourcetype, fields and time window. This is an investigation pivot, not a validated detection.

```spl
index=cloud_audit earliest=-24h
| eval actor=coalesce(userIdentity.arn, user, principalId), action=coalesce(eventName, operationName, action), resource=coalesce(resourceId, requestParameters.instanceId, requestParameters.resourceId)
| search action="*RunInstances*" OR action="*CreateFunction*" OR action="*CreateVirtualMachine*" OR action="*CreateJob*" OR action="*UpdateFunction*" OR action="*CreateContainer*"
| table _time actor action resource awsRegion sourceIPAddress userAgent errorCode
| sort - _time
```

## Containment guidance
Use approved incident authority, preserve evidence where feasible, and coordinate high-impact actions with service owners.

- Preserve resource state, image identifiers, startup scripts, API events and flow logs before termination where feasible.
- Coordinate stopping/deleting workload resources with service owners; check for production impact and data preservation requirements.
- Revoke compromised workload identities/credentials from a trusted control plane.
- Investigate related resources and build/deployment automation, not only the suspected instance.

## Escalation criteria
- Unexpected compute creation in privileged account or production scope.
- Evidence of cryptomining/resource hijack, exposed secrets, unauthorized data access or public exposure.
- Cloud logs disabled or the deployment pipeline/role may be compromised.

## Closure criteria
- Resource and creation/modification actor are identified.
- Workload is removed or restored safely; credentials and pipeline impact addressed.
- Cost, data-access and logging impacts are documented.

## False-positive and validation notes
The query uses illustrative event names and fields; provider schemas and resource-creation APIs differ. Verify against the cloud provider logs in use.

Correlate independent telemetry. An alert name or isolated query result does not prove compromise. Record sources not searched, retention gaps and unresolved hypotheses.
