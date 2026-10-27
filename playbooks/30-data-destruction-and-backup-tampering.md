# 30 — Data Destruction and Backup Tampering

**Default severity:** Critical  
**MITRE ATT&CK:** T1485 (Data Destruction), T1490 (Inhibit System Recovery), T1489 (Service Stop)

## Objective
Determine whether destructive file activity, backup deletion, snapshot manipulation or recovery inhibition is occurring, protect surviving restore paths, and coordinate recovery decisions.

## Indicators that trigger this playbook
- Unusual bulk deletes, mass file overwrites, volume formatting or storage snapshot deletion.
- Backup jobs fail or retention/immutability settings change unexpectedly.
- Shadow copies, recovery services, backup agents or database/archive services stopped or deleted.
- Destructive activity follows privileged compromise, ransomware indicators or cloud control-plane abuse.

## Pre-triage evidence checklist
- [ ] Affected systems, storage resources, backup vault/snapshot IDs, actor, job IDs, timestamps and change tickets.
- [ ] Storage/file audit, backup-control-plane audit, endpoint events, cloud activity logs and service status.
- [ ] Recovery point objective, backup immutability/isolation status, known-good restore points and service dependencies.
- [ ] Whether deletion is ongoing, reversible, replicated, or propagating to backups.

## Tier 1 triage workflow
### Step 1 — Determine whether destruction is active
Confirm write/delete volume, affected objects, operation results and whether activity is spreading or replicated.

### Step 2 — Protect known-good recovery paths
Check backup vault access, immutable/offline copies, snapshot retention and backup admin identities using a trusted management plane.

### Step 3 — Identify actor and change path
Correlate deletion commands, admin/API calls, sessions, service stop events, deployment tooling and approval records.

### Step 4 — Scope replication and dependency
Determine which file shares, databases, object stores, snapshots and downstream replicas were affected.

### Step 5 — Contain without destroying evidence
Coordinate disablement of compromised credentials, restrict destructive permissions, protect backup control plane and isolate affected hosts where authorized.

### Step 6 — Plan restoration safely
Use incident command and service owners to select verified clean restore points; validate scope and persistence before reconnecting restored systems.

## Splunk SPL investigation pivot
Adapt the index, sourcetype, fields and time window. This is an investigation pivot, not a validated detection.

```spl
index=wineventlog earliest=-7d (EventCode=4660 OR EventCode=4663 OR EventCode=4719 OR EventCode=1102 OR EventCode=7036)
| eval actor=coalesce(SubjectUserName, user, AccountName)
| table _time host EventCode actor ObjectName AccessMask Message
| sort - _time
```

## Containment guidance
Use approved incident authority, preserve evidence where feasible, and coordinate high-impact actions with service owners.

- Do not initiate broad restoration until scope, attacker persistence and clean restore points have been reviewed.
- Protect backup administration and immutable copies from the compromised identity/control plane.
- Preserve deletion, configuration and backup job records, including successful and failed actions.
- Coordinate critical service availability and recovery sequencing through incident command.

## Escalation criteria
- Active or widespread data destruction, backup tampering or loss of immutable recovery paths.
- Domain/cloud admin, backup administrator or storage control plane may be compromised.
- Critical business systems, regulated data or multi-site replication is affected.

## Closure criteria
- Destruction scope, backup state and available clean restore points are documented.
- Access/persistence vectors are contained and a recovery validation is completed.
- Recovery gaps, lost data estimates and control improvements have owners.

## False-positive and validation notes
The query is a broad Windows audit pivot, not a universal delete detector. Storage, cloud and backup-provider audit events must be added for full coverage.

Correlate independent telemetry. An alert name or isolated query result does not prove compromise. Record sources not searched, retention gaps and unresolved hypotheses.
