# 12 — Ransomware Early Triage

**Default severity:** Critical  
**Triage target:** Immediate; follow incident command  
**MITRE ATT&CK:** T1486, T1490, T1489

## Objective
Identify active encryption, potential spread, backup tampering and safe urgent containment decisions.

## Indicators that trigger this playbook
- Rapid file modifications/renames, ransom note, EDR ransomware behavior, shadow-copy deletion or backup tampering.
- Encryption is active, additional hosts are touched, or critical shared storage is impacted.

## Pre-triage evidence checklist
- [ ] Affected endpoints/shares, first encryption/write time, ransom-note path, EDR status, backup status and critical business service.
- [ ] Process tree, file-change velocity, shadow-copy/backup tampering, remote execution, common account and spread path.
- [ ] Network segments, impacted shares, known-good recovery assets, communications owner and evidence preservation.

## Tier 1 triage workflow
### Step 1 — Determine whether encryption is active
Correlate EDR behavior, high-rate renames/writes, ransom notes and business reports; check whether more hosts are affected.

### Step 2 — Protect life-critical operations and evidence
Follow incident command, preserve volatile/endpoint evidence where feasible, and use approved isolation actions. Do not casually power off systems.

### Step 3 — Assess spread and access path
Search lateral movement, compromised identities, remote services, exposed RDP, initial access and suspicious staging.

### Step 4 — Protect backups and recovery
Check backup control-plane access, immutability, snapshots and restore points from a trusted management plane.

### Step 5 — Coordinate containment and recovery
Segment affected hosts/shares under authority, preserve forensic evidence, notify response leads and avoid restoring before scope is understood.

## Splunk SPL investigation pivots

Adapt indexes, sourcetypes, field names, event codes and time range to your environment. These are investigation starting points, not production-certified detections.

```spl
index=sysmon earliest=-24h (EventCode=1 OR EventCode=11 OR EventCode=23 OR EventCode=26)
| eval cmd=lower(CommandLine), image=lower(Image), target=lower(TargetFilename)
| search cmd="*vssadmin*delete*shadows*" OR cmd="*wbadmin*delete*" OR cmd="*bcdedit*recoveryenabled*" OR image="*\vssadmin.exe" OR target="*.encrypted"
| table _time host user Image CommandLine TargetFilename EventCode
| sort - _time
```

### Correlation pivot — build a compact timeline
```spl
(index=wineventlog OR index=sysmon OR index=edr) earliest=-24h
| eval entity=coalesce(user, TargetUserName, SubjectUserName, AccountName)
| eval event_detail=coalesce(CommandLine, Message, EventDescription, action)
| table _time host entity EventCode Image ParentImage CommandLine event_detail
| sort 0 _time
```

## Containment guidance
- Preserve original evidence (message, command line, process tree, relevant log events, network/session metadata) before cleanup when feasible.
- Use approved containment authority. Coordinate with system, identity, email, data or application owners when action may disrupt business services.
- Prefer targeted controls and verify collateral impact before blocking shared infrastructure or disabling shared service identities.
- Record exactly what action was taken, by whom, when, why, and what was observed afterward.

## Tier 2 / incident response workflow
- Reconstruct the incident timeline across relevant email, endpoint, identity, network and application sources.
- Hunt the strongest observed indicators across the environment; include negative results and data gaps.
- Assess persistence, credentials, lateral movement, data access and whether containment succeeded.
- Confirm remediation with the owning team and define targeted monitoring for residual risk.

## Escalation criteria
Escalate promptly when any of these apply:
- Confirmed execution, unauthorized access, persistence, successful compromise or ongoing harmful activity.
- A privileged identity, critical system, domain controller, security/backup control or sensitive data repository is involved.
- Multiple hosts/users, broad campaign activity, suspected exfiltration, ransomware behavior or evidence tampering.
- Required logs are missing around critical actions or impact cannot be safely scoped.

## Closure criteria
Close only when:
- Evidence supports a clear disposition (true positive, benign positive, false positive, or inconclusive with stated limitations).
- Scope, affected assets/identities, timeline and containment outcomes are documented.
- Required owner/IR handoff is completed and remaining risks have an explicit owner.
- Any false-positive/tuning follow-up is recorded separately from incident facts.

## False-positive considerations
- Check approved changes, scheduled tasks, scanners, service accounts, deployment systems, remote-management infrastructure and business workflows.
- Rarity, failure volume, a suspicious command string or one event ID is not proof by itself.
- Where corroborating telemetry is unavailable, document the result as inconclusive rather than asserting no compromise.

## Query validation and data gaps
Validate SPL against real field extraction and source coverage before operational use. Confirm the search's time range, event IDs, source indexes, field names, result semantics and benign test cases. The examples have not been run against a live Splunk instance.
