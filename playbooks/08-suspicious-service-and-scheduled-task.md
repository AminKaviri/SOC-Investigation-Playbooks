# 08 — Suspicious Service and Scheduled Task

**Default severity:** High–Critical  
**Triage target:** 15–30 minutes, based on impact  
**MITRE ATT&CK:** T1543.003, T1053.005

## Objective
Determine whether a new or modified service/task is legitimate administration or a persistence/privilege mechanism.

## Indicators that trigger this playbook
- Unexpected service installation/change or scheduled task creation, especially from user-writable path or unusual actor.
- Service/task starts a shell, script host, unknown binary, or makes unusual network connections.

## Pre-triage evidence checklist
- [ ] Service/task name, executable/action path, hashes/signers, creator account, host and timestamp.
- [ ] Service/task creation/modification/start events, parent process, schedule/trigger, run-as identity and change ticket.
- [ ] Persistence artifacts, network destinations, affected fleet and recovery/rollback prerequisites.

## Tier 1 triage workflow
### Step 1 — Validate creation or change
Identify service/task creator, binary/action path, run-as account, command line, trigger and event time.

### Step 2 — Check legitimacy
Compare to approved software installs, management platforms, deployment jobs and change tickets.

### Step 3 — Inspect executed payload
Review file signature/hash, writable path, parent process, child processes, network calls and privilege context.

### Step 4 — Hunt fleet-wide
Search service/task names, hashes, paths, commands and originating identities across hosts.

### Step 5 — Contain safely
Preserve configuration and event evidence; disable/remove unauthorized persistence only after confirming impact and coordinating owner.

## Splunk SPL investigation pivots

Adapt indexes, sourcetypes, field names, event codes and time range to your environment. These are investigation starting points, not production-certified detections.

```spl
index=wineventlog earliest=-7d (EventCode=4697 OR EventCode=7045 OR EventCode=4698 OR EventCode=4702)
| table _time host EventCode SubjectUserName ServiceName ImagePath TaskName TaskContent Message
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
