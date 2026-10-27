# 10 — Windows Event Log Tampering

**Default severity:** High–Critical  
**Triage target:** 15–30 minutes, based on impact  
**MITRE ATT&CK:** T1070.001, T1562.002

## Objective
Confirm whether logs or audit controls were intentionally modified and identify the surrounding activity and telemetry gap.

## Indicators that trigger this playbook
- Security/System log clear, audit-policy change, event service stop, or sudden host telemetry gap.
- Log tampering occurs near suspicious execution, privileged access, lateral movement or ransomware indicators.

## Pre-triage evidence checklist
- [ ] Event IDs/timestamps, host, actor, channels affected, service state, audit-policy changes and telemetry last-seen.
- [ ] Admin session, process execution, lateral-movement and defense-evasion events before/after gap.
- [ ] Alternate telemetry sources and host criticality; document the exact period whose evidence may be missing.

## Tier 1 triage workflow
### Step 1 — Confirm the gap
Validate event 1102, System 104, event service stop, audit-policy change, retention or ingestion failure.

### Step 2 — Build a before/after timeline
Find activity immediately before the gap and confirm last/first event timestamps. Document exact visibility window.

### Step 3 — Use alternate sources
Correlate EDR, SIEM forwarder, proxy, identity, firewall and domain controller telemetry.

### Step 4 — Scope affected systems
Search for same actor, command, event sequence and gaps across endpoints.

### Step 5 — Escalate and protect
Treat a gap around suspected compromise as an evidence-integrity risk. Preserve remaining records and restore logging through authorized operations.

## Splunk SPL investigation pivots

Adapt indexes, sourcetypes, field names, event codes and time range to your environment. These are investigation starting points, not production-certified detections.

```spl
index=wineventlog earliest=-7d (EventCode=1102 OR EventCode=104 OR EventCode=4719 OR EventCode=1100)
| table _time host EventCode SubjectUserName Message
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
