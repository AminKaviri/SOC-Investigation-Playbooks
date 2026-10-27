# 03 — Lateral Movement Investigation

**Default severity:** High–Critical  
**Triage target:** 15–30 minutes, based on impact  
**MITRE ATT&CK:** T1021.001, T1021.002, T1021.006, T1550.002

## Objective
Determine whether an account or host was used to access additional systems and identify the origin, target set and credential scope.

## Indicators that trigger this playbook
- A user or host authenticates to multiple systems unusually, new SMB/RDP/WinRM activity, remote service creation, or administrative-share access.
- Remote execution follows suspicious logon, credential theft or unusual privilege use.

## Pre-triage evidence checklist
- [ ] Origin host/account, destination hosts, logon IDs/types, source IP, protocols, process/service/task evidence.
- [ ] Administrative change records, approved jump hosts, EDR ancestry and local/remote event logs.
- [ ] Credential reuse indicators, sensitive targets, and timeline of all source-to-target connections.

## Tier 1 triage workflow
### Step 1 — Identify the originating host
Establish first suspicious actor/host/account and identify whether it is a known jump host or management system.

### Step 2 — Build the source-target graph
Correlate logon IDs, source IPs, SMB/RDP/WinRM, remote services and endpoint process events into a chronological host graph.

### Step 3 — Validate credentials and mechanism
Review explicit-credential use, NTLM/Kerberos patterns, remote execution tooling and whether the action is part of approved admin operations.

### Step 4 — Identify target criticality
Prioritize domain controllers, backup servers, identity systems, security tooling and systems containing sensitive data.

### Step 5 — Scope and respond
Find all targets touched by the origin/account, preserve evidence and coordinate isolation/credential response.

## Splunk SPL investigation pivots

Adapt indexes, sourcetypes, field names, event codes and time range to your environment. These are investigation starting points, not production-certified detections.

```spl
index=wineventlog earliest=-24h (EventCode=4624 OR EventCode=4648 OR EventCode=5140 OR EventCode=7045)
| eval account=coalesce(TargetUserName, SubjectUserName, user), src_ip=coalesce(IpAddress, Source_Network_Address, src)
| stats count values(EventCode) as event_ids values(LogonType) as logon_types values(ShareName) as shares values(ServiceName) as services by account src_ip host
| sort - count
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
