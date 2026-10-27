# 09 — Suspicious RDP and Remote Access

**Default severity:** Medium–Critical  
**Triage target:** 15–30 minutes, based on impact  
**MITRE ATT&CK:** T1021.001, T1133, T1078

## Objective
Determine whether remote interactive access is authorized and whether it enabled subsequent activity.

## Indicators that trigger this playbook
- Unusual RDP session, logon type 10, session reconnect from a new source, or remote logon outside approved window.
- Remote session is followed by admin-share access, process execution or access to sensitive assets.

## Pre-triage evidence checklist
- [ ] Source/destination host, account, source IP, session ID, logon type, MFA/VPN context and timestamps.
- [ ] Logon success/failure, interactive sessions, clipboard/drive redirection if available, subsequent process and file activity.
- [ ] Asset criticality, approved remote admin source list, EDR and network telemetry.

## Tier 1 triage workflow
### Step 1 — Validate remote session
Confirm session established, source address/device, authentication/MFA/VPN and identity; distinguish failed attempts from successful logons.

### Step 2 — Check authorization
Compare to approved jump hosts, support windows, vendor access and role requirements.

### Step 3 — Trace session activity
Correlate RDP session events with process execution, file access, clipboard/drive redirection telemetry and subsequent network activity.

### Step 4 — Scope related sessions
Search same account/source against other endpoints and identify privileged or sensitive targets.

### Step 5 — Contain and recover
Coordinate session termination, account/session revocation or host isolation based on evidence and operational impact.

## Splunk SPL investigation pivots

Adapt indexes, sourcetypes, field names, event codes and time range to your environment. These are investigation starting points, not production-certified detections.

```spl
index=wineventlog earliest=-24h (EventCode=4624 OR EventCode=4625 OR EventCode=4778 OR EventCode=4779)
| eval account=coalesce(TargetUserName, user), src_ip=coalesce(IpAddress, Source_Network_Address, src)
| search LogonType=10 OR EventCode=4778 OR EventCode=4779
| stats count values(EventCode) as events values(host) as targets values(LogonType) as logon_types by account src_ip
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
