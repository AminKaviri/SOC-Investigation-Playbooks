# 07 — Active Directory Account Compromise

**Default severity:** High–Critical  
**Triage target:** 15–30 minutes, based on impact  
**MITRE ATT&CK:** T1078.002, T1098, T1003

## Objective
Determine whether an AD identity has been compromised and identify suspicious logons, persistence, credential access and scope.

## Indicators that trigger this playbook
- Unusual successful logon, password reset/MFA changes, privileged group modification, or impossible-travel alert involving an AD user.
- Same account accesses sensitive systems or changes identity/persistence settings shortly after suspicious authentication.

## Pre-triage evidence checklist
- [ ] Affected identity, role/group memberships, source IP/device, logon type, authentication/MFA outcome and time range.
- [ ] Password reset, MFA-method change, group/role change, delegated rights, tickets and adjacent accounts.
- [ ] Domain controller logs, endpoint timeline, privileged access path and any service dependencies.

## Tier 1 triage workflow
### Step 1 — Confirm identity compromise
Review authentication failures/successes, source/device, logon type, MFA/password events and unusual account behavior.

### Step 2 — Inspect identity changes
Review group membership, privileged roles, delegates, SPNs, key credentials, password resets and account creation.

### Step 3 — Map access and scope
Correlate account use across endpoints, domain controllers, file servers, remote sessions and admin tools.

### Step 4 — Check persistence and credential theft
Review suspicious services/tasks, credential-dumping indicators, new keys/secrets and security logging changes.

### Step 5 — Coordinate recovery
Use identity owners to revoke sessions/rotate credentials and ensure service dependencies aren't unexpectedly broken.

## Splunk SPL investigation pivots

Adapt indexes, sourcetypes, field names, event codes and time range to your environment. These are investigation starting points, not production-certified detections.

```spl
index=wineventlog earliest=-24h (EventCode=4624 OR EventCode=4625 OR EventCode=4720 OR EventCode=4728 OR EventCode=4732 OR EventCode=4768 OR EventCode=4769)
| eval account=coalesce(TargetUserName, SubjectUserName, user), src_ip=coalesce(IpAddress, Source_Network_Address, src)
| table _time host EventCode account src_ip LogonType Status TargetUserName SubjectUserName MemberName Message
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
