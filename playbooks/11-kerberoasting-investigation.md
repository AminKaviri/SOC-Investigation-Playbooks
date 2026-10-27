# 11 — Kerberoasting Investigation

**Default severity:** High  
**Triage target:** 15–30 minutes, based on impact  
**MITRE ATT&CK:** T1558.003

## Objective
Assess unusual service-ticket requests, account context, service-account exposure and possible follow-on use.

## Indicators that trigger this playbook
- High volume or unusual pattern of Kerberos service-ticket requests, especially across many SPNs or from non-admin workstation.
- Service account is high-privilege, weakly protected or followed by suspicious authentication.

## Pre-triage evidence checklist
- [ ] Requester account, source host, request count, SPNs/service accounts and ticket encryption type.
- [ ] Domain controller event 4769 coverage, normal service-ticket baseline, privilege/value of service accounts and source context.
- [ ] Related credential-access indicators and follow-on use of target service accounts.

## Tier 1 triage workflow
### Step 1 — Quantify ticket requests
Count event 4769 by requester, SPN/service, encryption type and time window relative to a known baseline.

### Step 2 — Validate source and role
Determine whether the requester is a workstation, scanner, service account or approved admin tool.

### Step 3 — Assess service-account exposure
Review SPN owner, privilege, password age/rotation policy and whether the account accesses sensitive systems.

### Step 4 — Check for related credential abuse
Search unusual logons, admin group changes, remote execution and access using the target identity.

### Step 5 — Escalate with evidence
Provide request patterns and service-account risk; don't claim offline password recovery without corroborating evidence.

## Splunk SPL investigation pivots

Adapt indexes, sourcetypes, field names, event codes and time range to your environment. These are investigation starting points, not production-certified detections.

```spl
index=wineventlog earliest=-24h EventCode=4769
| eval account=coalesce(TargetUserName, user), service=coalesce(ServiceName, Service_Name)
| stats count dc(service) as unique_services values(service) as services values(TicketEncryptionType) as enc_types by account host
| where count > 20 OR unique_services > 10
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
