# 05 — Data Exfiltration Investigation

**Default severity:** High–Critical  
**Triage target:** 15–30 minutes, based on impact  
**MITRE ATT&CK:** T1048, T1041, T1567, T1567.002

## Objective
Determine whether sensitive data was staged or transferred outside approved boundaries, through which channel and with what impact.

## Indicators that trigger this playbook
- DLP/egress alert, unusual upload/download volume, archive staging, cloud-storage transfer, or rare external destination.
- Sensitive data access is correlated with unauthorized account or endpoint activity.

## Pre-triage evidence checklist
- [ ] Data classification/owner, source repository, actors, file count/volume, archive hash and destination.
- [ ] Transfer channel, proxy/firewall/DLP records, timestamps, user authorization and business purpose.
- [ ] Whether transfer is ongoing, data was accessible publicly, and legal/privacy referral status.

## Tier 1 triage workflow
### Step 1 — Quantify the event
Measure bytes, file/object count, sensitivity, destinations, time window and whether the transfer continues.

### Step 2 — Identify the channel
Correlate proxy, firewall, cloud audit, DLP, DNS, removable media and application telemetry.

### Step 3 — Determine what data was accessed
Use file/share/cloud audit logs and data-owner context to identify repositories and classes of data involved.

### Step 4 — Attribute activity carefully
Correlate identity, device, session, process and change/ticket records; don't infer intent from volume alone.

### Step 5 — Contain and assess impact
Preserve logs and hashes; coordinate restriction of transfer/access with data owner, IR, privacy/legal as policy requires.

## Splunk SPL investigation pivots

Adapt indexes, sourcetypes, field names, event codes and time range to your environment. These are investigation starting points, not production-certified detections.

```spl
index=proxy earliest=-24h
| eval src=coalesce(src, src_ip, client_ip), dest=coalesce(dest, dest_ip, dhost), out=coalesce(bytes_out, cs_bytes, sent_bytes)
| stats sum(out) as bytes_out count values(url) as urls values(action) as actions by src dest
| where bytes_out > 100000000
| sort - bytes_out
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
