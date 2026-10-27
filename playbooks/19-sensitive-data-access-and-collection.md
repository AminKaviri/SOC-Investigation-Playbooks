# 19 — Sensitive Data Access and Staging

**Default severity:** Medium–Critical  
**Initial response target:** Triage: 30 minutes; immediate escalation if regulated data staging or extraction is suspected.  
**MITRE ATT&CK:** T1005 (Data from Local System), T1039 (Data from Network Shared Drive), T1119 (Automated Collection), T1560 (Archive Collected Data)

## Objective
Determine whether unusual file access, collection or archive activity represents approved work, insider risk, or preparation for exfiltration.

## Indicators that trigger this playbook
- Unusual mass file reads/downloads, archive creation, staging to temp directories, or share enumeration.
- Sensitive repository access by account/device outside normal role or business hours.
- Archive utility execution followed by outbound network activity or cloud uploads.
- DLP, file audit or endpoint alert tied to sensitive data classification.

## Pre-triage evidence checklist
- [ ] User, host, data source/share, file paths/classification, operation, time range and access result.
- [ ] File audit, file server access, EDR archive/process events, DLP and cloud upload logs.
- [ ] User role, approved export/task, service-account status, scheduled jobs and change records.
- [ ] Count/volume of files, unique directories, archive size/hash and destination.

## Tier 1 triage workflow
### Step 1 — Quantify access
Measure number of objects, size and sensitivity, access result, time span and deviation from user baseline.

### Step 2 — Identify source and tools
Review share/file audit and process telemetry for archive, copy, compression, scripting and staging activity.

### Step 3 — Establish authorization
Validate with data owner through a trusted channel. Check role, support ticket, backup/export job or approved migration.

### Step 4 — Look for staging and transfer
Correlate temporary archives, staging paths, cloud sync clients, removable-media events, proxy uploads and network destinations.

### Step 5 — Scope the event
Search other systems for account, archive name/hash, destinations, command lines and similar access bursts.

### Step 6 — Contain under governance
Engage data owner, privacy/legal and incident response before destructive actions. Preserve evidence and restrict access/transfer only under approved authority.

## Splunk SPL investigation pivot
Adapt index, sourcetype, field names, event codes and time ranges to your environment. This is an investigation starting point, not a validated production detection.

```spl
index=file_audit earliest=-24h
| eval actor=coalesce(user, src_user, AccountName), object=coalesce(file_path, ObjectName, path)
| stats count dc(object) as unique_objects values(action) as actions values(object) as sample_objects by actor host
| where unique_objects > 100 OR count > 500
| sort - unique_objects
```

## Containment guidance
Use approved authority and incident procedures. Preserve relevant logs and evidence before disruptive action when feasible.

- Preserve logs, file metadata and archive hashes before deleting or moving artifacts.
- Use approved access controls or transfer blocks, coordinating with data owner and privacy/legal.
- Don't label an employee malicious based on volume alone; assess role, authorized work and evidence of exfiltration intent.
- If transfer is ongoing, use critical-incident communications and containment process.

## Escalation criteria
Escalate to Tier 2 / IR when any of the following apply:

- Sensitive/regulated data is staged or transferred without authorization.
- Data access is tied to account compromise, archive tooling, suspicious cloud upload or removable media.
- Many repositories are affected or privacy/legal assessment may be required.

## Closure criteria
Close only when the evidence supports a disposition, scope and remaining gaps are recorded, and actions are complete or assigned.

- Data accessed and potentially exposed is identified to supported extent.
- Authorization/business impact is documented; privacy/legal decisions are tracked separately.
- Evidence retention, containment and access-review actions are recorded.

## False-positive and validation notes
File audit schemas differ. Volume thresholds require per-source baselining; this is not a standalone insider-threat verdict.

Do not treat an alert name, rarity score, or single query result as proof of compromise. Correlate independent telemetry and document unavailable sources.
