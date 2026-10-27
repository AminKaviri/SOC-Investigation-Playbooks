# 22 — Potential Insider Threat or Acceptable-Use Violation

**Default severity:** Medium–Critical  
**Initial response target:** Follow internal privacy and HR/legal procedures; immediate escalation if sensitive data is actively leaving.  
**MITRE ATT&CK:** T1530 (Data from Cloud Storage Object), T1005 (Data from Local System), T1020 (Automated Exfiltration), T1567 (Exfiltration Over Web Service)

## Objective
Review suspicious data access, control bypass or unusual user activity impartially while minimizing unnecessary exposure of employee information.

## Indicators that trigger this playbook
- High-volume access/download outside job role.
- Unexpected removable media, personal cloud storage, unauthorized archive or mass deletion.
- Repeated policy/control bypass or transfer to unusual external destination.
- Correlated events suggest data theft rather than a benign anomaly.

## Pre-triage evidence checklist
- [ ] Alert details, affected resources, business owner, time range, data classification and objective evidence.
- [ ] File/DLP/endpoint/proxy/cloud logs and retention windows.
- [ ] User role, authorized project, approved export, change/support tickets and data-owner validation.
- [ ] Applicable HR/legal/privacy rules; least-privilege access to case data.

## Tier 1 triage workflow
### Step 1 — Validate without assumptions
Record objective event facts and baseline comparison; do not infer intent from role, demographics or a single anomaly.

### Step 2 — Confirm business context
Ask data/resource owner or manager through approved process whether behavior has an authorized explanation.

### Step 3 — Determine data scope and movement
Quantify sensitive objects accessed, staged, copied, deleted or transferred; correlate endpoint, cloud and removable-media telemetry.

### Step 4 — Check for account compromise
Validate sign-ins, MFA changes, malware, unusual devices and credential-theft indicators that could explain activity.

### Step 5 — Escalate through restricted channels
Engage incident lead, privacy/legal and HR when policy requires. Avoid broad distribution of employee data.

### Step 6 — Preserve and protect evidence
Use approved case access controls and chain-of-custody; do not perform unsanctioned surveillance.

## Splunk SPL investigation pivot
Adapt index, sourcetype, field names, event codes and time ranges to your environment. This is an investigation starting point, not a validated production detection.

```spl
index=dlp earliest=-7d
| eval actor=coalesce(user, src_user, AccountName), action=coalesce(action, Activity, operation)
| stats count dc(resource) as unique_resources values(action) as actions values(policy_name) as policies values(destination) as destinations by actor host
| sort - unique_resources
```

## Containment guidance
Use approved authority and incident procedures. Preserve relevant logs and evidence before disruptive action when feasible.

- Any account restriction/monitoring change must follow internal policy, legal/privacy direction and incident authority.
- For ongoing transfer, coordinate proportionate action with data owner and incident commander.
- Do not access personal content, disclose allegations widely, or collect beyond authorized scope.
- Keep evidence access logged and restricted to assigned responders.

## Escalation criteria
Escalate to Tier 2 / IR when any of the following apply:

- Sensitive data appears transferred/destroyed without authorization.
- Senior staff, regulated data, or legal/contractual notification may be involved.
- Account compromise or malware may explain anomalous activity.

## Closure criteria
Close only when the evidence supports a disposition, scope and remaining gaps are recorded, and actions are complete or assigned.

- Evidence-backed findings are separated from assumptions and unresolved questions.
- Privacy/legal/HR decisions are documented in restricted systems.
- Data exposure, control actions and policy follow-ups are assigned.

## False-positive and validation notes
Follow employment/privacy/data-protection requirements. SIEM anomalies alone do not establish malicious intent.

Do not treat an alert name, rarity score, or single query result as proof of compromise. Correlate independent telemetry and document unavailable sources.
