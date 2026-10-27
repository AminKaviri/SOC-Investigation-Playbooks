# Incident Report Template

Use during or immediately after triage. Use UTC timestamps, distinguish observations from hypotheses, and do not include secrets or unnecessary personal data.

## 1. Incident Summary

| Field | Value |
|---|---|
| Incident / ticket ID | |
| Detection name / source | |
| First seen / last seen (UTC) | |
| Analyst / team | |
| Severity and rationale | |
| Status | New / Triage / Contained / Escalated / Monitoring / Closed |
| Incident category | |
| ATT&CK techniques (observed vs suspected) | |
| Confidence and key uncertainty | |

## 2. Scope and affected assets

| Entity | Type / owner | Criticality | Evidence source | Status |
|---|---|---|---|---|
| | Host / identity / app / data / network | | | |

## 3. Timeline

| Time UTC | Observed event | Source / event ID | Confidence | Analyst note |
|---|---|---|---|---|
| | | | Observed / inferred | |

## 4. Technical evidence and Splunk pivots
- Query time range:
- Indexes / sourcetypes:
- SPL run and purpose:
- Result count / key event IDs:
- Related files, hashes, URLs, domains, IPs, accounts and sessions:
- Evidence location / custody reference:
- Telemetry missing or searched sources with no results:

## 5. Investigation findings

### Confirmed observations
- 

### Hypotheses not yet confirmed
- 

### Scope and impact
- Systems, identities, data and business services potentially affected:
- Lateral movement / persistence / credential exposure:
- Data accessed, staged, transferred or destroyed:
- Business and operational impact:

## 6. Containment, eradication and recovery

| Action | Requested/approved by | Executed by | UTC time | Result / verification |
|---|---|---|---|---|
| | | | | |

Record exceptions, outage risks, deferred actions and validation evidence.

## 7. Escalation and communications
- Escalated to / role:
- Time and channel:
- Criteria met / reason:
- System owner / incident commander:
- Privacy, legal, HR, finance or external notification referrals (where applicable):

## 8. Final disposition
- [ ] True positive / confirmed incident
- [ ] Benign positive / authorized activity
- [ ] False positive / detection defect
- [ ] Inconclusive / telemetry or scope limitation

Rationale:
Residual risk and monitoring:
Outstanding tasks and owners:
Closed by / UTC time:

## 9. Lessons learned
- Detection tuning:
- Telemetry and logging gaps:
- Process/control changes:
- Follow-up owner and target date:
