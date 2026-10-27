# SOC Tier 1 → Tier 2 / Incident Response Escalation Template

Use the approved incident-management channel. For critical or actively harmful incidents, follow the on-call procedure immediately; do not wait to perfect this write-up. Avoid secrets and unnecessary personal data.

## Escalation header
- **Subject:** [URGENT / HIGH] [Incident ID] — [scenario] — [primary entity]
- **Incident ID / SIEM alert:**
- **Escalated by / team:**
- **UTC timestamp:**
- **Severity and rationale:**
- **Affected critical asset or privileged identity:**

## Executive summary
In 2–4 sentences, state what was observed, where and when, what is confirmed, what remains uncertain, and why Tier 2/IR intervention is required.

## Evidence and timeline
- First / last seen (UTC):
- Observed entities (host, user, source IP, destination, app, resource):
- Key event IDs or evidence references:
- Relevant ATT&CK technique (observed behavior vs hypothesis):
- SPL searches run, indexes/time ranges, hit counts:
- Correlated sources and findings:
- Missing telemetry or scope limitations:

## Impact and current state
- Confirmed impact:
- Potential impact:
- Is activity ongoing? [Yes / No / Unknown]
- Current containment and verification:
- Business owner / service impact:
- Data sensitivity / privacy concern:
- Related incidents or hosts:

## Requested Tier 2 / IR actions
- [ ] Validate scope and build a full timeline
- [ ] Hunt indicators across the environment
- [ ] Assess credential/session compromise and persistence
- [ ] Decide on endpoint / identity / network containment
- [ ] Preserve evidence and coordinate collection
- [ ] Engage system owner, identity, cloud, privacy/legal, HR or finance as appropriate

Specific question or decision needed:
Deadline / operational constraint:

## Communication and handoff
- Incident commander / on-call notified at (UTC):
- Owner accepting handoff:
- Next update due:
- Ticket / channel link:
