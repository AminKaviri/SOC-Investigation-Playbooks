# 01 — Phishing Triage

**Default severity:** Medium–High  
**Triage target:** 15–30 minutes, based on impact  
**MITRE ATT&CK:** T1566.001, T1566.002, T1204

## Objective
Determine whether a reported email is malicious, whether a user interacted with it, and whether endpoint or identity compromise followed.

## Indicators that trigger this playbook
- User-reported suspicious message, email-gateway alert, malicious URL or attachment detection.
- Office/email-client child process, suspicious download, domain reputation alert, or multiple recipients for the same campaign.

## Pre-triage evidence checklist
- [ ] Original email and headers; sender/recipient, subject, Message-ID, timestamps, URL and attachment hash.
- [ ] User interaction status: clicked, opened, executed, or entered credentials; affected mailbox and host.
- [ ] Email trace, endpoint process tree, DNS/proxy, identity sign-ins and related recipients.

## Tier 1 triage workflow
### Step 1 — Check interaction and exposure
Determine whether the user clicked, opened, ran content, or submitted credentials. Contact through a trusted channel, not the potentially compromised mailbox.

### Step 2 — Analyze message evidence
Review full headers, sender/Reply-To alignment, authentication results, URL and attachment reputation in approved tools. Defang indicators before sharing.

### Step 3 — Search the campaign
Use message IDs, sender, subject, URL/hash and recipients to scope delivery and actions across mailboxes.

### Step 4 — Correlate endpoint and identity
For interaction, examine browser/download/process telemetry and authentication, MFA, inbox rules and OAuth changes.

### Step 5 — Scope and contain
Hunt shared indicators, preserve the message and logs, and coordinate email/endpoint/identity actions based on confirmed behavior.

## Splunk SPL investigation pivots

Adapt indexes, sourcetypes, field names, event codes and time range to your environment. These are investigation starting points, not production-certified detections.

```spl
index=email earliest=-7d
| eval sender=coalesce(sender, from, src_user), recipient=coalesce(recipient, to, dest_user), subject=coalesce(subject, Subject), msgid=coalesce(message_id, MessageID)
| stats count values(recipient) as recipients values(subject) as subjects values(url) as urls values(attachment_name) as attachments values(msgid) as message_ids by sender
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
