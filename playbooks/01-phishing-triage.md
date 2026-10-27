# 01 — Phishing Triage

## Objective
Determine whether a reported email is malicious, whether a user interacted with it, and whether endpoint or identity compromise followed.

## Tier 1 workflow
1. Preserve the original message and headers; record sender, recipient, subject, timestamps, URLs, attachment hashes, and message ID.
2. Check sender/domain reputation using approved tools. Do not open attachments or URLs directly on an analyst workstation.
3. Search mail telemetry for other recipients and matching indicators.
4. Establish whether the user clicked, opened, or executed content. Correlate endpoint events around the interaction.
5. Escalate if execution, credential submission, suspicious authentication, persistence, or multiple recipients are identified.

## Splunk SPL pivots
Adapt index and field names to your environment.

```spl
index=email earliest=-7d
| search (sender="*" OR src="*" OR subject="*")
| stats count values(recipient) values(subject) values(url) values(attachment_name) by sender
| sort - count
```

```spl
index=sysmon EventCode=1 earliest=-24h
| search (CommandLine="*\Downloads\*" OR CommandLine="*AppData*" OR Image="*\powershell.exe" OR Image="*\wscript.exe" OR Image="*\mshta.exe")
| table _time host user ParentImage Image CommandLine
| sort - _time
```

```spl
(index=wineventlog EventCode=4624) earliest=-24h
| stats count values(IpAddress) values(LogonType) by host TargetUserName
| sort - count
```

## Tier 2 workflow
- Build a timeline across email, browser/download, process, DNS/network, and authentication events.
- Hunt the sender, URL, hash, filename, and related infrastructure across the environment.
- Confirm whether credentials were entered; review sign-ins, MFA events, mailbox rules, and account changes.
- Preserve evidence and coordinate containment under incident-response policy.

## Escalation / closure
Escalate confirmed execution, credential theft, suspicious post-click authentication, persistence, or campaign spread. Close as benign only with documented evidence and no unresolved telemetry gaps.
