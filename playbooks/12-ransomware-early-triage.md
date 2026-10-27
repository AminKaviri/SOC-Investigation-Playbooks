# 12 — Ransomware Early Triage

## Priority
Potential ransomware is time-sensitive. Follow the organization's incident command and containment process; do not independently shut down systems or delete artifacts.

## Tier 1
- Capture alert, affected host/user, timestamp, ransom-note path, sample hashes, and observed file impact.
- Look for shadow-copy deletion, recovery inhibition, mass file changes, and suspicious remote execution.
- Escalate immediately when encryption or destructive activity appears active.

## SPL pivots
Potential recovery inhibition:
```spl
index=sysmon EventCode=1 earliest=-24h
| search (CommandLine="*vssadmin*delete shadows*" OR CommandLine="*wbadmin*delete*" OR CommandLine="*bcdedit*recoveryenabled*no*" OR CommandLine="*wmic*shadowcopy*delete*")
| table _time host User ParentImage Image CommandLine
| sort - _time
```

Potential ransom-note file writes (tune names to local telemetry):
```spl
index=sysmon EventCode=11 earliest=-24h
| search (TargetFilename="*README*RECOVER*" OR TargetFilename="*DECRYPT*" OR TargetFilename="*HOW_TO_RESTORE*")
| table _time host Image TargetFilename
| sort - _time
```

## Tier 2 / incident response
- Correlate endpoint detection, file-change telemetry, process trees, SMB activity, identity events, and backups.
- Determine spread, affected shares, privileged accounts, and first observed execution.
- Preserve evidence and coordinate isolation, credential actions, and recovery with incident command.

## Escalation / closure
Escalate immediately for active encryption, recovery inhibition, or multi-host impact. Suspicious commands alone are indicators to investigate, not definitive ransomware proof.
