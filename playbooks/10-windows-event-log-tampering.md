# 10 — Windows Event Log Tampering

## Tier 1
- Check for Security log clear event 1102 and System log clear event 104, where collected.
- Identify actor, host, time, and surrounding activity; look for logging service changes or commands such as wevtutil.
- Treat telemetry gaps as a lead and verify collector/forwarder health.

## SPL pivots
```spl
index=wineventlog (EventCode=1102 OR EventCode=104) earliest=-30d
| table _time host EventCode SubjectUserName User Message
| sort - _time
```

```spl
index=sysmon EventCode=1 earliest=-7d
| search (CommandLine="*wevtutil* cl *" OR CommandLine="*Clear-EventLog*" OR CommandLine="*Remove-EventLog*")
| table _time host User ParentImage Image CommandLine
| sort - _time
```

## Tier 2
- Correlate with endpoint protection, process execution, service changes, and log-forwarding health.
- Determine whether clearing was authorized maintenance or attacker defense evasion.
- Preserve remaining evidence and escalate according to incident policy.

## Escalation
Escalate unexplained log clearing, disabled collection, or log tampering combined with suspicious activity. A missing event alone does not prove malicious deletion.
