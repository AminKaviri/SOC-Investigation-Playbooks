# 08 — Suspicious Service and Scheduled Task

## Tier 1
- Record host, creator account, service/task name, executable path, trigger, and timestamp.
- Verify publisher/path and whether the change aligns with software deployment or maintenance.
- Review process ancestry and outbound connections from the service/task payload.

## SPL pivots
Service installation (System 7045):
```spl
index=wineventlog EventCode=7045 earliest=-7d
| table _time host ServiceName ImagePath ServiceType StartType AccountName
| sort - _time
```

Scheduled task creation (Security 4698):
```spl
index=wineventlog EventCode=4698 earliest=-7d
| table _time host SubjectUserName TaskName Message
| sort - _time
```

Related process execution:
```spl
index=sysmon EventCode=1 earliest=-24h
| search (CommandLine="*schtasks*" OR CommandLine="*New-ScheduledTask*" OR CommandLine="*sc.exe create*")
| table _time host User ParentImage Image CommandLine
| sort - _time
```

## Tier 2
- Validate binary signature/hash, file creation time, parent process, service account, and task XML where available.
- Hunt the same binary/hash/name across endpoints.
- Assess persistence and lateral-movement context.

## Escalation
Escalate unexpected service/task creation by unusual users, payloads in user-writable paths, encoded commands, or links to other suspicious events. Event IDs and fields depend on audit configuration.
