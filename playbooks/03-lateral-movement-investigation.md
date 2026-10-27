# 03 — Lateral Movement Investigation

## Objective
Determine whether an account or host was used to access additional systems unexpectedly.

## Tier 1
- Record source/destination hosts, account, time, logon type, and alert context.
- Review Windows 4624 logon types 3 (network) and 10 (RemoteInteractive), where available.
- Search for remote service creation (7045), admin-share access, and unusual process launches.
- Compare against jump hosts, admin tooling, maintenance windows, and account role.

## Splunk SPL
```spl
index=wineventlog EventCode=4624 earliest=-24h (LogonType=3 OR LogonType=10)
| stats count values(host) as destinations values(IpAddress) as sources values(LogonType) as logon_types by TargetUserName
| sort - count
```

```spl
index=wineventlog EventCode=7045 earliest=-24h
| table _time host ServiceName ImagePath ServiceType StartType AccountName
| sort - _time
```

Sysmon process pivots:
```spl
index=sysmon EventCode=1 earliest=-24h
| search (CommandLine="*psexec*" OR CommandLine="*wmic*" OR CommandLine="*sc.exe create*" OR CommandLine="*winrs*" OR CommandLine="*\\ADMIN$*")
| table _time host User ParentImage Image CommandLine
| sort - _time
```

## Tier 2
- Build a source-to-destination timeline and identify first-seen host/account relationships.
- Correlate logon events with service/task creation, process execution, and network telemetry.
- Verify approved administration activity with the system owner.

## Escalation / closure
Escalate unexplained privileged access, multiple internal destinations, remote execution, or confirmed compromise. Do not label ordinary network logons as lateral movement without corroboration.
