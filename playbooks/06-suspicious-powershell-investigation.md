# 06 — Suspicious PowerShell Investigation

## Tier 1
- Capture host, user, timestamp, full command line, parent process, and script-block logging availability.
- Look for encoded commands, download cradles, hidden windows, unusual parent processes, and unexpected network connections.
- Treat obfuscation as a lead, not proof of maliciousness.

## SPL pivots
```spl
index=sysmon EventCode=1 earliest=-24h
| search (Image="*\\powershell.exe" OR Image="*\\pwsh.exe")
| table _time host User ParentImage Image CommandLine ProcessGuid
| sort - _time
```

```spl
index=wineventlog (EventCode=4103 OR EventCode=4104) earliest=-24h
| table _time host User EventCode Message ScriptBlockText
| sort - _time
```

```spl
index=sysmon EventCode=3 earliest=-24h
| search (Image="*powershell.exe" OR Image="*pwsh.exe")
| table _time host User Image DestinationIp DestinationPort
| sort - _time
```

## Tier 2
- Reconstruct script content and process ancestry; correlate file writes, DNS, network, scheduled tasks, and authentication.
- Determine whether commands were administrative, software deployment, or attacker-driven.
- Hunt matching command fragments across hosts.

## Escalation
Escalate suspicious script execution with payload download, credential access, persistence, or C2 evidence. Confirm logging coverage before treating absent 4104 events as exculpatory.
