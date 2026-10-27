# 24 — Linux Host Compromise and Suspicious Privileged Activity

**Default severity:** High–Critical  
**Initial response target:** Triage: 15–30 minutes based on asset criticality.  
**MITRE ATT&CK:** T1059.004 (Unix Shell), T1543.002 (Systemd Service), T1053.003 (Cron), T1078 (Valid Accounts)

## Objective
Identify suspicious Linux execution, privilege escalation, persistence or access, and determine if a single host or broader fleet is impacted.

## Indicators that trigger this playbook
- Unexpected sudo/root activity, new user/key, modified cron/systemd unit or shell from a web process.
- SSH anomalies, unusual process/network behavior or security-agent tampering.
- New binaries in temporary paths or package changes outside maintenance windows.
- Host alerts correlate with cloud control-plane activity or unusual outbound connections.

## Pre-triage evidence checklist
- [ ] Hostname, cloud/VM ID, account/UID, source IP, process command line, path/hash and UTC time.
- [ ] Auth logs, auditd, journald, process/network telemetry, EDR, SSH authorized_keys and sudo logs.
- [ ] Patch/change windows, admin automation, orchestration/CI job and service ownership.
- [ ] Data volumes and log coverage; preserve snapshots only under approved IR process.

## Tier 1 triage workflow
### Step 1 — Establish access/privilege timeline
Review SSH auth, sudo/su activity, new users/groups, authorized_keys, PAM changes and logins from unexpected sources.

### Step 2 — Review process ancestry and artifacts
Identify shells/interpreters, parent process, binary location, signer/package owner, permissions and child processes.

### Step 3 — Check persistence
Inspect systemd units/timers, cron, init scripts, shell profiles, SSH keys, new services and startup files.

### Step 4 — Inspect network/workload behavior
Correlate listening ports, outbound connections, DNS, cloud metadata access, container/orchestrator activity and data transfer.

### Step 5 — Scope across fleet
Hunt same key, hash, command, username and source IP across hosts; consider shared image/pipeline compromise.

### Step 6 — Contain and recover
Coordinate isolation/snapshot, key rotation, workload redeployment from known-good images and patching while preserving evidence and continuity.

## Splunk SPL investigation pivot
Adapt index, sourcetype, field names, event codes and time ranges to your environment. This is an investigation starting point, not a validated production detection.

```spl
index=linux_auth earliest=-24h
| eval actor=coalesce(user, src_user, uid), src_ip=coalesce(src, src_ip, rhost)
| stats count values(action) as actions values(process) as processes values(reason) as reasons by host actor src_ip
| sort - count
```

## Containment guidance
Use approved authority and incident procedures. Preserve relevant logs and evidence before disruptive action when feasible.

- Preserve auth, audit, journal, process and cloud control-plane logs before rotation.
- Rotate keys/secrets from a clean management plane and assess shared credentials across fleet.
- For critical workloads, coordinate isolation/redeployment with service owners.
- Check image/build pipeline integrity when multiple hosts exhibit same persistence.

## Escalation criteria
Escalate to Tier 2 / IR when any of the following apply:

- Root access, cloud metadata/credential access, security-agent tampering or persistence is confirmed.
- Production critical systems, container control plane or several hosts involved.
- Logs are missing during suspected activity or automation compromise is plausible.

## Closure criteria
Close only when the evidence supports a disposition, scope and remaining gaps are recorded, and actions are complete or assigned.

- Entry path, identities, processes and persistence are documented.
- Compromised keys/secrets are rotated and host integrity verified or rebuilt from trusted images.
- Fleet hunt and logging/control gaps are completed or assigned.

## False-positive and validation notes
Requires Linux authentication/audit telemetry. Query fields differ for journald, auditd, syslog and EDR.

Do not treat an alert name, rarity score, or single query result as proof of compromise. Correlate independent telemetry and document unavailable sources.
