# 21 — VPN and Remote Access Anomaly

**Default severity:** Medium–Critical  
**Initial response target:** Triage: 30 minutes; elevate immediately for privileged users or active remote intrusion.  
**MITRE ATT&CK:** T1133 (External Remote Services), T1078 (Valid Accounts), T1110 (Brute Force)

## Objective
Determine whether VPN, ZTNA, SSH gateway or other remote-access activity is authorized, compromised-account use, or a route into internal systems.

## Indicators that trigger this playbook
- Successful VPN authentication after unusual failures or MFA anomalies.
- Sign-in from unfamiliar location/device/ASN, impossible travel, or outside approved support window.
- Remote access by privileged account from unmanaged device.
- VPN session followed by lateral movement, scanning or access to sensitive assets.

## Pre-triage evidence checklist
- [ ] Account, source IP/device, gateway, auth/MFA result, assigned VPN IP and session duration.
- [ ] VPN/IdP logs, source reputation, geolocation, user profile and device posture.
- [ ] Internal destinations, DNS/proxy, EDR and authentication events after connection.
- [ ] Travel, vendor access, support tickets and expected egress IPs.

## Tier 1 triage workflow
### Step 1 — Validate authentication outcome
Determine failed, successful or session-established status; correlate MFA and device posture.

### Step 2 — Compare with known behavior
Check source/device, ASN, geo, time, VPN profile, assigned address and corporate/VPN egress.

### Step 3 — Trace internal access
Identify internal destinations and services reached; correlate logons and process activity.

### Step 4 — Look for follow-on activity
Search remote execution, file shares, privilege changes, unusual transfer and multi-host targeting.

### Step 5 — Contain the session
Coordinate session termination, credential/session revocation, source blocking or device isolation as evidence supports.

### Step 6 — Confirm safe re-entry
Verify identity/device through trusted channels and enforce expected MFA/device controls.

## Splunk SPL investigation pivot
Adapt index, sourcetype, field names, event codes and time ranges to your environment. This is an investigation starting point, not a validated production detection.

```spl
index=vpn earliest=-24h
| eval account=coalesce(user, username, src_user), src_ip=coalesce(src, src_ip, client_ip)
| stats count values(action) as actions values(reason) as reasons values(device) as devices values(dest) as internal_targets min(_time) as first_seen max(_time) as last_seen by account src_ip
| sort - count
```

## Containment guidance
Use approved authority and incident procedures. Preserve relevant logs and evidence before disruptive action when feasible.

- Preserve session IDs, assigned addresses and destination logs before retention expires.
- Terminate sessions or disable access through approved gateway/identity controls when compromise is credible.
- Do not blanket-block shared carrier, corporate VPN or travel egress without checking impact.
- Review vendor access with the owning business unit before revocation unless active harm demands emergency action.

## Escalation criteria
Escalate to Tier 2 / IR when any of the following apply:

- Privileged identity or critical-system access is involved.
- Remote session is followed by lateral movement, data staging or security-control changes.
- Multiple accounts/devices share the source or a compromised remote-access appliance is suspected.

## Closure criteria
Close only when the evidence supports a disposition, scope and remaining gaps are recorded, and actions are complete or assigned.

- Session and internal access are explained or confirmed malicious and scoped.
- Credential/device/session actions and exceptions are documented.
- Remote-access policy or monitoring gaps are tracked.

## False-positive and validation notes
Normalize provider-specific fields. IP geolocation and reputation are contextual signals, not proof of compromise.

Do not treat an alert name, rarity score, or single query result as proof of compromise. Correlate independent telemetry and document unavailable sources.
