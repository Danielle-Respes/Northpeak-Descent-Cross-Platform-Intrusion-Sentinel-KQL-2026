# Incident Report: Northpeak Descent Intrusion
**Date:** July 12, 2026 | **Author:** Danielle Respes | **Range:** LOG(N) Pacific Cyber Range

## Executive Summary

*Status: Active hunting.* Someone gained unauthorized access to the Northpeak Logistics estate on the evening of June 16, 2026, across a mixed Windows and Linux environment. This report captures my investigative steps, the hurdles I hit, and the process I'm using to learn KQL and threat hunting.

## Methodology

I use an AI assistant as a tutor to help me understand KQL syntax. It helps me learn the how and why behind the commands, which I then validate and interpret myself. My syntax notes and dead ends are in [kql-learning-log.md](./kql-learning-log.md).

## Q00: Baseline and Setup

Before hunting anything, I confirmed I was on the right workspace and could query it. One scoped count proved three things at once: access, a working host filter, and real data in the intrusion window.

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-06-16 18:00) .. datetime(2026-06-17 02:00))
| where DeviceName has_any ("npt-ws01","npt-srv01","npt-linux01")
| summarize Events = count() by DeviceName
```

**Gate phrase submitted:** `Northpeak hunter ready`

<img width="945" height="765" alt="process-events-by-host-pie" src="https://github.com/user-attachments/assets/848949da-2bd5-4312-987f-fcb2f82493e9" />

**What I noticed:** the two Windows hosts sit near 1,050 events each, but npt-linux01 carries about 7x that, roughly 78% of all process telemetry.

**Note:** high volume alone doesn't confirm compromise. The Linux count could be normal activity or the attacker's work. I'm treating it as a lead for Q02, not a conclusion.


## Q01: Initial Access

The alerts are full of failed logins, so it looks like brute force. But the brief said not to trust that, and it was right. The real entry logged in cleanly and never set off an alarm. So I stopped looking at the failures and went looking for the login that worked, from outside.

**Question:** which logins worked, from an address outside the estate?

```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2026-06-16 18:00) .. datetime(2026-06-17 02:00))
| where DeviceName has_any ("npt-ws01","npt-srv01","npt-linux01")
| where ActionType == "LogonSuccess"
| where LogonType == "RemoteInteractive"
| project AccountName, ActionType, DeviceName, InitiatingProcessFolderPath, LogonType, RemoteIP, RemoteIPType
```

**What I found:**

- **Source IP:** `148.64.103.173`. RemoteIPType is `Public`, so it's from outside. That's the way in.
- **Account:** `sancadmin`, a real admin account. Nothing was hacked; they just logged in with valid credentials.
- **How:** LogonType is `RemoteInteractive` on the Windows hosts, which means RDP.

**How I got there:** I started with the same base as  Q00 (table, time, host), then added `LogonSuccess` to drop the failed logins, checked `RemoteIPType` to confirm the source was outside, and used `LogonType` to find the method (RDP). I used one of the two hints (15 points) for the "it's a decoy, look at what succeeded" and I want to get to that on my own next time.

**Q01 answer:** `148.64.103.173, RDP`

## Q02: Which Foothold Came First

The obvious story, and the pie chart, both point to Linux. npt-linux01 has about 78% of all the process events, so it looks like the center of everything. The brief warned me not to trust that and to prove the order myself. Volume isn't order, so I put all three hosts on one timeline and let the timestamps decide.

<img width="612" height="355" alt="Screenshot 2026-07-12 at 2 25 35 PM" src="https://github.com/user-attachments/assets/2a2a525d-7257-49c9-9daf-3222f0f1cb61" />



**Question:** which host was accessed from outside first?

```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2026-06-16 18:00) .. datetime(2026-06-17 02:00))
| where DeviceName has_any ("npt-ws01","npt-srv01","npt-linux01")
| where ActionType == "LogonSuccess"
| where RemoteIPType == "Public"
| project TimeGenerated, DeviceName, AccountName, RemoteIP, LogonType
| sort by TimeGenerated asc
```

**What I changed from Q01:** I dropped the `LogonType == "RemoteInteractive"` filter. RDP logs as RemoteInteractive, which is a Windows thing, so keeping it would have hidden the Linux host completely and I'd have "proven" Windows first by accident. To compare the two platforms fairly, I filtered on external access (`RemoteIPType == Public`) instead of a Windows-only logon type, then sorted by time so the earliest access is the top row.

**What I found:** earliest external login from `148.64.103.173` (account `sancadmin`) on each host:

- **npt-ws01 (Windows): 20:57:54**
- npt-srv01 (Windows): 21:58:03
- **npt-linux01 (Linux): 22:01:38**

The first foothold was npt-ws01 at 20:57:54, over an hour before Linux was touched at 22:01:38. So Windows came first, not Linux. Same attacker on both (same account, same IP), just different platforms and different arrival times.

**Note on logon types:** npt-ws01 shows Network logins at 20:57:54 immediately followed by RemoteInteractive at 20:58:02, same IP. That's one RDP connection establishing: the network auth lands first, then the interactive session opens. The Linux logins are Network type, not RemoteInteractive. Both count as successful remote access from outside; the type just describes how each session authenticated.

**What this proves:** volume is not order. Linux looked central because it's noisy, but the timestamps show the operator started on the Windows workstation and reached Linux later. This is the "don't assume Linux first" trap the brief set, and the two timestamps side by side disprove it.

**Hint used:** 1 of 2 (25 points). The hint pointed me to find the earliest external access on each host and not stay on one platform, which is what led me to drop the Windows-only logon filter.

**Q02 answer:** `npt-ws01, 148.64.103.173`
