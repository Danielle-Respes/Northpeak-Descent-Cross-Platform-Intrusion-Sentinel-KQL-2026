# Incident Report: Northpeak Descent Intrusion
**Date:** July 12, 2026 | **Author:** Danielle Respes | **Range:** LOG(N) Pacific Cyber Range

## Executive Summary

*Status: Active hunting.* Someone gained unauthorized access to the Northpeak Logistics estate on the evening of June 16, 2026, across a mixed Windows and Linux environment. his report captures my investigative steps, the hurdles I hit, and the process I'm using to learn KQL and threat hunting.

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
