# Incident Report: Northpeak Descent Intrusion
**Date:** July 12, 2026 | **Author:** Danielle Respes | **Range:** LOG(N) Pacific Cyber Range

## Executive Summary

*Status: Active hunting.* Someone gained unauthorized access to the Northpeak Logistics estate on the evening of June 16, 2026, across a mixed Windows and Linux environment. I'm working the incident from the evidence to reconstruct what actually happened, in order.

## Methodology

This is a practice hunt and my first extended KQL investigation, so I'm learning the query language as I work. I use an AI assistant as a syntax tutor while doing the analysis myself: reading each result, choosing the pivots, and drawing the conclusions. My running syntax notes and dead ends live in [kql-learning-log.md](./kql-learning-log.md).

## Phase 00: Baseline and Setup

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

**What I'm not concluding yet:** a loud host isn't automatically the compromised one. That 7,175 could be the real workload, or just a naturally noisy Linux box (cron, services, automation). I'm holding it as a lead to test in Phase 02, not an answer.

## Phase 01: Initial Access

The alert queue is a wall of failed logons that looks like brute force. The brief warned me not to trust that, and it was right: the real entry authenticated cleanly and never tripped an alarm. So I set the failures aside and went looking for the quiet success from outside.

**Question:** which logons succeeded, from an address outside the estate?

```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2026-06-16 18:00) .. datetime(2026-06-17 02:00))
| where DeviceName has_any ("npt-ws01","npt-srv01","npt-linux01")
| where ActionType == "LogonSuccess"
| where LogonType == "RemoteInteractive"
| project AccountName, ActionType, DeviceName, InitiatingProcessFolderPath, LogonType, RemoteIP, RemoteIPType
```

**What I found:**

- **Source:** `148.64.103.173`, with `RemoteIPType` of `Public`, confirming an external origin. That's the entry point.
- **Account:** `sancadmin`, a valid admin account. Nothing was exploited; they logged in with legitimate credentials.
- **Method:** `LogonType` of `RemoteInteractive` on the Windows hosts, which is RDP.

**How I got there:** I reused the scoped base from Phase 00 (table, time, host), then filtered to `LogonSuccess` to clear the brute-force noise, checked `RemoteIPType` to confirm the source was external, and used `LogonType` to pin the method as RDP. I took one of two hints (15 points) for the decoy versus signal direction, and I want to reach that instinct on my own next time.

**Q01 answer:** `148.64.103.173, RDP`
