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

```

<img width="945" height="765" alt="process-events-by-host-pie" src="https://github.com/user-attachments/assets/848949da-2bd5-4312-987f-fcb2f82493e9" />



**Observation:** the two Windows hosts sit at a near-identical baseline (~1,050 each),
while npt-linux01 carries roughly 7x that volume — ~78% of all process telemetry.


**Working note (not yet a conclusion):** this imbalance could mean the Linux host was
the busier foothold, or simply that it's noisier by nature (cron, services, routine
automation). Which of the two is unknown at this stage. Per the brief, most estate
activity is automation, so this 7,175 figure is the haystack Phase 02 will sift when
separating the operator's hands from the machine's routine.
  

## Phase 1: Initial Access
*   **Objective:** Identify the true entry point and reconcile the "brute-force" decoy traffic vs. legitimate successful authentications.
*   **Hypothesis:** The operator utilized a valid account to bypass initial detection.
*   **Current Findings:**
    *   Filtered `DeviceLogonEvents` for `LogonType == 10` (Remote Interactive).
    *   *Self-Correction/Note:* Initial queries included too much noise from generic estate logs. Applying strict host filter resolved data visibility. 
    *   *Observation:* Identified successful remote logons. Currently mapping timestamps between Windows and Linux hosts to determine sequence (Patient Zero).

## Peer Review & Methodology Notes
*   **Current Wall:** Differentiating between the operator's initial foothold and background noise when both use valid accounts. 
*   **Pivot Strategy:** Pivoting on `RemoteIP` to correlate activity across hosts rather than focusing solely on `AccountName`.
