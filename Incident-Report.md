# Incident Report: LOG(N) Pacific Cyber Range // Northpeak Descent Intrusion
**Date:** July 12, 2026 | **Author:** Danielle Respes

## Executive Summary
*Status: Initial Phase (Active Hunting).* Investigating unauthorized access to Northpeak Logistics estate observed on June 16, 2026. Preliminary analysis focused on identifying the initial foothold across a mixed Windows/Linux environment.

## Phase 00 — Baseline & Setup Confirmation

Setup gate cleared. A scoped process-event count across the three Northpeak hosts
confirmed workspace access, a working host filter, and telemetry present in the
intrusion window.

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-06-16 18:00) .. datetime(2026-06-17 02:00))
| where DeviceName has_any ("npt-ws01","npt-srv01","npt-linux01")
| summarize Events = count() by DeviceName
*   **Gate Phrase:** "Northpeak hunter ready."
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
