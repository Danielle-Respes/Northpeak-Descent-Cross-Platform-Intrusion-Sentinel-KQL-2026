# Incident Report: [LOG(N) Pacific Cyber Range // Northpeak Descent Intrusion
**Date:** July 12, 2026 | **Author:** Danielle Respes

## Executive Summary
*Status: Initial Phase (Active Hunting).* Investigating unauthorized access to Northpeak Logistics estate observed on June 16, 2026. Preliminary analysis focused on identifying the initial foothold across a mixed Windows/Linux environment.

## Phase 0: Environment Validation
*   **Status:** Cleared.
*   **Method:** Confirmed connectivity to `law-cyber-range` Sentinel workspace.
*   **Verification:** Verified host telemetry visibility using:
    `DeviceEvents | where DeviceName has_any ("npt-ws01","npt-srv01","npt-linux01") | summarize count() by DeviceName`
*   **Gate Phrase:** "Northpeak hunter ready."

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
