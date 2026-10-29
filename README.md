<img width="977" height="298" alt="Screenshot 2026-07-10 at 6 44 46 PM" src="https://github.com/user-attachments/assets/25afcbe8-3711-43da-b847-e579ed2eeee4" />

# Northpeak Descent: Cross-Platform Intrusion Investigation

**Senior Endpoint Technician | Cyber Defense | GRC | IAM**

> **Status:** Hunt complete. All five sections solved, 19 flags (Section 1 in July, Sections 2–5 on October 29).

I'm a Senior Endpoint Technician moving into cyber defense. I'm using my background in system administration to build threat hunting and security analysis skills, and I document my process clearly so my work is transparent and useful to others.

---

## Mission

My mission is to learn, document, and grow. This repo tracks my move from endpoint management into a security role, building toward cyber defense, GRC, and IAM. It's a self-directed practice project in the LOG(N) Pacific Cyber Range, and my first time through this scenario, so I'm treating it as reps: real telemetry, real dead ends, and understanding the why behind the data.

## Read the Investigation

**→ [Incident Report](./Incident-Report.md)** — the full write-up: initial access, Linux recon, pivot and persistence, command and control, and exfiltration, plus a full timeline, IOCs and MITRE mapping.

**→ [KQL Learning Log](./kql-learning-log.md)** — the syntax I learned, the dead ends, and the queries behind each finding.

**→ [Prep for the July 15 Community Debrief](./debrief-prep-july-15.md)** — where I got stuck, how I worked each question, and what I'm bringing to the group.

## Why this matters for the roles I want

I'm building toward Cyber Defense, GRC, and IAM, and I'm using this hunt to practice the skills each one needs:

- **Cyber Defense / SOC:** working real telemetry in Microsoft Sentinel and KQL, and pivoting from alert noise to the activity that actually matters.
- **GRC:** learning to document an investigation clearly and map findings to frameworks like the NIST Cybersecurity Framework.
- **Remote work:** writing this up as a standalone artifact someone can follow without me in the room.

## Attack Chain

<img width="1485" height="1035" alt="attack-chain" src="https://github.com/user-attachments/assets/7991d735-93a2-4b92-be7e-dccb18bc0ca8" />


The operator connected over RDP from `148.64.103.173` (workstation `loranse`) into `npt-ws01` first at 20:57, then reached `npt-srv01` (21:58) and `npt-linux01` (22:01), all on the valid `sancadmin` admin account. *(The diagram above covers Section 1, initial access.)*

From there:

1. **Linux recon:** `sudo -l` (after a `sudo -1` typo), bash `/dev/tcp` checks on RDP 3389, then NetExec installed via pipx.
2. **Pivot:** NetExec over SMB from the Linux host (`10.2.0.30`) back into `npt-ws01` as `sancadmin`.
3. **Persistence:** after confirming local admin rights (`findstr S-1-5-32-544`), an HKCU Run key `NorthpeakSyncTray` launching a hidden PowerShell script.
4. **C2:** beacons to three look-alike subdomains of `sync-northpeak.com`. Only one showed up in network telemetry; one was hidden in a Base64 `-EncodedCommand`.
5. **Impact:** `customer_data_export_20260616.csv` uploaded from `npt-srv01` to `cdn.sync-northpeak.com` in a second RDP session at 23:44.

No exploits, no security tooling touched: valid accounts and living off the land the whole way. Reconstructed from Sentinel/MDE telemetry.

## Investigation Progress

| Section | Flags | Focus | Status |
|---|---|---|---|
| 0 Setup Gate | Q00 | Confirm workspace, submit gate phrase | Complete |
| 1 Initial Access | Q01–Q04 | Real entry, first foothold, operator workstation, server vector | Complete |
| 2 Linux Recon | Q05–Q07 | Sudo enumeration, reachability check, tooling | Complete |
| 3 Pivot & Persistence | Q08–Q10 | Lateral movement, human vs machine PowerShell, Run key | Complete |
| 4 Command & Control | Q11–Q15 | Beacon domains, encoded beacon, noise vs operator, rhythm, TTL | Complete |
| 5 Impact | Q16–Q19 | Exfil, session correlation, how they stayed quiet, admin check | Complete |

## Investigation Journal

### July 12

- **Q00 — Baseline:** confirmed the workspace and ran the baseline count.
- **Q01 — Initial Access:** real entry was an external RDP login from `148.64.103.173` on the `sancadmin` admin account.
- **Q02 — Order of Footholds:** used timestamps to prove Windows (`npt-ws01`, 20:57) was first, over an hour before Linux (22:01). Debunked the "Linux first" assumption.
- **Q03 — Operator Workstation:** found the attacker's own machine, `loranse`, leaking its name on every session.
- **Q04 — srv01 Access Vector:** reconstructed the server's own external entry, RDP from `148.64.103.173`, RemoteInteractive. Did this one solo, no hints.

### October 29

Came back and finished Sections 2–5 in one session, with much heavier AI help than Section 1 (the AI drafted most queries; I ran them and brought the results back). Details per flag are in the incident report.

- **Linux Recon:** `sudo -l`, `/dev/tcp` on 3389, NetExec.
- **Pivot & Persistence:** `sancadmin` from `10.2.0.30` into `npt-ws01`; `explorer.exe` was the human's PowerShell; HKCU Run key `NorthpeakSyncTray`.
- **C2:** `status`, `updates`, `cdn` .sync-northpeak.com; decoded the UTF-16LE beacon; `gc_worker.exe` was the noise; the 2-second spacing showed a script; TTL as the DNS indicator.
- **Impact:** customer export out of `npt-srv01` in the second session; no defense tampering, valid accounts and living off the land; operator checked local Administrators membership.
- **Cost:** used Hint 2 on Beacon Rhythm (−15) after two wrong answers, and had one wrong submission on the Run key from a curly quote.

## Hunting Principles

These are the principles from the hunt brief that I'm using as my north star, to keep the noise from drowning out the signal:

1. Filter first: scope every query to the Northpeak hosts.
2. Separate signal from noise: the brute-force storm is bait.
3. Prove the order: two platforms, let the timestamps decide.
4. Pivot on identity: one account and one address thread the case.
5. Separate human from machine: hands-on-keyboard vs automation.
6. Treat absence as evidence: what they did not do matters too.
7. Then tell the story: entry, pivot, persistence, C2, impact.

## Technical Stack

- **SIEM:** Microsoft Sentinel
- **Endpoint telemetry:** Microsoft Defender for Endpoint (MDE)
- **Query language:** Kusto Query Language (KQL)
- **Mode:** Practice, working after contest close to learn properly


---

<details>
<summary><strong>Scenario and hunt details</strong></summary>

<br>

**THREAT DETECTED // NORTHPEAK LOGISTICS ESTATE**
Intrusion window: 16 Jun 2026, 20:00 to 00:30 UTC
Platforms: Windows + Linux

Overnight the Northpeak Logistics estate lit up: a cross-platform intrusion using valid accounts, a chain that runs from a quiet foothold through to impact across both Windows and Linux hosts. The alert queue is loud with failed logons. It looks like brute force. It is not.

> "Night shift already logged a cause on this one. I am not sold. Work the incident yourself, follow the evidence, and tell me what actually happened, in order." — Hunt Lead, SancLogic

**Environment**

| Field | Details |
|---|---|
| Target | Northpeak Logistics: Windows estate + Linux host |
| SIEM | Microsoft Sentinel |
| Telemetry | Microsoft Defender XDR + Sentinel |
| Workspace | LAW-Cyber Range Sentinel |
| Attack Chain | Initial Access, Recon, Pivot and Persistence, C2, Impact |
| Community Debrief | Wednesday July 15, 2026, 22:00 UK / 21:00 UTC |

**Attack Timeline**

| UTC | Event | Host | Confidence |
|---|---|---|---|
| ~20:00 | Intrusion window opens | Northpeak estate | |
| 20:57 | First foothold: external RDP login, sancadmin from 148.64.103.173 | npt-ws01 | Confirmed (Q02) |
| 21:58 | External RDP login (RemoteInteractive), sancadmin | npt-srv01 | Confirmed (Q04) |
| 22:01 | Linux accessed, over an hour after Windows | npt-linux01 | Confirmed (Q02) |
| - | Operator workstation identified: loranse (source of the RDP sessions) | loranse | Confirmed (Q03) |
| 22:11–22:16 | `sudo -1` typo, then `sudo -l` | npt-linux01 | Confirmed (Q05) |
| 22:21 | `/dev/tcp` checks on 3389 against 10.2.0.10 and 10.2.0.20 | npt-linux01 | Confirmed (Q06) |
| 22:29–22:31 | NetExec installed via pipx | npt-linux01 | Confirmed (Q07) |
| 22:32–22:37 | NetExec SMB pivot as sancadmin from 10.2.0.30 | npt-ws01 | Confirmed (Q08) |
| 22:43 | `whoami /groups \| findstr S-1-5-32-544` after RDP re-entry | npt-ws01 | Confirmed (Q19) |
| 23:04 | HKCU Run key `NorthpeakSyncTray` planted | npt-ws01 | Confirmed (Q10) |
| 23:15–23:28 | Beacons to status / updates / cdn .sync-northpeak.com | npt-ws01 | Confirmed (Q11–Q14) |
| 23:42 | Second RDP session, Unlock | npt-srv01 | Confirmed (Q17) |
| 23:44 | `customer_data_export_20260616.csv` uploaded to cdn.sync-northpeak.com | npt-srv01 | Confirmed (Q16) |
| ~00:30 | Intrusion window closes | | |

</details>

---

Hunt built by Dogukan Oruc // LOG(N) Pacific Cyber Range

[Portfolio](https://github.com/Danielle-Respes) | [LinkedIn](https://www.linkedin.com/in/danielle-respes-64113767/)
