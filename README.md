
<img width="977" height="298" alt="Screenshot 2026-07-10 at 6 44 46 PM" src="https://github.com/user-attachments/assets/25afcbe8-3711-43da-b847-e579ed2eeee4" />

# Northpeak Descent: Cross-Platform Intrusion Investigation

**Senior Endpoint Technician | Cyber Defense | GRC | IAM**

> **Status:** Active investigation. Q00 and Q01 complete, working Q02 (Linux recon).

I'm a Senior Endpoint Technician moving into cyber defense. I'm using my background in system administration to build threat hunting and security analysis skills, and I document my process clearly so my work is transparent and useful to others.

---
## Mission

My mission is to learn, document, and grow. This repo tracks my move from endpoint management into a security role, building toward cyber defense, GRC, and IAM. It's a self-directed practice project in the LOG(N) Pacific Cyber Range, and my first time through this scenario, so I'm treating it as reps: real telemetry, real dead ends, and understanding the why behind the data.

## Read the Investigation

**→ [Incident Report](./Incident-Report.md)** — the full write-up: baseline, initial access, and the reconstructed chain as it develops.

**→ [Prep for the July 15 Community Debrief](./debrief-prep-july-15.md)** — where I got stuck, how I worked Q01, and the questions I'm bringing to the group.

## Why this matters for the roles I want

I'm building toward Cyber Defense, GRC, and IAM, and I'm using this hunt to practice the skills each one needs:

- **Cyber Defense / SOC:** working real telemetry in Microsoft Sentinel and KQL, and pivoting from alert noise to the activity that actually matters.
- **GRC:** learning to document an investigation clearly and map findings to frameworks like the NIST Cybersecurity Framework.
- **Remote work:** writing this up as a standalone artifact someone can follow without me in the room.

## Investigation Progress

| Phase | Focus | Status |
|---|---|---|
| Q00 Setup Gate | Confirm workspace, submit gate phrase | Complete |
| Q01 Initial Access | Real entry point, account, method | Complete |
| Q02 Linux Recon | Escalation, tooling, pivot prep | Complete |
| Q03 Pivot and Persistence | Internal movement, persistence | Complete |
| Q04 Command and Control | C2 infrastructure, beacon channel | Working |
| Q05 Impact | Data theft, session used, attack model | Not started |

## Investigation Journal

**July 12:** Confirmed the workspace and ran the baseline count (Q00). Solved Q01: the real entry was an external RDP login from `148.64.103.173` on the `sancadmin` admin account, not the brute-force noise it looked like. Also noticed npt-linux01 carries about 78% of all process events, and flagged it as a lead to test in Q02.

**Next:** Q02, Linux recon. Dig into what those Linux processes actually are and start separating the operator's activity from normal automation.

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

## Post-Debrief Reflections

To be filled in after the July 15 debrief: peer feedback, and any hunting logic I refine as a result.

## What I Learned

To be filled in after the debrief:
- What the hunt was designed to teach
- Where I got stuck
- What the debrief clarified
- What I'd do faster next time

---

<details>
<summary><strong>Scenario and hunt details</strong></summary>

<br>

**THREAT DETECTED // NORTHPEAK LOGISTICS ESTATE**
Intrusion window: 16 Jun 2026, 20:00 to 00:30 UTC
Platforms: Windows + Linux
Status: Active investigation

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

**Attack Timeline** (fills in as evidence is confirmed)

| UTC | Event | Host | Confidence |
|---|---|---|---|
| ~20:00 | Intrusion window opens | Northpeak estate | |
| 20:57 | First foothold: external login, sancadmin from 148.64.103.173 | npt-ws01 | Confirmed (Q02) |
| 21:58 | External login | npt-srv01 | Confirmed (Q02) |
| 22:01 | Linux accessed, over an hour after Windows | npt-linux01 | Confirmed (Q02) |
| - | Operator workstation identified: loranse (source of the RDP sessions) | loranse | Confirmed (Q03) |
| TBD | Internal pivot | | TBD |
| TBD | Persistence established | | TBD |
| TBD | C2 beacon | | TBD |
| TBD | Impact, crown jewel reached | | TBD |
| ~00:30 | Intrusion window closes | | |

</details>

---

Hunt built by Dogukan Oruc // LOG(N) Pacific Cyber Range

[Portfolio](https://github.com/Danielle-Respes) | [LinkedIn](https://www.linkedin.com/in/danielle-respes-64113767/)
