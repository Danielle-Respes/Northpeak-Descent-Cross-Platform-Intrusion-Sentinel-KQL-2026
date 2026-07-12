
<img width="977" height="298" alt="Screenshot 2026-07-10 at 6 44 46 PM" src="https://github.com/user-attachments/assets/25afcbe8-3711-43da-b847-e579ed2eeee4" />

# Northpeak Descent: Cross-Platform Intrusion Investigation

## Overview

This repository documents a self-directed threat hunting investigation conducted within the LOG(N) Pacific Cyber Range. As this is my first time executing this specific scenario, I am treating this as a deliberate reps focused practice project to build proficiency in Microsoft Sentinel and KQL.

---
## 📄 Read the Investigation

**→ [Incident Report](./Incident-Report.md)** — the full write-up: baseline, initial access, and the reconstructed chain as it develops.

Supporting detail lives in the per-phase notes and query log linked below.

---


## Practice and Community Learning

> I believe real expertise is built in the noise by navigating real telemetry and dead ends to understand the why behind the data.

**Methodology:** I am focusing on iterative query refinement, pivot analysis, and reducing signal noise within complex datasets.

**Community Engagement:** I am attending a community technical debrief on July 15, 2026, to validate my findings, pressure test my logic, and compare my hunting patterns against peer workflows.

**Continuous Improvement:** Following the debrief, I will update this repository with refined pivot logic and key lessons learned.

---

## Investigation Journal

> **July 12:** TBD plan:  Initial environment setup and telemetry baselining. Encountered significant noise in MDE DeviceEvents while attempting to isolate anomalous process execution.
>
> **July 13:** TBD plan:  Focused on query refinement. Successfully identified a pivot point after filtering out standard service account activity and administrative noise.
>
> **July 14:** TBD plan:  Deep dive into cross-platform anomalies. Working on reducing false positives in the investigation logic to isolate the core intrusion pattern.

---

## Post Debrief Reflections

> *This section will be updated after the community technical debrief on July 15, 2026, to include peer feedback and refined hunting logic.*

---

## Career Signal — What This Demonstrates

*   **For SOC Roles:** Demonstrates end-to-end incident response, including multi-SIEM telemetry correlation (Sentinel/MDE), KQL-based pivot analysis, and proactive detection engineering developed from confirmed investigation findings.

*   **For GRC Roles:** Demonstrates adherence to the NIST Cybersecurity Framework (Detect, Respond, Recover), formal incident documentation, and the ability to translate technical findings into business-impact reports for leadership.

*   **For Remote Roles:** Proves effective asynchronous communication skills. This report is structured as a standalone artifact—providing clear, actionable data that requires minimal clarification, mirroring the standard for high-performance remote teams.

--- 


## Technical Stack
[![Platform](https://img.shields.io/badge/SIEM-Microsoft%20Sentinel-0078D4?style=flat-square&logo=microsoft&logoColor=white)](https://azure.microsoft.com/en-us/products/microsoft-sentinel)
[![Telemetry](https://img.shields.io/badge/Telemetry-Defender%20XDR-0078D4?style=flat-square&logo=microsoft&logoColor=white)](https://www.microsoft.com/en-us/security/business/siem-and-xdr/microsoft-defender-xdr)
[![Language](https://img.shields.io/badge/Query%20Language-KQL-00B4D8?style=flat-square)](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/)
[![Mode](https://img.shields.io/badge/Mode-Practice-orange?style=flat-square)]()
[![Debrief](https://img.shields.io/badge/Community%20Debrief-July%2015%202026-red?style=flat-square)]()

**Platform:** Microsoft Sentinel

**Query Language:** Kusto Query Language (KQL)

**Endpoint Analysis:** Microsoft Defender for Endpoint (MDE)

## Role-Specific Takeaways

> I approach every investigation by considering the unique priorities of the security team.

*   **SOC Analyst Lens:** My methodology focuses on reducing "mean time to detect" (MTTD). In this investigation, I demonstrate how KQL pivoting moved me from initial alert to confirmed attacker command line. Each report includes a proposed detection rule to automate future defenses.

*   **GRC Analyst Lens:** I view incidents through the lens of risk and compliance. I identify the specific security controls (NIST CSF) impacted and translate technical findings into business-impact summaries suitable for leadership.

*   **Remote Work Evidence:** This report is written for clarity and asynchronous consumption. By documenting my thought process and providing high-fidelity logs, I ensure that my work is fully transparent and actionable for any team member, regardless of their location.


</div>

---

```
THREAT DETECTED // NORTHPEAK LOGISTICS ESTATE
INTRUSION WINDOW: 16 JUN 2026 // 20:00 – 00:30 UTC
PLATFORMS: WINDOWS + LINUX
STATUS: ACTIVE INVESTIGATION
```

---

## The Scenario

Overnight the Northpeak Logistics estate lit up. A cross-platform intrusion — valid accounts, a chain that runs from a quiet foothold through to impact across both Windows and Linux hosts.

The alert queue is loud with failed logons. It looks like brute force. It is not.

> **"Night shift already logged a cause on this one. I am not sold. Work the incident yourself, follow the evidence, and tell me what actually happened, in order."**
> — Hunt Lead, SancLogic

---

## Environment

| Field | Details |
|---|---|
| Target | Northpeak Logistics — Windows estate + Linux host |
| SIEM | Microsoft Sentinel |
| Telemetry | Microsoft Defender XDR + Sentinel |
| Workspace | LAW-Cyber Range Sentinel |
| Query Language | KQL (Kusto Query Language) |
| Attack Chain | Initial Access → Recon → Pivot and Persistence → C2 → Impact |
| Hunt Built By | Dogukan Oruc // Hunt Lead: SancLogic // LOG(N) Pacific Cyber Range |
| Mode | Practice — working after contest close to learn properly |
| Community Debrief | Wednesday July 15, 2026 @ 22:00 UK / 21:00 UTC |

---

## Investigation Progress

| Phase | Focus | Status |
|---|---|---|
| Q00 Setup Gate | Confirm workspace, submit gate phrase | Complete |
| Phase 01 Initial Access | Real entry point, order of footholds, operator client | In Progress |
| Phase 02 Linux Recon | Escalation, tooling, pivot preparation | Not Started |
| Phase 03 Pivot and Persistence | Internal movement, persistence mechanism | Not Started |
| Phase 04 Command and Control | C2 infrastructure, beacon channel | Not Started |
| Phase 05 Impact | Data theft, session used, attack model | Not Started |

---

## Documents

| File | Description |
|---|---|
| [phase-01-initial-access.md](./phase-01-initial-access.md) | Real entry point — separate signal from noise |
| [phase-02-linux-recon.md](./phase-02-linux-recon.md) | Escalation and pivot tooling on Linux host |
| [phase-03-pivot-persistence.md](./phase-03-pivot-persistence.md) | Internal movement and persistence |
| [phase-04-c2.md](./phase-04-c2.md) | Command and control infrastructure |
| [phase-05-impact.md](./phase-05-impact.md) | Data theft and attack model |
| [kql-queries.md](./kql-queries.md) | Every query run — including dead ends |
| [attack-timeline.md](./attack-timeline.md) | Full reconstructed chain |

---

## Attack Timeline

> Built in real time as evidence is confirmed across phases

| UTC | Event | Host | Source | Confidence |
|---|---|---|---|---|
| ~20:00 | Intrusion window opens | Northpeak estate | | |
| TBD | Real initial access — not brute force | | Sentinel | |
| TBD | Linux host activity | npt-linux01 | Defender XDR | |
| TBD | Internal pivot | | Sentinel | |
| TBD | Persistence established | | MDE Registry | |
| TBD | C2 beacon | | MDE Network | |
| TBD | Impact — crown jewel reached | | MDE File | |
| ~00:30 | Intrusion window closes | | | |

---

## Hunting Principles

```
01  Filter first — every query scoped to Northpeak hosts
02  Separate signal from noise — the brute force storm is bait
03  Prove the order — two platforms, timestamps decide
04  Pivot on identity — one account and one address thread the case
05  Separate human from machine — hands-on-keyboard vs automation
06  Treat absence as evidence — what they did not do matters too
07  Then tell the story — entry to pivot to persistence to C2 to impact
```

---

## What I Learned

> Filled in after the community debrief — Wednesday July 15, 2026

**What the hunt was designed to teach:**

**Where I got stuck:**

**What the debrief clarified:**

**What I would do faster next time:**

---

<div align="center">

This is my first CTF-style threat hunt — working in practice mode to learn how to hunt properly, not to optimise for done.
Every query, every dead end, every wrong turn is documented.


[Portfolio](https://github.com/Danielle-Respes) &nbsp;|&nbsp; [LinkedIn](https://www.linkedin.com/in/danielle-respes-64113767/)




LOG(N) Pacific Cyber Range // NORTHPEAK DESCENT // built by @Dogukan Oruc
</div>
