# Incident Report: Northpeak Descent Intrusion
**Date:** July 12, 2026 | **Author:** Danielle Respes | **Range:** LOG(N) Pacific Cyber Range

## Executive Summary

*Status: All phases solved.* Someone gained unauthorized access to the Northpeak Logistics estate on the evening of June 16, 2026, across a mixed Windows and Linux environment. This report captures my investigative steps, the hurdles I hit, and the process I'm using to learn KQL and threat hunting.

## Methodology

I use an AI assistant as a tutor to help me understand KQL syntax. It helps me learn the how and why behind the commands, which I then validate and interpret myself. My syntax notes and dead ends are in [kql-learning-log.md](./kql-learning-log.md).

---


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

---

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

**How I got there:** I started with the same base as Q00 (table, time, host), then added `LogonSuccess` to drop the failed logins, checked `RemoteIPType` to confirm the source was outside, and used `LogonType` to find the method (RDP). I used one of the two hints (15 points) for the "it's a decoy, look at what succeeded" and I want to get to that on my own next time.

**Q01 answer:** `148.64.103.173, RDP`

---

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

**Hint used:** 1 of 2 (25 points). The hint said to find the earliest external access on each host and not stay on one platform.

**Assistance:** I worked out the query approach for this one with my AI tutor, specifically dropping the Windows-only `RemoteInteractive` filter and comparing on external access instead. The reasoning about what the result meant, that Windows came before Linux and why volume isn't order, is my own.

**Q02 answer:** `npt-ws01, 148.64.103.173`

---


## Q03: Operator Workstation Name

The lead said the operator was sloppy: something they connected with announced itself on every remote session, and I needed to name it. The answer format was a hostname, so I was looking for a machine name, not an IP or a tool.

**My first read (and where it went wrong):** I thought "something they connected with" meant a tool or process the attacker used to connect, so I went back to my logon results and looked at the process column. I found `svchost.exe -k netsvcs` running under sancadmin. But svchost.exe is a native Windows process, it runs on every Windows machine, so it wasn't an attacker tool. Dead end. That result plus the `hostname` answer format told me I was looking for a machine name, not a process.

**Syntax I fixed along the way:**
- I first wrote `LogonType == "remoteinteractive"` in lowercase and got nothing. KQL matches string values exactly, so it had to be `"RemoteInteractive"` with the right capitals.
- I wrote `RemoteIP == 148.64.103.173"` and it wouldn't run, I'd dropped the opening quote and had spacing issues on the `where` lines. Fixed to `"148.64.103.173"` with clean spacing.

**The query I typed to work the attacker's sessions** (after the fixes above):

```kql
DeviceLogonEvents
|where TimeGenerated between (datetime(2026-06-16 18:00) .. datetime(2026-06-17 02:00))
|where DeviceName has_any ("npt-ws01","npt-srv01","npt-linux01")
|where ActionType == "LogonSuccess"
|where LogonType == "RemoteInteractive"
|where RemoteIP == "148.64.103.173"
|project AccountName, ActionType,DeviceName, InitiatingProcessFolderPath,LogonType,RemoteIP,RemoteIPType
```

This is where I saw `svchost.exe` in the process column and ruled it out. But it didn't surface the workstation name, because this query filters to `RemoteInteractive` only, and the name rides in on the Network logon rows.

**Hint used:** 1 of 2 (15 points). "Their inbound sessions carried more than an address." That confirmed the answer was the name of the remote machine riding in alongside the IP, not a process.

**The query that found it** (worked out with my AI tutor):

```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2026-06-16 18:00) .. datetime(2026-06-17 02:00))
| where RemoteIP == "148.64.103.173"
| where ActionType == "LogonSuccess"
| distinct RemoteDeviceName
```

`distinct` was new syntax for me. It collapses a column down to just its unique values, so instead of hundreds of session rows I got a short list: a blank, and `loranse`.

**What I found:** `loranse`. It isn't one of the Northpeak hosts (npt-ws01, npt-srv01, npt-linux01), so it's a foreign machine name that rode in on the attacker's sessions from 148.64.103.173. That's the operator's own workstation, leaking its name on every connection.

**Note, two queries for two questions:** My earlier logon query kept `LogonType == "RemoteInteractive"`, which was right for finding the RDP method. But when I added `distinct RemoteDeviceName` to that same filtered query, it returned empty. The hostname is recorded on the Network logon rows, not the RemoteInteractive ones, so the interactive filter hid it. Dropping that filter returned the name. Lesson: a filter that's correct for one question can hide the answer to the next. This is the second time an over-specific RemoteInteractive filter cost me data (it also hid Linux in Q02).

**Q03 answer:** `loranse`

---

## Q04: srv01 Access Vector

The lead said the server "took its own way in, it wasn't reached from inside." So npt-srv01 wasn't pivoted to from another host, it had its own external login. I reconstructed it. Did this one solo, no hints.

**Question:** how was npt-srv01 accessed from outside, method, source, and session type?

```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2026-06-16 18:00) .. datetime(2026-06-17 02:00))
| where DeviceName == "npt-srv01"
| where ActionType == "LogonSuccess"
| where RemoteIPType == "Public"
| project TimeGenerated, DeviceName, AccountName, RemoteIP, LogonType, RemoteDeviceName
| sort by TimeGenerated asc
```

**How I built it:** I reasoned "not reached from inside, so it had to be public," scoped to `npt-srv01`, filtered on `RemoteIPType == "Public"` and `LogonSuccess`, then projected the columns I needed.

**The real thinking, three values in one column:** the `LogonType` column had three values: `RemoteInteractive`, `Network`, and `Unlock`. I had to work out which one was the actual access vector:
- `Network` is the credential-check handshake.
- `Unlock` is reopening an already-open session.
- `RemoteInteractive` is a hands-on remote desktop session opening, that's the way in.

So the vector is `RemoteInteractive` (RDP), from 148.64.103.173.

**A mistake I caught myself:** I first put RDP in the logon_type slot. But RDP is the method, and `RemoteInteractive` is the logon_type, they're not the same thing. RDP is what I call it, RemoteInteractive is what the log calls it. Fixed the order to match the format.

**Corroboration I went looking for:** I added `RemoteDeviceName` to check for `loranse` (the operator workstation from Q03), but it was empty for these sessions. So my answer rested on a single signal: the matching IP plus my reasoning about the logon type. It was right, but that was my best judgment, not a locked-down confirmation. Lesson: when the field I want to corroborate with is blank, find a different corroborator rather than settling for one signal.

**Q04 answer:** `RDP, 148.64.103.173, RemoteInteractive`
