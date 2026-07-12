# Prep for the July 15 Community Debrief

I got stuck at a few points but kept going, and I want to be open with the group about where those spots were so we can talk through them on July 15.

**Where I am:** Q00, Q01, and Q02 done. Working Q03 next.

## Q01: Initial Access

- Ignored the failed logins (the decoy), filtered to successful logins from outside, and found one external IP (148.64.103.173) on a valid admin account (sancadmin) over RDP.
- I used the decoy-vs-signal hint (15 points) to point me the right way.

## Q02: Which foothold came first

This is the one I want to talk through, because it's where my thinking went wrong before it went right.

**The trap I almost fell into:** the pie chart shows npt-linux01 with about 78% of all process events, so my gut said Linux was the center of the attack and probably the first foothold. The brief flat-out warned "don't assume Linux first," but the data still made Linux *look* like the obvious answer.

**Where my query went wrong:** my first instinct was to reuse my Q01 query, which filtered on `LogonType == "RemoteInteractive"`. That's RDP, which is a Windows-only logon type. If I'd trusted that, I would have filtered the Linux host out completely and "proven" Windows first by accident, without ever really comparing the two. I also tried `where AccountDomain == "npt-linux01"` at one point, which was wrong because AccountDomain isn't the host, DeviceName is.

**How I fixed it:** the fix was to stop filtering on a Windows-only logon type and instead filter on external access (`RemoteIPType == "Public"`) across all three hosts, then sort by time. That put Windows and Linux on the same timeline fairly.

**What it showed:**
- npt-ws01 (Windows): first external login 20:57
- npt-linux01 (Linux): first external login 22:01

Windows was first by over an hour. Volume is not order. Linux only looked central because it's noisy.

**Where I used help:**
- I revealed 1 of 2 hints (25 points). The hint said to find the earliest external access on each host and not stay on one platform. I unlocked it because I was stuck on how to compare the two platforms fairly.
- I also worked the query approach out with an AI tutor, dropping the Windows-only filter and comparing on external access. The interpretation, that Windows came first and why volume isn't order, was mine.

## What I want to ask the group

- I don't expect to have all the answers. I want to see how other people navigate these pivots so I can refine my own approach.
- On Q02, how would I have caught the "RemoteInteractive is Windows-only, so it hides Linux" problem on my own, without a hint? Is there a habit that flags "this filter is platform-specific"?
- npt-linux01 has about 78% of the process events. How do you tell the attacker's activity from normal Linux automation when both use valid accounts?
- Is RemoteIP the best thing to pivot on, or is there something better?


## Q03: Operator workstation name

Find the machine the attacker connected from, which leaked its name on every session.

**Where my thinking went wrong first:** I read "something they connected with" as a tool or process, so I checked the process column and found `svchost.exe -k netsvcs`. That's native Windows, not an attacker tool. Dead end. The `hostname` answer format told me I was after a machine name, not a process.

**Two queries for two questions (this is the part I want to raise):**
- Query 1 kept `LogonType == "RemoteInteractive"`. That was right for finding the RDP method and the attacker IP.
- Query 2, when I added `distinct RemoteDeviceName` to that same filtered query, returned empty. The hostname is recorded on the Network logon rows, not the RemoteInteractive ones, so the interactive filter hid it. Dropping that filter returned the name.
- Lesson: a filter that's right for one question can hide the answer to the next. Second time an over-specific RemoteInteractive filter cost me data (it also hid Linux in Q02).

**Syntax I learned:**
- `LogonType == "remoteinteractive"` in lowercase returned nothing. KQL matches string values exactly, needed `"RemoteInteractive"`.
- `distinct` was new to me. It collapses a column to its unique values, so `loranse` stood out against a blank.

**Where I used help:** 1 of 2 hints (15 points), "their inbound sessions carried more than an address," which confirmed I was after a machine name riding in with the IP.

**Answer:** the operator's workstation is `loranse`, a name that isn't a Northpeak host and rode in on every session from 148.64.103.173.


## Q04: How srv01 was accessed (no hints, did this one solo)

Reconstruct how npt-srv01 was reached. The lead said it "took its own way in, it wasn't reached from inside," so it had to be an external login, not an internal pivot.

**How I built it:** I reasoned "not reached from inside, so it had to be public," so I scoped to `npt-srv01`, filtered `RemoteIPType == "Public"` and `ActionType == "LogonSuccess"`, then projected the columns I needed. No hints, worked the whole query myself.

```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2026-06-16 18:00) .. datetime(2026-06-17 02:00))
| where DeviceName == "npt-srv01"
| where ActionType == "LogonSuccess"
| where RemoteIPType == "Public"
| project TimeGenerated, DeviceName, AccountName, RemoteIP, LogonType, RemoteDeviceName
| sort by TimeGenerated asc
```

**The real thinking, three values in one column:** the `LogonType` column had three different values: `RemoteInteractive`, `Network`, and `Unlock`. I had to work out which one was the actual access vector:
- `Network` is the credential-check handshake.
- `Unlock` is reopening an already-open session.
- `RemoteInteractive` is a hands-on remote desktop session opening, that's the way in.

So the vector is `RemoteInteractive` (RDP), from 148.64.103.173.

**A mistake I caught myself:** I first wrote the answer with RDP in the logon_type slot. But RDP is the method, and RemoteInteractive is the logon_type, they're not the same thing. RDP is what I call it, RemoteInteractive is what the log calls it. Fixed the order to match the format.

**Corroboration I went looking for:** I added `RemoteDeviceName` back to my projection to check for `loranse` (the operator workstation from Q03). It did NOT show up, that column was empty for these sessions. So my answer rested on a single signal: the matching IP (148.64.103.173) plus my reasoning about the logon type. It was right, but that was my best judgment, not a locked-down confirmation. The lesson: when my usual corroborating field is blank, find a different corroborator (like whether the 21:58 timestamp lines up with the operator's activity elsewhere) rather than settling for one signal.

**Q04 answer:** `RDP, 148.64.103.173, RemoteInteractive`


## What I want to ask the group

- I don't expect to have all the answers. I want to see how other people navigate these pivots so I can refine my own approach.
- Twice now an over-specific `RemoteInteractive` filter has hidden the data I needed (Linux in Q02, the hostname in Q03). How do you build the instinct to catch "this filter is platform-specific or too narrow" before it burns you?
- npt-linux01 has about 78% of the process events. How do you tell the attacker's activity from normal Linux automation when both use valid accounts?
- Is RemoteIP the best thing to pivot on, or is there something better?
