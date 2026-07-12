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
