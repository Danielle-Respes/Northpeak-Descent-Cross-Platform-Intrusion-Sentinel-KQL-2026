# Prep for the July 15 Community Debrief

I got stuck at a few points but kept going, and I want to be open with the group about where those spots were so we can talk through them on July 15.

**Where I am:** Q00 and Q01 done. Working Q02 now.

**Where I got stuck:**
- Empty results at first. My time range was "Last 24 hours" but the intrusion was weeks back. Fixed it by setting the window inside the query.

**How I worked Q01:**
- Ignored the failed logins (the decoy), filtered to successful logins from outside, and found one external IP on a valid admin account over RDP.
- I used the decoy-vs-signal hint (15 points) to point me the right way.

**What I want to ask the group:**
- I don't expect to have all the answers. I want to see how other people navigate these pivots so I can refine my own approach.
- How do you get to "ignore the noise, find the quiet success" without a hint?
- npt-linux01 has about 78% of the process events. How do you tell the attacker's activity from normal Linux automation when both use valid accounts?
- Is RemoteIP the best thing to pivot on, or is there something better?
