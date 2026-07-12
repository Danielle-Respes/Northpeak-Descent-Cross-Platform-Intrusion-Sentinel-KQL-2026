# KQL Learning Log

I'm new to KQL, so I'm keeping a log of what I figure out and the questions I still have. It helps me remember what I've learned so I can use it on the next hunt. AI helps me with the syntax. The analysis is mine.

## Syntax learned

- **Table name** (first line): the data source. Example: `DeviceLogonEvents`
- **Pipe operator**: passes results into the next step; read the query top to bottom
- **`where`**: keeps only rows matching a condition. Example: `where ActionType == "LogonSuccess"`
- **`==`**: exact match; strings need double quotes. Example: `where LogonType == "RemoteInteractive"`
- **`between (datetime() .. datetime())`**: filters to a time window, pinned in the query
- **`has_any ("a","b")`**: matches if the field contains any listed value. Example: `where DeviceName has_any ("npt-ws01","npt-srv01")`
- **`summarize ... by`**: groups rows and aggregates, like a pivot table. Example: `summarize Events = count() by DeviceName`
- **`count()`**: counts rows, usually paired with summarize
- **`project`**: picks which columns to show, and their order. Example: `project AccountName, RemoteIP, LogonType`
- **`distinct`**: collapses a column (or columns) down to just its unique values. Example: `distinct RemoteDeviceName`. Great for pulling one clean list out of hundreds of repeated rows, so an odd value stands out.


## Q00 — Baseline

Learned to scope a query and aggregate.

- Built the reusable base: table, then `TimeGenerated between (...)`, then `DeviceName has_any (...)`.
- Used `summarize Events = count() by DeviceName` to turn thousands of raw rows into one count per host.

<img width="646" height="71" alt="1 kql" src="https://github.com/user-attachments/assets/f394dad1-67fd-4d97-b083-dbdb7b979087" />

## Q01 — Initial Access

Learned to stack filters and pick columns.

- Added `where ActionType == "LogonSuccess"` to drop failed logons.
- Added `where LogonType == "RemoteInteractive"` to isolate remote interactive sessions (RDP).
- Used `project` to keep only the columns that answered the question: account, source IP, IP type, logon type.
- Read `RemoteIPType == Public` off the result to confirm the source was external.


<img width="772" height="116" alt="3 kql" src="https://github.com/user-attachments/assets/b5eff574-4f9c-4148-947f-194192a40b97" />


## Q02 — Order of Footholds

Learned to compare across platforms with a time sort.

- Dropped the Windows-only logon filter and filtered on external access (`RemoteIPType == "Public"`) so all three hosts could be compared.
- Used `sort by TimeGenerated asc` so the earliest external login was the top row.

<img width="661" height="123" alt="q02" src="https://github.com/user-attachments/assets/6f11163c-68e2-4ebd-bb87-832875501992" />






## Q03 — Operator Workstation Name

Learned `distinct`, and learned the hard way that a filter can hide the answer.

- Used `distinct RemoteDeviceName` to pull one clean list of connecting machine names. The attacker's own workstation (`loranse`) stood out because it wasn't a Northpeak host.
- Key takeaway: `distinct` is a tool I'll use constantly. When I only care about the unique values in a column, not every row, `distinct` gives me the short list to read.






The IP address (148.64.103.173) was already known from Q01 and Q02. I worked out the `distinct` syntax with AI help; the interpretation, that `loranse` is the attacker's workstation because it isn't a Northpeak host, is mine.
<img width="649" height="98" alt="5 kql" src="https://github.com/user-attachments/assets/5058abf1-6993-418e-b6d0-cc121bce00da" />


<img width="305" height="190" alt="4 kql-results" src="https://github.com/user-attachments/assets/b4caf042-cd87-4ac3-982b-c8b3609959b0" />



## Q04 — srv01 Access Vector

Did this one solo, no hints.

- Scoped to `npt-srv01` and filtered on `RemoteIPType == "Public"`, reasoning that if it wasn't reached from inside, the login had to come from outside.
- The `LogonType` column held three values: `RemoteInteractive`, `Network`, and `Unlock`. Learned to tell them apart: Network is the credential handshake, Unlock is reopening an existing session, and RemoteInteractive is the actual way in (RDP).
- Learned the difference between the method and the logon type: RDP is what I call it, `RemoteInteractive` is what the log calls it. They go in different answer slots.
- Added `RemoteDeviceName` back to my projection to corroborate the operator, but it was empty here (no `loranse`). Takeaway: when my usual corroborating field is blank, find a different signal rather than settling for one.


<img width="674" height="141" alt="last2 kql" src="https://github.com/user-attachments/assets/8178a8a6-137b-4669-9a13-31c5e8b3fbe8" />

## Corrections and dead ends

- **Empty results on first run.** Time range was set to "Last 24 hours" but the intrusion was weeks earlier. Fixed by pinning the window in the query. Cost me a confused few minutes; lesson learned, the UI time range silently overrides you.
- **Lowercase value returned nothing.** I wrote `LogonType == "remoteinteractive"` and got no results. KQL matches string values exactly, so it had to be `"RemoteInteractive"` with the right capitals. Lesson: the value inside the quotes is case-sensitive.
- **A filter that hid the answer.** Keeping `LogonType == "RemoteInteractive"` while pulling `distinct RemoteDeviceName` returned empty. The machine name is on the Network logon rows, not the interactive ones, so the filter hid it. Dropping that one filter returned the name. Lesson: a filter that is right for one question can hide the answer to the next.
- **Corroborating field came back empty.** On Q04 I added `RemoteDeviceName` to confirm srv01's session tied to the operator's `loranse` workstation, but the column was blank for those sessions. My answer still held on the matching IP, but it left me with one signal instead of two. Lesson: when the field I want to corroborate with is empty, go find a different corroborator rather than assuming.

## Patterns I'm noticing

Every query starts the same way: table, then time filter, then host filter, then the question-specific `where` clauses. That skeleton (table, time, host) is becoming automatic, which feels good.

`project` trims columns; `summarize` collapses rows into groups. Different jobs.

