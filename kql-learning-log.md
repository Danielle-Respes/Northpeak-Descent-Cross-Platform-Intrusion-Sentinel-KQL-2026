# KQL Learning Log

My running log as I learn KQL on this hunt: the operators that clicked, the ones that bit me, and the patterns starting to stick. AI is my syntax tutor; the analysis is mine.

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

## Phase 00 — Baseline

Learned to scope a query and aggregate.
- Built the reusable base: table, then `TimeGenerated between (...)`, then `DeviceName has_any (...)`.
- Used `summarize Events = count() by DeviceName` to turn thousands of raw rows into one count per host.

## Phase 01 — Initial Access

Learned to stack filters and pick columns.

- Added `where ActionType == "LogonSuccess"` to drop failed logons.
- Added `where LogonType == "RemoteInteractive"` to isolate remote interactive sessions (RDP).
- Used `project` to keep only the columns that answered the question: account, source IP, IP type, logon type.
- Read `RemoteIPType == Public` off the result to confirm the source was external.

## Queries run so far


**Phase 00 — baseline count**


<img width="646" height="71" alt="1 kql" src="https://github.com/user-attachments/assets/f394dad1-67fd-4d97-b083-dbdb7b979087" />



**Phase 01 — successful external logon query**

<img width="772" height="95" alt="2 kql" src="https://github.com/user-attachments/assets/a7c902b6-3cfb-438f-ad43-a764ae9cf682" />



**Phase 01 — result**

<img width="772" height="116" alt="3 kql" src="https://github.com/user-attachments/assets/b5eff574-4f9c-4148-947f-194192a40b97" />


## Corrections and dead ends

- **Empty results on first run.** Time range was set to "Last 24 hours" but the intrusion was weeks earlier. Fixed by pinning the window in the query. Cost me a confused few minutes; lesson learned, the UI time range silently overrides you.
- **`LogonType == 10` returned nothing.** DeviceLogonEvents stores LogonType as a string, not a number. Fixed with `"RemoteInteractive"`. Lesson: check a column's data type before filtering.

## Patterns I'm noticing

Every query starts the same way: table, then time filter, then host filter, then the question-specific `where` clauses. That skeleton (table, time, host) is becoming automatic, which feels good.

`project` trims columns; `summarize` collapses rows into groups. Different jobs.
