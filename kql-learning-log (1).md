# KQL Learning Log

Running record of the KQL I'm learning on this hunt. AI is my syntax tutor; the analysis is mine.

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

## Corrections and dead ends

- **Empty results on first run.** Time range was set to "Last 24 hours" but the intrusion was weeks earlier. Fixed by pinning the window in the query. Lesson: the UI time range silently overrides you.
- **`LogonType == 10` returned nothing.** DeviceLogonEvents stores LogonType as a string, not a number. Fixed with `"RemoteInteractive"`. Lesson: check a column's data type before filtering.
- **Ran the wrong query.** Two queries were stacked in the editor and the cursor decides which block runs. Lesson: clear old queries or place the cursor in the right block.

## Patterns I'm noticing

Every query starts the same way: table, then time filter, then host filter, then the question-specific `where` clauses. That skeleton (table, time, host) is becoming automatic.

`project` trims columns; `summarize` collapses rows into groups. Different jobs.
