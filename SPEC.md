# Mac security investigator

Version 3.2.0. Engineering co-worker for read-only live macOS log observation.

## Observation lifecycle

- Start a standard batch run through OtterDesk, the API, or `mn`. The output
  folder is the only operator setting. The collector observes new unified log
  events for 120 seconds using the native `/usr/bin/log stream` command.
- The existing native domain-operation blocks observe, commit to the
  Job-scoped ledger, and assess evidence. The stock report publication block
  publishes the packet on completion. Platform controls own pause, stop, and
  replay. Capture is idle between runs. A replay with a committed capture
  reuses those records.
- Placement requires Darwin and `runtime.placement.must_run_local: true`.
  The Job and its workers are pinned to the submitting Mac. Private evidence
  requires a standalone runtime without shared-output replication.
- Collection uses the current macOS account's permissions. It is limited to
  `syspolicyd` and `amfid` events that match a selected message fragment or
  fault level. The fixed 4 MiB output cap, 2,000 retained-record cap, and
  watchdog bound collection.

## Assessment and evidence

The investigator evaluates only observed events from the current window.
It recognizes specific messages for a Gatekeeper block or application
integrity validation failure, plus fault-level messages from those two Apple
security services. Rules for issues require the emitting system binary's
expected path. The report describes what the log supports, how confident that
interpretation is, and what to review next. Multiple log records may describe
one underlying action.

The collector uses message text in memory to check those rules. It retains
the rule identifier, event time, bounded logger metadata and a SHA-256 digest
of the source line. It discards message text, arguments, full executable paths
and other log values. Capture is read-only and performs no OS file inspection,
source execution, privilege changes, or remediation.

A stream receipt records the observed window and coverage. Missing permissions,
dropped or malformed events, clock changes and capture limits produce an
explicit gap. Evidence is limited to visible records in the requested scope.
There is no claim about events outside that scope, startup configuration,
attributed execution, actor identity, malicious intent, or complete host safety.

The Job history stores immutable, time-qualified receipts and assertions. Run
references pin the acquired revision so a later run cannot change a published
assessment. The shared temporal ledger and existing loopback context graph
remain the durable evidence and navigation layers. Live issue citations
resolve directly to retained source records. Earlier startup history fixtures
still exercise TB-01/TB-03 and retained historical replay. See the
[acceptance matrix](docs/acceptance.md) for those tests.

## Report delivery and supervision

The required assessment, evidence and Markdown files are
`final_artifact.json`, `evidence.json`, and `report.md`. Each live evidence
bundle includes its acquisition receipt even when coverage is unavailable or
there are zero findings. Case counts cover matching retained records.
The report shows up to eight supporting records per issue type and discloses
when it samples. If no rule matches, it shows a sample of recent observations.

The stock publication block renders the shared report template as
`web/index.html` with **Assessment**, **Evidence**, and **Coverage**. It emits
`web_ui.json` for OtterDesk's existing static adapter. The web files are
optional outputs with isolated failure handling. The template escapes
untrusted values and restricts executable content to its bundled assets.

The package uses `mn.mcp.supervision.v1` for common Job and Run tools.
Private evidence remains in the saved report. Chat can explain live activity,
report availability and how to review the evidence. Memory only stores
explicit explanation preferences. Existing runs keep their sealed artifacts.
