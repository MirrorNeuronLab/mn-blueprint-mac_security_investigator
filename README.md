# Mac security investigator

The co-worker observes macOS unified logs live for two minutes each time you
start a run. When the web report is ready, open it to see what needs review,
the evidence behind it, and gaps in coverage.

## Start an observation

Start a run in OtterDesk. The default output folder is
`~/Downloads/mac-security-investigator`. Keep it or choose another destination.
The collector uses the log access already available to your macOS account.

You can also start an observation from the CLI.

```bash
mn blueprint run ./mac_security_investigator
```

Use `outputs.folder_path` to choose a different destination.

```bash
mn blueprint run ./mac_security_investigator --set outputs.folder_path=~/Downloads/security-reviews
```

Each run starts Apple's `/usr/bin/log stream` on the submitting Mac and
watches `syspolicyd` and `amfid` for selected security signals. It processes
events emitted during that window and is idle between runs. Review rules recognize Gatekeeper blocks,
application integrity validation failures, and fault-level messages from the
two security services. A policy block or validation failure can be expected
during an ordinary installation or app launch.

## Read the report

Open **Mac security report** after the run finishes. The shared web template
puts the assessment first, with confidence and a suggested follow-up for each
issue, including the first and last matching timestamps. The **Evidence** tab
shows the record IDs, UTC times, processes and log levels that support those assessments. On a run
without matches, it shows a sample of the latest observed records.
**Coverage** shows the observation window, watched processes, record count and
any collection gaps. A quiet run and an unavailable stream have distinct
outcomes. A quiet observation leaves activity outside the window unknown.

The output folder also contains `report.md`, the sealed assessment
(`final_artifact.json`), and `evidence.json` with exact record locators,
full timestamps, logger metadata, line digests and the capture receipt. The run's `web/index.html` and
`web_ui.json` use OtterDesk's existing static report support. When the web
report is unavailable, the Markdown and JSON files remain the saved result.

At the end of the requested window the reader flushes a completion receipt, including when no events matched. A missing receipt or timeout is recorded as a coverage gap.

The active window is bounded to 120 seconds, 4 MiB of native output and 2,000
retained records. Permission problems, interrupted streams, dropped events
and capacity limits are reported. macOS may suppress or redact events.
Raw messages, arguments and full process paths are discarded. This is a
read-only logs review. It makes no determination of malicious intent,
execution attribution or system-wide safety.

## Local runtime and history

The blueprint requires HostLocal Python on the submitting Mac, including when
Core runs in Docker. It uses the existing batch, run controls and output
delivery. Use a standalone local runtime for private evidence. Core's
shared-output replication is a separate setting. The existing Membrane
context integration uses an explicitly configured loopback endpoint. Chat can
explain how to read the report and leaves private evidence in the saved view.

Local source preparation requires the matching sibling packages. Binary
preparation requires a published `mirrorneuron-macos-logs-skill` with
`observe_unified_logs` (declared minimum `1.4.1.dev15`), the shared web
report skill with section navigation (`1.4.1.dev15` or newer), and the declared
Web UI SDK component. For an existing idle
OtterDesk co-worker, apply the updated blueprint through the normal definition
update flow when the package is available.

The Job-scoped history retains sealed acquisition receipts and evidence
across runs. Each live assessment covers the current window. Earlier saved
reports remain historical. Synthetic startup history under
`examples/sample_history/` exercises temporal evidence behavior in tests.

## Verify the blueprint

```bash
python -m pytest tests/test_mac_security_investigator.py tests/test_mcp_mac_security_investigator.py tests/test_manifest_contracts.py -q
```

See the [product contract](SPEC.md) for coverage, output, and evidence limits.
