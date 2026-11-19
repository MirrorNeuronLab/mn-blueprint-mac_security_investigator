# Mac security investigator user manual

## Start and review

Start a run on the Mac you want to observe. The co-worker watches new security
log events for two minutes, using your account's existing log access. The
default output folder is `~/Downloads/mac-security-investigator`. You can
change it in configuration.

Open the web report when the run finishes. **Assessment** shows the issue
types to review and how to interpret them. **Evidence** links those assessments
to timestamped log records. **Coverage** describes the observed window, the
watched processes and any missing or interrupted data. The output folder also
contains the Markdown report, the sealed assessment and evidence JSON.

Review rules cover Gatekeeper blocks, application integrity validation failures
and faults from those security services. Their scope is the visible two-minute
window. A policy block may be expected. A quiet or incomplete observation
leaves activity outside its coverage unknown. The co-worker is idle between
runs and keeps the collected metadata in the saved report and Job history.

See the [conversation guide](conversation_guide.md) for a report walkthrough.
Chat explains the method and directs you to the saved report for private
findings. Keep private evidence on a standalone local runtime.

## Supervision

The SDK provides the shared MCP supervision tools. Use `get_capabilities`
for available controls, `start_run` to begin observation and `stop_run` to
end active work. Pause and resume use the Run controls. Track asynchronous
actions with `get_operation_status`. Check the runtime outcome after it
accepts an operation. Tool mutations require a request ID.
