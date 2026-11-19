"""Readable assessment, evidence and coverage for the shared report template."""

from mn_temporal_graph_skill import fingerprint


GAP_LABELS = {
    "byte_limit": "The capture reached its byte limit.",
    "clock_changed": "The system clock moved backward during capture.",
    "diagnostic_limit": "The reader produced too much diagnostic output.",
    "log_reader_failed": "The macOS log reader stopped with an error.",
    "log_reader_missing": "The macOS log reader was unavailable.",
    "permission_denied": "macOS denied access to all or part of the log stream.",
    "record_limit": "The capture reached its retained-record limit.",
    "requires_macos": "Live unified logging requires macOS.",
    "stream_count_mismatch": "The stream receipt count differed from the number of events read.",
    "stream_dropped_events": "macOS reported dropped events.",
    "stream_ended_without_receipt": "The stream stopped before confirming completion.",
    "timeout": "The reader did not close within the allowed time.",
    "unparsed_or_out_of_scope_record": "Some events could not be read or fell outside the observation scope.",
    "unparsed_stream_record": "The log reader returned records in an unrecognized format.",
}


def _summary(observation, issues):
    if issues:
        headline = (
            "One issue type needs review." if len(issues) == 1 else f"{len(issues)} issue types need review."
        )
        if observation["enumeration"] != "complete":
            headline += " Coverage was incomplete."
        return headline
    if observation["availability"] != "available":
        return "The live log stream was unavailable. The evidence was insufficient for an assessment."
    if observation["enumeration"] != "complete":
        return "The available events did not match the review rules. Coverage was incomplete."
    if not observation["retained_records"]:
        return "No events matched the stream filter during this observation."
    return "No observed events matched the review rules during this window."


def _assessment(case):
    matched = case["matched_records"]
    count = "1 matching record." if matched == 1 else f"{matched} matching records."
    shown = len(case["evidence_refs"])
    if shown < matched:
        count += f" The evidence table shows {shown} records, including the first and last."
    window = f"First observed {case['first_observed_at']}. Last observed {case['last_observed_at']}."
    return {
        "text": f"{case['title']}. {case['assessment']} {case['confidence']} confidence in the interpretation of this signal. "
                f"{count} {window} {case['next_step']}",
        "source_refs": [f"Record {ref['locator'] + 1}" for ref in case["evidence_refs"]],
    }


def _evidence_rows(refs, evidence):
    rows = []
    for ref in refs:
        record = evidence[fingerprint(ref)]["record"]
        fields = record["fields"]
        logger = " · ".join(fields[key] for key in ("process", "messageType") if fields.get(key))
        event_time = record["time"]["earliest"].replace("T", " ").removesuffix("Z")
        rows.append([
            f"Record {ref['locator'] + 1}",
            event_time,
            logger,
            fields.get("indicator", "No review rule matched"),
        ])
    return sorted(rows, key=lambda row: (row[1], row[0]))


def document(report, evidence):
    observation = report["observation"]
    cases = report["cases"]
    coverage_status = (
        "Complete within the selected scope" if observation["enumeration"] == "complete" else
        "Partial" if observation["availability"] == "available" else "Unavailable"
    )
    acquisition = observation["acquisition"]
    assessment = []
    if cases:
        assessment.append({"type": "findings", "items": [_assessment(case) for case in cases]})
    elif coverage_status in {"Partial", "Unavailable"}:
        assessment.append({"type": "paragraph", "text": "Check the capture gaps in Coverage before interpreting the empty issue list."})
    assessment.append({
        "type": "paragraph",
        "text": "This review covers the events visible during this window. A log signal leaves malicious intent and system-wide safety undetermined.",
    })
    refs = [ref for case in cases for ref in case["evidence_refs"]] or observation["recent_record_refs"]
    rows = _evidence_rows(refs, evidence)
    evidence_blocks = []
    if rows:
        evidence_blocks.append({
            "type": "table",
            "caption": ("Retained log metadata supporting the assessment, ordered by event time." if cases else
                        "Sample of the most recent observed log records."),
            "columns": ["Record", "Time (UTC)", "Source", "Matched indicator"],
            "rows": rows,
        })
    evidence_blocks.append({
        "type": "paragraph",
        "text": "Evidence JSON in the output folder contains exact timestamps, subsystem and category when available, record locators, SHA-256 digests and the acquisition receipt. Message text, arguments and full process paths are discarded.",
    })
    coverage = [{
        "type": "table", "columns": ["Measure", "Observed"],
        "rows": [
            ["Coverage", coverage_status],
            ["Capture started (UTC)", acquisition["earliest"]],
            ["Capture ended (UTC)", acquisition["latest"] or "Unknown"],
            ["Requested duration", f"{observation['requested_duration_seconds']} seconds"],
            ["Watched processes", ", ".join(observation["processes"])],
            ["Stream filter", "Gatekeeper and application integrity indicators, plus fault-level messages"],
            ["Retained log records", observation["retained_records"]],
        ],
    }]
    for gap in observation["gaps"]:
        coverage.append({"type": "warning", "text": GAP_LABELS.get(gap, "The log reader reported an unspecified coverage gap.")})
    coverage.append({
        "type": "paragraph",
        "text": "macOS may redact or omit messages. Coverage applies only to the selected log signals during the observed window.",
    })
    return {
        "schema_version": "mn.report_document.v1",
        "title": "Mac security report",
        "identity": "Live system log observation",
        "summary": _summary(observation, cases),
        "sections": [
            {"id": "assessment", "title": "Assessment", "blocks": assessment},
            {"id": "evidence", "title": "Evidence", "blocks": evidence_blocks},
            {"id": "coverage", "title": "Coverage", "blocks": coverage},
        ],
    }
