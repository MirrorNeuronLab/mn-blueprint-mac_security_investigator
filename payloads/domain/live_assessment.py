"""Assess the current live observation and cite retained source records."""

from collections import defaultdict

from mn_temporal_graph_skill import fingerprint

from .log_signals import ASSESSMENTS


def assess_observation(scan, source, revision, limits):
    source_ref = {"scan_revision": revision, "source_id": source["source_id"]}
    matches = defaultdict(list)
    limit = limits["max_log_evidence_per_issue"]
    for index, record in enumerate(source["records"]):
        signal = record["fields"].get("signal")
        if signal in ASSESSMENTS:
            matches[signal].append((record["time"]["earliest"], index))

    cases = []
    for signal, assessment in ASSESSMENTS.items():
        records = sorted(matches[signal])
        if not records:
            continue
        # Show the first records and the last record when the evidence is capped.
        samples = records if len(records) <= limit else [*records[:limit - 1], records[-1]]
        cases.append({
            **assessment,
            "case_id": "case-" + fingerprint([scan["host_epoch_id"], scan["scan_id"], signal])[:24],
            "pattern_family": signal,
            "scope": source["scope"],
            "review_state": "open",
            "status": "MATCHED",
            "malicious_intent": "not_established",
            "matched_records": len(records),
            "first_observed_at": records[0][0],
            "last_observed_at": records[-1][0],
            "evidence_refs": [{**source_ref, "locator": index} for _, index in samples],
        })

    recent = [] if cases else sorted(
        range(len(source["records"])),
        key=lambda index: source["records"][index]["time"]["earliest"],
    )[-limit:]
    receipt = {key: value for key, value in source.items() if key != "records"}
    complete = receipt["availability"] == "available" and receipt["enumeration"] == "complete"
    return {
        "schema_version": "mn.mac_security.analysis.v1",
        "host_epoch_id": scan["host_epoch_id"],
        "graph_revision": revision,
        "knowledge_cutoff": revision,
        "policy_version": "mac-live-log-review-v1",
        "collection_scope": "macos_unified_logs",
        "observation": {
            "scan_id": scan["scan_id"],
            "retained_records": len(source["records"]),
            "receipt_ref": {**source_ref, "locator": -1},
            "recent_record_refs": [{**source_ref, "locator": index} for index in recent],
            **receipt,
        },
        "cases": cases,
        "pending_matches": [],
        "deltas": [],
        "coverage": [receipt],
        "completeness": {
            "status": "complete_for_declared_log_scope" if complete else "INCOMPLETE_SEARCH",
            "unresolved": receipt["gaps"],
            "limits": limits,
        },
        "capability_limits": {"TB-01": "NOT_EVALUABLE", "TB-02": "NOT_EVALUABLE",
                              "TB-03": "NOT_EVALUABLE", "TB-05": "NOT_EVALUABLE",
                              "attributed_execution": "NOT_EVALUABLE"},
        "remediation_performed": False,
        "current_runtime_status": "unknown",
    }
