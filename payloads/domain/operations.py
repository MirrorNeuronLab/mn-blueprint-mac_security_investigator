"""Native block operations for bounded local evidence and temporal policy."""
from mn_sdk.blueprint.hooks import report_activity

from .acquisition import acquire_mac
from .configuration import BLUEPRINT_ID, investigation_policy
from .history import history
from .live_assessment import assess_observation
from .patterns import analyze


def capture(block, inputs):
    report_activity("Watching live Mac security logs", owner_blueprint=BLUEPRINT_ID, step_id=block.step_id, run_dir=block.store.run_dir)
    store = block.store
    scans = store.read_path("scan_batch.json") if store.path("scan_batch.json").exists() else [
        acquire_mac(block.run_id, investigation_policy(), check=block.check)]
    if not scans or any(scan["host_epoch_id"] != scans[0]["host_epoch_id"] for scan in scans):
        raise ValueError("all scans must belong to one local host epoch")
    reference = store.commit("scan_batch.json", scans, kind="mac_security_scans")
    return {"scan_count": len(scans), "scan_batch": reference.to_dict()}


def reconcile(block, inputs):
    report_activity("Reconciling temporal security history", owner_blueprint=BLUEPRINT_ID, step_id=block.step_id, run_dir=block.store.run_dir)
    batch = inputs["previous"]["scan_batch"]
    scans = block.store.read(batch)
    if not scans or any(scan["host_epoch_id"] != scans[0]["host_epoch_id"] for scan in scans):
        raise ValueError("all scans must belong to one local host epoch")
    ledger = history(block, scans[0]["host_epoch_id"])
    try:
        receipts = [ledger.ingest_scan(scan) for scan in scans]
        # A later run cannot advance this run's knowledge cutoff.
        if block.store.path("graph_revision.json").exists():
            pinned = block.store.read_path("graph_revision.json")
        else:
            pinned = {
                "revision": max(receipt["revision"] for receipt in receipts),
                "receipts": receipts,
                "host_epoch_id": ledger.host_epoch_id,
                "scan_batch": batch,
            }
        reference = block.store.commit("graph_revision.json", pinned, kind="mac_security_revision")
        return {"graph_revision": pinned["revision"], "revision_artifact": reference.to_dict()}
    finally:
        ledger.close()


def investigate(block, inputs):
    report_activity("Assessing Mac security evidence", owner_blueprint=BLUEPRINT_ID, step_id=block.step_id, run_dir=block.store.run_dir)
    from .context_graph import enrich

    pinned = block.store.read(inputs["previous"]["revision_artifact"])
    ledger = history(block, pinned["host_epoch_id"])
    try:
        revision = pinned["revision"]
        scans = block.store.read(pinned["scan_batch"])
        limits = investigation_policy()
        current = scans[-1]
        live_source = next((source for source in current["sources"] if source.get("collection_mode") == "live"), None)
        if live_source is not None:
            report = assess_observation(current, live_source, pinned["receipts"][-1]["revision"], limits)
        else:
            report = analyze(ledger, revision, limits)
        reference = block.store.commit("analysis.json", report, kind="mac_security_analysis")
        graph = enrich(block, ledger, report)
        block.store.commit("context_graph.json", graph, kind="mac_security_context_graph")
        return {"case_count": len(report["cases"]), "analysis": reference.to_dict()}
    finally:
        ledger.close()
