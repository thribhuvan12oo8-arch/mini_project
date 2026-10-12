import json
import os
from pathlib import Path
from database.store import Store
from evidence.integrity import verify
from psaiac98.service import HubService
from telemetry.adapters import SyslogAdapter, WazuhAdapter, WindowsEventLogAdapter
from telemetry.synthetic import scenarios


def main():
    configured_db = os.getenv("PSAIAC_DB")
    db = Path(configured_db or ("demo.db" if Path("demo.db").exists() else "psaiac98.db"))
    store = Store(str(db))
    service = HubService(store)
    print("PSAIAC_98 JURY DEMONSTRATION")
    for code in "ABCDE":
        for event in scenarios()[code]:
            service.ingest(event.to_dict(), "synthetic", f"Scenario {code}", True)
            print(f"{code}: raw -> normalized -> correlation -> rules | {event.event_id}")
    by_code = {code: scenarios()[code] for code in "FGHKL"}
    for code in "FGH":
        for event in by_code[code]:
            service.ingest(event.to_dict(), "synthetic", f"Scenario {code}", True)
    gap_f = service.create_rule_gap([event.event_id for event in by_code["F"]], {"firewall": "demo-firewall-evidence-F"})
    gap_g = service.create_rule_gap([event.event_id for event in by_code["G"]], {})
    gap_h = service.create_rule_gap([event.event_id for event in by_code["H"]], {"firewall": "firewall-evidence-001"})
    print(f"F: RULE GAP {gap_f['gap_id']} | evidence={gap_f['evidence_status']} | admin={gap_f['admin_status']}")
    print(f"G: RULE EVOLUTION BLOCKED | evidence={gap_g['evidence_status']}")
    gap_h = service.decide_gap(gap_h["gap_id"], "MALICIOUS", "demo-admin")
    proposal = service.create_candidate(gap_h["gap_id"])
    print(f"H: VERIFIED RULE GAP {gap_h['gap_id']} | proposal={proposal['proposal_id']}")
    replay_result = service.replay_candidate(proposal["proposal_id"])
    print(f"I: REPLAY | records={replay_result['records_checked']} | matches={replay_result['match_count']}")
    service.review_candidate(proposal["proposal_id"], "APPROVED", "demo-admin")
    active_rule = service.activate_candidate(proposal["proposal_id"], "demo-admin")
    print(f"J: RULE ACTIVATION | {proposal['proposal_id']}={active_rule['status']}")
    recurrence_events = scenarios()["K"]
    recurrence_results = [service.ingest(event.to_dict(), "synthetic", "Scenario K", True) for event in recurrence_events]
    recurrence_matches = [incident for result in recurrence_results for incident in result["incidents"] if incident.get("proposal_id") == proposal["proposal_id"]]
    print(f"K: FUTURE RECURRENCE | events={len(recurrence_results)} | active_rule_matches={len(recurrence_matches)}")
    evidence_result = service.ingest(by_code["L"][0].to_dict(), "synthetic", "Scenario L", True)
    stored_event = store.find("normalized_events", {"event_id": evidence_result["event"]["event_id"]})
    evidence_payload = json.dumps(stored_event["raw_payload"], sort_keys=True, default=str).encode("utf-8")
    original_hash = stored_event["integrity"]["sha256"]
    verification = verify(evidence_payload, original_hash)
    store.add("evidence", {"event_id": stored_event["event_id"], "original_hash": original_hash, **verification})
    store.add("audit_log", {"action": "evidence_integrity_check", "actor": "demo-admin", "details": {"event_id": stored_event["event_id"], "status": verification["integrity_status"]}})
    print(f"L: EVIDENCE INTEGRITY | hash={original_hash[:16]}... | status={verification['integrity_status']}")
    store.add("telemetry_health", {"source": "Windows Event Log", "status": WindowsEventLogAdapter().status()})
    store.add("telemetry_health", {"source": "Wazuh", "status": WazuhAdapter().status()})
    store.add("telemetry_health", {"source": "Syslog", "status": SyslogAdapter().status()})
    store.add("telemetry_health", {"source": "Suricata", "status": "NOT CONFIGURED"})


if __name__ == "__main__": main()
