from dataclasses import asdict
import json
import os
import sys
import time
from pathlib import Path
from time import perf_counter

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pandas as pd
import streamlit as st

from database.store import Store
from evidence.integrity import hash_bytes, verify
from reports.generator import completion_report, report_html, report_text
from rules.engine import RULES, detect
from telemetry.adapters import DatasetReplayAdapter, SyslogAdapter, WazuhAdapter, WindowsEventLogAdapter, OptionalAdapter
from telemetry.synthetic import generate_live_attack_cycle, scenarios
from psaiac98.models import NormalizedEvent, event_id
from psaiac98.service import HubService

PAGES = ["Overview", "Live Telemetry", "Normalized Events", "Correlation", "Incidents", "Rule Gaps", "Rule Library", "Replay", "Telemetry Health", "Endpoint Health", "Audit Trail", "Reports"]
NAVY = "#081827"
TEAL = "#19b7a5"


def database_path() -> str:
    configured = os.getenv("PSAIAC_DB")
    if configured:
        return configured
    return "demo.db" if Path("demo.db").exists() else "psaiac98.db"


def fresh_store() -> Store:
    return Store(database_path())


def rows(store: Store, table: str) -> list[dict]:
    return store.list(table, 5000)


def audit(store: Store, action: str, details: dict) -> None:
    store.add("audit_log", {"action": action, "actor": st.session_state.get("username") or "system", "details": details})


def event_map(store: Store) -> dict[str, dict]:
    return {event["event_id"]: event for event in rows(store, "normalized_events") if event.get("event_id")}


def card(label: str, value: int, accent: str = TEAL) -> None:
    st.markdown(f"<div class='metric-card'><div class='metric-label'>{label}</div><div class='metric-value' style='color:{accent}'>{value:,}</div></div>", unsafe_allow_html=True)


def event_frame(events: list[dict]) -> pd.DataFrame:
    fields = ("event_id", "timestamp", "source_type", "source_name", "event_type", "severity", "user_id", "device_id", "source_ip", "action", "result", "target_resource", "is_synthetic")
    labels = {"synthetic": "Synthetic", "syslog": "Syslog", "wazuh": "Wazuh", "windows_event_log": "Windows"}
    return pd.DataFrame([
        {**{key: event.get(key) for key in fields}, "source_type": labels.get(event.get("source_type"), event.get("source_type"))}
        for event in events
    ])


def page_header(title: str, eyebrow: str) -> None:
    st.markdown(f"<div class='eyebrow'>{eyebrow}</div><h2>{title}</h2>", unsafe_allow_html=True)


st.set_page_config(page_title="Big Data Hub", page_icon=":material/security:", layout="wide", initial_sidebar_state="expanded")
st.markdown(f"""
<style>
:root {{ --navy:{NAVY}; --teal:{TEAL}; --bg:#071822; --panel:#0d1d2a; --panel-2:#122b3a; --text:#ebf7ff; --muted:#9bb7c7; --line:#224a62; --danger:#ff6b6b; --success:#4fe0b4; --warning:#ffce5c; }}
html, body, [data-testid="stAppViewContainer"], .stApp {{ background:linear-gradient(135deg,#071822 0%,#0b1f2b 35%,#0d2435 100%); color:var(--text); }}
.stApp p,.stApp li,.stApp label,.stApp [data-testid="stMarkdownContainer"], .stApp .stTabs [role="tablist"] button, .stApp .stDataFrame div, .stApp .stDataFrame, .stApp h1, .stApp h2, .stApp h3, .stApp h4 {{ color:var(--text) !important; }}
.stApp .stTextInput label, .stApp .stSelectbox label, .stApp .stNumberInput label, .stApp .stMultiSelect label, .stApp .stCheckbox label, .stApp .stRadio label {{ color:var(--text) !important; }}
[data-testid="stSidebar"] {{ background:linear-gradient(180deg,#091b27 0%,#0d2434 100%); border-right:1px solid rgba(25,183,165,.25); }}
[data-testid="stSidebar"] p,[data-testid="stSidebar"] label,[data-testid="stSidebar"] [data-testid="stMarkdownContainer"],[data-testid="stSidebar"] h3 {{ color:#f3fbff !important; }}
[data-testid="stSidebar"] svg {{ color:#7de3d5 !important; fill:none !important; stroke:#7de3d5 !important; visibility:visible !important; opacity:1 !important; }}
.block-container {{ max-width:1440px; padding-top:2rem; padding-bottom:3rem; }}
.hero {{ background:linear-gradient(135deg,#0f2231,#173c4c); color:white; border:1px solid rgba(25,183,165,.38); border-radius:18px; padding:2rem 2.4rem; margin-bottom:1.5rem; box-shadow:0 18px 36px rgba(0,0,0,.22); }}
.hero h1 {{ font-size:2.3rem; margin:0; letter-spacing:0; font-weight:800; color:#ffffff; }} .hero p {{ color:#badde6; margin:.6rem 0 0; }}
.project-id {{ color:var(--teal); font-size:.75rem; letter-spacing:.12em; text-transform:uppercase; font-weight:700; }}
.metric-card,.soc-card {{ background:linear-gradient(180deg,#0f2532,#0c1d2a); border:1px solid rgba(25,183,165,.24); border-radius:14px; padding:1rem 1.15rem; box-shadow:0 5px 14px rgba(0,0,0,.18); }}
.metric-label {{ color:#a7d3e9; font-size:.78rem; font-weight:700; text-transform:uppercase; letter-spacing:.05em; }} .metric-value {{ font-size:1.9rem; font-weight:800; margin-top:.35rem; }}
.eyebrow {{ color:var(--teal); text-transform:uppercase; letter-spacing:.1em; font-size:.72rem; font-weight:800; }}
h2 {{ color:var(--text); margin-top:.2rem; }} h3 {{ color:var(--text); letter-spacing:0; }}
.status-good {{ color:#53e7bf; font-weight:800; }} .status-bad {{ color:#ff8f8f; font-weight:800; }}
.timeline {{ border-left:3px solid var(--teal); padding-left:1rem; margin:.75rem 0 1rem; }} .timeline-item {{ margin:.55rem 0; color:var(--text); }} .small {{ color:var(--muted); font-size:.82rem; }}
button,[data-testid="stButton"] button {{ color:#071822 !important; }}
button svg,[data-testid="stButton"] svg,[data-testid="stDownloadButton"] svg {{ color:var(--teal) !important; fill:none !important; stroke:currentColor !important; visibility:visible !important; opacity:1 !important; }}
[data-testid="stDownloadButton"] button {{
    color:#f3fbff !important;
    background:rgba(8,24,39,.96) !important;
    border:1px solid rgba(25,183,165,.65) !important;
    border-radius:10px !important;
    font-weight:600 !important;
    box-shadow:none !important;
    opacity:1 !important;
    -webkit-text-fill-color:#f3fbff !important;
}}
[data-testid="stDownloadButton"] button,
[data-testid="stDownloadButton"] button > *,
[data-testid="stDownloadButton"] button span,
[data-testid="stDownloadButton"] button div,
[data-testid="stDownloadButton"] button p {{
    color:#f3fbff !important;
    fill:#f3fbff !important;
    stroke:#f3fbff !important;
    -webkit-text-fill-color:#f3fbff !important;
}}
[data-testid="stExpander"] summary,[data-testid="stSelectbox"] label,[data-testid="stTextInput"] label {{ color:var(--text) !important; }}
[data-testid="stDeckGlifCard"], .stDataFrame, .stTable {{ background:transparent; }}
</style>
""", unsafe_allow_html=True)

store = fresh_store()
service = HubService(store)

if "username" not in st.session_state:
    st.session_state.username = "local-user"
if "live_running" not in st.session_state:
    st.session_state.live_running = False
if "live_cycle" not in st.session_state:
    st.session_state.live_cycle = 0
if "live_last_tick" not in st.session_state:
    st.session_state.live_last_tick = 0.0


def reset_live_case() -> None:
    global store, service
    store = fresh_store()
    store.clear_tables(("normalized_events", "correlated_groups", "incidents", "rule_gaps"))
    service = HubService(store)
    st.session_state.live_running = False
    st.session_state.live_cycle = 0
    st.session_state.live_last_tick = 0.0
    audit(store, "live_case_reset", {"source": "dashboard"})


def generate_live_cycle() -> list[dict]:
    global service, store
    batch = generate_live_attack_cycle(st.session_state.live_cycle)
    ingested = []
    for event in batch:
        result = service.ingest(event.to_dict(), "synthetic", "Live SOC Attack", True)
        ingested.append(result)
    st.session_state.live_cycle += 1
    audit(store, "live_attack_generated", {"batch_id": st.session_state.live_cycle, "events": len(batch)})
    return ingested


st.sidebar.markdown("<h3 style='color:white'>SOC Console</h3>", unsafe_allow_html=True)
page = st.sidebar.radio("Navigation", PAGES, label_visibility="collapsed")
st.sidebar.divider()
st.sidebar.caption("Local telemetry ledger")
st.sidebar.caption("Local SQLite event store")
st.markdown("<div class='hero'><h1>Big Data Hub</h1><p>Integrated Cybersecurity Telemetry for SMEs</p></div>", unsafe_allow_html=True)

if page == "Overview":
    page_header("Operations overview", "Security operations center")
    metrics = [("Events Processed", store.count("normalized_events")), ("Correlated Incidents", store.count("incidents")), ("Rule Gaps", store.count("rule_gaps")), ("Active Rules", len(RULES) + sum(item.get("status") == "ACTIVE" for item in rows(store, "rules"))), ("Replay Validations", store.count("replay_results")), ("Evidence Checks", store.count("evidence"))]
    for start in range(0, len(metrics), 3):
        columns = st.columns(3)
        for column, (label, value) in zip(columns, metrics[start:start + 3]):
            with column:
                card(label, value)
    incidents = rows(store, "incidents")
    if incidents:
        st.markdown("### Latest incidents")
        st.dataframe(pd.DataFrame(incidents[:5]), width="stretch", hide_index=True)

elif page == "Live Telemetry":
    page_header("Live telemetry", "Streaming collection")
    st.caption("Real-time SOC telemetry generator and active detection workflow.")
    col_a, col_b, col_c = st.columns([1.3, 1.3, 1])
    with col_a:
        choice = st.selectbox("Scenario", list(scenarios()), help="Select a scenario to inject manually or start a fresh live attack stream.")
    with col_b:
        if st.button("Generate one batch", type="primary"):
            generate_live_cycle()
            st.rerun()
    with col_c:
        if st.button("Fresh investigation"):
            reset_live_case()
            st.rerun()
    start_col, stop_col = st.columns(2)
    with start_col:
        if st.button("Start generation", type="primary"):
            st.session_state.live_running = True
            st.session_state.live_last_tick = 0.0
            st.session_state.live_cycle = 0
            audit(store, "live_generation_started", {"scenario": choice})
            st.rerun()
    with stop_col:
        if st.button("Stop generation"):
            st.session_state.live_running = False
            audit(store, "live_generation_stopped", {"scenario": choice})
            st.rerun()

    if st.session_state.live_running:
        if time.monotonic() - st.session_state.live_last_tick >= 3:
            generate_live_cycle()
            st.session_state.live_last_tick = time.monotonic()
            st.rerun()
        st.info("Live generator active. Threat events are being created and correlated in real time.")

    if st.button("Ingest selected scenario"):
        for event in scenarios()[choice]:
            service.ingest(event.to_dict(), "synthetic", f"Scenario {choice}", True)
        audit(store, "synthetic_ingest", {"scenario": choice})
        st.rerun()

    with st.expander("Local source test inputs"):
        syslog_col, wazuh_col = st.columns(2)
        with syslog_col:
            st.markdown("#### Syslog · TEST MODE")
            syslog_message = st.text_input(
                "Syslog message",
                value=f"<34>{time.strftime('%b %d %H:%M:%S')} localhost sshd[1234]: Failed password for soc-test",
                key="syslog_test_message",
            )
            if st.button("Ingest Syslog test event", key="syslog_test_ingest"):
                try:
                    result = SyslogAdapter(service=service).ingest_message(syslog_message, test_mode=True)
                    audit(store, "syslog_test_ingest", {"event_id": result["event"]["event_id"]})
                    st.success("Syslog test event entered the shared pipeline.")
                    st.rerun()
                except ValueError as error:
                    st.error(str(error))
        with wazuh_col:
            st.markdown("#### Wazuh JSON · TEST MODE")
            wazuh_json = st.text_area(
                "Wazuh alert JSON",
                value='{"rule":{"id":"100100","level":7,"description":"User login failed"},"agent":{"id":"local-test","name":"local-test-agent"},"data":{"srcuser":"soc-test"}}',
                key="wazuh_test_json",
            )
            if st.button("Ingest Wazuh test event", key="wazuh_test_ingest"):
                try:
                    payload = json.loads(wazuh_json)
                    if not isinstance(payload, dict):
                        raise ValueError("Wazuh JSON must contain an object.")
                    payload.setdefault("id", event_id())
                    result = WazuhAdapter(service=service).ingest_event(payload, test_mode=True)
                    audit(store, "wazuh_test_ingest", {"event_id": result["event"]["event_id"]})
                    st.success("Wazuh test event entered the shared pipeline.")
                    st.rerun()
                except (json.JSONDecodeError, ValueError) as error:
                    st.error(str(error))

        st.markdown("#### Windows Event Log")
        windows_adapter = WindowsEventLogAdapter()
        st.caption(f"Source status: {windows_adapter.status()}")
        if st.button("Collect Windows Event Log", key="windows_event_collect"):
            if windows_adapter.status() != "CONNECTED":
                st.warning(f"Windows Event Log collection unavailable: {windows_adapter.status()}.")
            else:
                try:
                    collected = [service.ingest_event(event) for event in windows_adapter.read(limit=100)]
                    audit(store, "windows_event_log_collection", {"events": len(collected)})
                    st.success(f"Collected {len(collected)} Windows events through the shared pipeline.")
                    st.rerun()
                except (OSError, RuntimeError) as error:
                    st.error(str(error))

    recent = rows(store, "normalized_events")[:20]
    if recent:
        st.dataframe(event_frame(recent), width="stretch", hide_index=True)
    else:
        st.info("No live logs yet. Start generation to populate the SOC console.")

    incident_rows = rows(store, "incidents")
    if incident_rows:
        st.markdown("### Active detections")
        st.dataframe(pd.DataFrame(incident_rows), width="stretch", hide_index=True)

elif page == "Normalized Events":
    page_header("Normalized events", "Common event model")
    store_events = rows(store, "normalized_events")
    if store_events:
        selected_id = st.selectbox("Select event", [item["event_id"] for item in store_events])
        selected = next(item for item in store_events if item["event_id"] == selected_id)
        left, right = st.columns(2)
        with left:
            st.markdown("### Raw event")
            st.json({"raw_event_reference": selected.get("raw_event_reference"), "source_type": selected.get("source_type"), "source_name": selected.get("source_name"), "event_type": selected.get("event_type"), "payload": selected})
        with right:
            st.markdown("### Normalized event")
            st.json({key: selected.get(key) for key in NormalizedEvent.__dataclass_fields__})
        st.markdown("### Common Event Model fields")
        st.dataframe(pd.DataFrame([selected]), width="stretch", hide_index=True)
    else:
        st.info("No normalized events have been persisted yet.")

elif page == "Correlation":
    page_header("Correlation workspace", "Indexed relationships")
    events = event_map(store)
    groups = rows(store, "correlated_groups")
    if not groups:
        st.info("No correlated groups have been persisted yet.")
    for group in groups:
        members = [events[event_id] for event_id in group.get("event_ids", []) if event_id in events]
        with st.expander(f"{group.get('group_id')} · {len(members)} events"):
            st.markdown(f"**Why these events are grouped:** {group.get('reason', 'No reason recorded')}")
            st.markdown("<div class='timeline'>" + "".join(f"<div class='timeline-item'><b>{event.get('event_type')}</b> · {event.get('timestamp')} · {event.get('user_id') or 'unknown user'} · {event.get('device_id') or 'unknown device'}</div>" for event in sorted(members, key=lambda item: item.get("timestamp", ""))) + "</div>", unsafe_allow_html=True)
            st.dataframe(event_frame(members), width="stretch", hide_index=True)
            if st.button("Evaluate for Rule Gap", key=f"gap_evaluate_{group.get('group_id')}"):
                group_ids = sorted(set(group.get("event_ids", [])))
                previous_gap = store.find("rule_gaps", {"event_ids": group_ids})
                try:
                    gap = service.create_rule_gap(group_ids)
                except ValueError as error:
                    st.info(str(error))
                else:
                    if previous_gap is None:
                        audit(store, "rule_gap_created", {"gap_id": gap["gap_id"], "event_ids": gap["event_ids"]})
                    st.success(f"Rule Gap {gap['gap_id']} · evidence {gap['evidence_status']}")

elif page == "Incidents":
    page_header("Incidents", "Known rule detections")
    incidents = rows(store, "incidents")
    events = event_map(store)
    if not incidents:
        st.info("No rule-backed incidents have been persisted yet.")
    for incident in incidents:
        with st.expander(f"{incident.get('rule_id')} · score {incident.get('score', 0)} · {incident.get('status', 'OPEN')}"):
            st.markdown(f"<div class='soc-card'><b>Incident ID</b> {incident.get('id')} &nbsp; <b>Rule</b> {incident.get('rule_name')} &nbsp; <b>Status</b> {incident.get('status', 'OPEN')}</div>", unsafe_allow_html=True)
            st.write({"score": incident.get("score", 0), "users": incident.get("users", []), "devices": incident.get("devices", []), "explanation": incident.get("explanation")})
            timeline = [events[event_id] for event_id in incident.get("event_ids", []) if event_id in events]
            st.dataframe(event_frame(timeline), width="stretch", hide_index=True)

elif page == "Rule Gaps":
    page_header("Rule gap review", "Evidence-gated evolution")
    gaps = rows(store, "rule_gaps")
    filter_status = st.multiselect("Filter status", ["PENDING", "MALICIOUS", "BENIGN"], default=[])
    if filter_status:
        gaps = [gap for gap in gaps if gap.get("admin_status") in filter_status]
    for gap in gaps:
        evidence_complete = gap.get("evidence_status") == "COMPLETE"
        with st.container(border=True):
            st.markdown(f"### {gap.get('gap_id')} · score {gap.get('score', 0)}")
            st.write({"Correlation reason": gap.get("correlation_reason"), "Admin decision": gap.get("admin_status"), "Event references": len(gap.get("event_ids", []))})
            st.markdown(f"Evidence gate: <span class='{'status-good' if evidence_complete else 'status-bad'}'>{'COMPLETE' if evidence_complete else 'RULE EVOLUTION BLOCKED'}</span>", unsafe_allow_html=True)
            if not evidence_complete:
                st.warning("A concrete firewall, host, or source-IP evidence reference is required before proposal generation.")
                evidence_col, reference_col = st.columns([1, 2])
                with evidence_col:
                    evidence_type = st.selectbox("Evidence type", ["firewall", "host", "source_ip"], key=f"evidence_type_{gap.get('gap_id')}")
                with reference_col:
                    evidence_reference = st.text_input("Evidence reference", key=f"evidence_ref_{gap.get('gap_id')}")
                if st.button("Attach evidence reference", key=f"evidence_save_{gap.get('gap_id')}", disabled=not evidence_reference.strip()):
                    service.attach_gap_evidence(gap["gap_id"], {evidence_type: evidence_reference.strip()}, st.session_state.username)
                    st.rerun()
            widget_key = f"{gap.get('gap_id')}_{gap.get('id')}"
            decision = st.selectbox("Administrator decision", ["PENDING", "BENIGN", "MALICIOUS"], index=["PENDING", "BENIGN", "MALICIOUS"].index(gap.get("admin_status", "PENDING")), key=f"decision_{widget_key}")
            action_col, proposal_col = st.columns(2)
            with action_col:
                if st.button("Save administrator decision", key=f"save_{widget_key}"):
                    service.decide_gap(gap["gap_id"], decision, st.session_state.username)
                    st.rerun()
            with proposal_col:
                can_propose = evidence_complete and gap.get("admin_status") == "MALICIOUS"
                if st.button("Generate candidate rule", disabled=not can_propose, key=f"proposal_{widget_key}"):
                    proposal = service.create_candidate(gap["gap_id"])
                    st.success(f"Created {proposal['proposal_id']} in PENDING state.")
                    st.rerun()
    proposals = rows(store, "rule_proposals")
    if proposals:
        st.markdown("### Proposals")
        st.dataframe(pd.DataFrame(proposals), width="stretch", hide_index=True)

elif page == "Rule Library":
    page_header("Rule library", "Transparent detection and lifecycle")
    st.dataframe(pd.DataFrame([asdict(rule) for rule in RULES]), width="stretch", hide_index=True)
    proposals = rows(store, "rule_proposals")
    if proposals:
        st.markdown("### Candidate review and lifecycle")
        proposal_id = st.selectbox(
            "Proposal",
            [item["proposal_id"] for item in proposals],
            format_func=lambda item_id: f"{item_id} · {next((item.get('status') for item in proposals if item.get('proposal_id') == item_id), 'UNKNOWN')}",
            key="proposal_select",
        )
        proposal = next(item for item in proposals if item.get("proposal_id") == proposal_id)
        st.json(proposal)
        if proposal.get("status") == "PENDING":
            if st.button("Run historical replay", key=f"replay_{proposal['proposal_id']}"):
                result = service.replay_candidate(proposal["proposal_id"])
                st.success(f"Historical replay checked {result['records_checked']} stored events; candidate matches: {result['match_count']}.")
                st.rerun()
            if proposal.get("replay_status") == "COMPLETED":
                approve_col, reject_col = st.columns(2)
                with approve_col:
                    if st.button("Approve candidate", key=f"approve_{proposal['proposal_id']}"):
                        service.review_candidate(proposal["proposal_id"], "APPROVED", st.session_state.username)
                        st.rerun()
                with reject_col:
                    if st.button("Reject candidate", key=f"reject_{proposal['proposal_id']}"):
                        service.review_candidate(proposal["proposal_id"], "REJECTED", st.session_state.username)
                        st.rerun()
        elif proposal.get("status") == "APPROVED":
            if st.button("Activate approved rule", key=f"activate_{proposal['proposal_id']}"):
                active = service.activate_candidate(proposal["proposal_id"], st.session_state.username)
                st.success(f"{active['proposal_id']} version {active['version']} is ACTIVE.")
                st.rerun()
        elif proposal.get("status") == "ACTIVE":
            if st.button("Deactivate active rule", key=f"deactivate_{proposal['proposal_id']}"):
                service.deactivate_candidate(proposal["proposal_id"], st.session_state.username)
                st.success("Rule deactivated; historical version retained.")
                st.rerun()
        replay_rows = [item for item in rows(store, "replay_results") if item.get("proposal_id") == proposal.get("proposal_id")]
        if replay_rows:
            st.markdown("### Historical replay results")
            st.dataframe(pd.DataFrame(replay_rows), width="stretch", hide_index=True)
    if rows(store, "rules"):
        st.markdown("### Version history")
        st.dataframe(pd.DataFrame(rows(store, "rule_versions")), width="stretch", hide_index=True)

elif page == "Replay":
    page_header("Replay validation", "Historical evidence")
    dataset = st.selectbox("Dataset", ["CTU-SME-11", "LANL Cyber1", "TON_IoT"])
    path = st.text_input("Local dataset path")
    if st.button("Replay external dataset", type="primary"):
        try:
            started = perf_counter()
            adapter = DatasetReplayAdapter(path, dataset)
            replay_events = list(adapter.read())
            active_rules = [rule for rule in rows(store, "rules") if rule.get("status") == "ACTIVE"]
            matches = detect(replay_events, active_rules=active_rules)
            matched_event_ids = sorted({event_id for incident in matches for event_id in incident["event_ids"]})
            result = {"dataset": dataset, "result_type": "HISTORICAL_REPLAY", "records_checked": len(replay_events), "matches": matched_event_ids, "match_count": len(matched_event_ids), "matched_rules": [incident.get("rule_id") for incident in matches], "duration_ms": round((perf_counter() - started) * 1000, 3), "validation": "COMPLETED"}
            store.add("replay_results", result)
            audit(store, "dataset_historical_replay", {"dataset": dataset, "records_checked": result["records_checked"], "match_count": result["match_count"]})
            st.success(f"Historical replay completed: {result['records_checked']} events scanned; matches: {result['match_count']}.")
        except (FileNotFoundError, ValueError, PermissionError) as error:
            st.error(str(error))
    replay_results = rows(store, "replay_results")
    if replay_results:
        st.dataframe(pd.DataFrame(replay_results), width="stretch", hide_index=True)

elif page == "Telemetry Health":
    page_header("Telemetry health", "Source availability")
    windows = WindowsEventLogAdapter()
    wazuh = WazuhAdapter()
    syslog = SyslogAdapter()
    sources = [
        {"source": windows.name, "status": windows.status(), "mode": "Windows native reader"},
        {"source": "Wazuh", "status": wazuh.status(), "mode": "JSON adapter; manager API not connected"},
        {"source": "Suricata", "status": OptionalAdapter("Suricata").status(), "mode": "not configured"},
        {"source": "Syslog", "status": syslog.status(), "mode": "UDP receiver or labeled local test input"},
    ]
    st.dataframe(pd.DataFrame(sources), width="stretch", hide_index=True)
    st.caption("CONNECTED is shown only after a source check succeeds. Local Syslog and Wazuh test inputs are labeled TEST MODE.")

elif page == "Endpoint Health":
    page_header("Endpoint health", "Lightweight collectors")
    endpoint_rows = rows(store, "endpoint_status")
    if endpoint_rows:
        st.dataframe(pd.DataFrame(endpoint_rows), width="stretch", hide_index=True)
    else:
        st.info("No endpoint heartbeat has been recorded. Central processing remains available through replay and API ingestion.")

elif page == "Audit Trail":
    page_header("Audit trail", "Administrator accountability")
    st.dataframe(pd.DataFrame(rows(store, "audit_log")), width="stretch", hide_index=True)

elif page == "Reports":
    page_header("Reports", "Exportable evidence")
    st.dataframe(pd.DataFrame([completion_report(store)]), width="stretch", hide_index=True)
    report_options = {
        "Telemetry Report": "normalized_events",
        "Incident Report": "incidents",
        "Rule Gap Report": "rule_gaps",
        "Rule Lifecycle Report": "rules",
        "Replay Report": "replay_results",
        "Audit Report": "audit_log",
    }
    for title, table in report_options.items():
        report_rows = rows(store, table)
        st.download_button(f"Download {title} (PDF-ready HTML)", report_html(title, report_rows), file_name=f"{table}.html", mime="text/html", key=f"html_{table}")
        st.download_button(f"Download {title} (text)", report_text(title, report_rows), file_name=f"{table}.txt", mime="text/plain", key=f"text_{table}")
        st.caption(f"{len(report_rows):,} records")

store.close()
