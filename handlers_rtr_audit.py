"""Real Time Response (RTR) -- start a session on a host and run read-only
commands (ls/ps/netstat/etc.) for live investigation, plus Spotlight
Vulnerabilities (CVE exposure per host) and the estate health audit."""
from __future__ import annotations

import crowdstrike_client as cs
from imperal_sdk import ActionResult

from app import ext, chat
from handlers_connection import _resolve_connection, _get_token
from schemas import (
    NoParams, ConnectionRefParams, RtrSessionParams, RtrCommandParams,
    ListVulnerabilitiesParams, RtrSession, RtrCommandResult, Vulnerability,
    VulnerabilityList, EstateAudit,
)


def _no_conn() -> ActionResult:
    return ActionResult.error("No CrowdStrike Falcon tenant is connected yet.")


@chat.function("start_rtr_session", "Start a Real Time Response (RTR) session on a host, for live read-only investigation (ls, ps, netstat, etc. via run_rtr_command).", action_type="write", chain_callable=True, data_model=RtrSession, event="crowdstrike-falcon-connector.start_rtr_session", effects=["crowdstrike.rtr.session_started"])
async def start_rtr_session(ctx, params: RtrSessionParams) -> ActionResult:
    """Start a Real Time Response (RTR) session on a host, for live read-only investigation."""
    conn = await _resolve_connection(ctx, params.connection_id)
    if not conn:
        return _no_conn()
    token = await _get_token(ctx, conn)
    try:
        resp = await cs.api_post(ctx, conn["region"], token, "/real-time-response/entities/sessions/v1", json={"device_id": params.host_id})
        res = resp.get("resources", []) if isinstance(resp, dict) else []
        if not res:
            return ActionResult.error("CrowdStrike did not return a session.")
        sid = res[0].get("session_id", "")
        return ActionResult.success(
            data=RtrSession(session_id=sid, host_id=params.host_id, status="active"),
            summary=f"Started RTR session on host {params.host_id}.",
        )
    except cs.ClientFail as e:
        return ActionResult.error(e.payload["error"], retryable=e.payload.get("retryable", False))


@chat.function("run_rtr_command", "Run a read-only RTR command (e.g. 'ls', 'ps', 'netstat', 'ifconfig') in an active RTR session and return its output.", action_type="write", chain_callable=True, data_model=RtrCommandResult, event="crowdstrike-falcon-connector.run_rtr_command", effects=["crowdstrike.rtr.command_run"])
async def run_rtr_command(ctx, params: RtrCommandParams) -> ActionResult:
    """Run a read-only RTR command in an active RTR session and return its output."""
    conn = await _resolve_connection(ctx, params.connection_id)
    if not conn:
        return _no_conn()
    token = await _get_token(ctx, conn)
    try:
        resp = await cs.api_post(ctx, conn["region"], token, "/real-time-response/entities/command/v1", json={
            "base_command": params.command.split(" ")[0], "command_string": params.command, "session_id": params.session_id,
        })
        res = resp.get("resources", []) if isinstance(resp, dict) else []
        r0 = res[0] if res else {}
        out = RtrCommandResult(
            session_id=params.session_id, command=params.command,
            stdout=r0.get("stdout", ""), stderr=r0.get("stderr", ""),
        )
        return ActionResult.success(data=out, summary=f"Ran '{params.command}'.")
    except cs.ClientFail as e:
        return ActionResult.error(e.payload["error"], retryable=e.payload.get("retryable", False))


@chat.function("list_vulnerabilities", "List Spotlight Vulnerabilities (CVE exposure) across the fleet, optionally filtered by an FQL expression (e.g. \"cve.severity:'CRITICAL'\").", action_type="read", chain_callable=True, data_model=VulnerabilityList, event="crowdstrike-falcon-connector.list_vulnerabilities")
async def list_vulnerabilities(ctx, params: ListVulnerabilitiesParams) -> ActionResult:
    """List Spotlight Vulnerabilities (CVE exposure) across the fleet."""
    conn = await _resolve_connection(ctx, params.connection_id)
    if not conn:
        return _no_conn()
    token = await _get_token(ctx, conn)
    try:
        query = {"limit": params.limit}
        if params.filter_expr:
            query["filter"] = params.filter_expr
        resp = await cs.api_get(ctx, conn["region"], token, "/spotlight/combined/vulnerabilities/v1", params=query)
        items = resp.get("resources", []) if isinstance(resp, dict) else []
        out = []
        for d in items:
            cve = d.get("cve", {}) if isinstance(d.get("cve"), dict) else {}
            host = d.get("host_info", {}) if isinstance(d.get("host_info"), dict) else {}
            out.append(Vulnerability(
                vuln_id=d.get("id", ""), cve_id=cve.get("id", ""),
                severity=cve.get("severity", ""), hostname=host.get("hostname", ""),
                status=d.get("status", ""),
            ))
        return ActionResult.success(data=VulnerabilityList(vulnerabilities=out), summary=f"Found {len(out)} vulnerability record(s).")
    except cs.ClientFail as e:
        return ActionResult.error(e.payload["error"], retryable=e.payload.get("retryable", False))


@chat.function("audit_falcon_estate", "Build one aggregated health report across the connected Falcon tenant: stale hosts, open critical incidents, new detections, and disabled prevention policies.", action_type="read", chain_callable=True, data_model=EstateAudit, event="crowdstrike-falcon-connector.audit_falcon_estate")
async def audit_falcon_estate(ctx, params: ConnectionRefParams) -> ActionResult:
    """Build one aggregated health report across the connected Falcon tenant."""
    conn = await _resolve_connection(ctx, params.connection_id)
    if not conn:
        return _no_conn()
    token = await _get_token(ctx, conn)
    try:
        hosts_resp = await cs.api_get(ctx, conn["region"], token, "/devices/queries/devices/v1", params={"limit": 500})
        host_ids = hosts_resp.get("resources", []) if isinstance(hosts_resp, dict) else []

        stale = 0
        if host_ids:
            details = await cs.api_post(ctx, conn["region"], token, "/devices/entities/devices/v2", json={"ids": host_ids[:500]})
            import time as _t
            now = _t.time()
            for d in (details.get("resources", []) if isinstance(details, dict) else []):
                ls = d.get("last_seen", "")
                if ls:
                    try:
                        import datetime
                        seen = datetime.datetime.fromisoformat(ls.replace("Z", "+00:00")).timestamp()
                        if now - seen > 7 * 86400:
                            stale += 1
                    except Exception:
                        pass

        inc_resp = await cs.api_get(ctx, conn["region"], token, "/incidents/queries/incidents/v1", params={"filter": "state:'open'", "limit": 500})
        open_incidents = inc_resp.get("resources", []) if isinstance(inc_resp, dict) else []
        critical_incidents = 0
        if open_incidents:
            inc_details = await cs.api_post(ctx, conn["region"], token, "/incidents/entities/incidents/GET/v1", json={"ids": open_incidents[:500]})
            for d in (inc_details.get("resources", []) if isinstance(inc_details, dict) else []):
                if int(d.get("fine_score", 0) or 0) >= 80:
                    critical_incidents += 1

        det_resp = await cs.api_get(ctx, conn["region"], token, "/detects/queries/detects/v1", params={"filter": "status:'new'", "limit": 500})
        new_detections = len(det_resp.get("resources", []) if isinstance(det_resp, dict) else [])

        pol_resp = await cs.api_get(ctx, conn["region"], token, "/policy/queries/prevention/v1", params={"limit": 500})
        pol_ids = pol_resp.get("resources", []) if isinstance(pol_resp, dict) else []
        disabled_policies = 0
        if pol_ids:
            pol_details = await cs.api_get(ctx, conn["region"], token, "/policy/entities/prevention/v1", params={"ids": pol_ids})
            for d in (pol_details.get("resources", []) if isinstance(pol_details, dict) else []):
                if not d.get("enabled", True):
                    disabled_policies += 1

        notes = []
        if critical_incidents:
            notes.append(f"{critical_incidents} open critical-severity incident(s) need triage.")
        if disabled_policies:
            notes.append(f"{disabled_policies} prevention polic(y/ies) are disabled.")
        if stale:
            notes.append(f"{stale} host(s) have not checked in for 7+ days.")
        if not notes:
            notes.append("No critical findings.")

        audit = EstateAudit(
            region=conn["region"], total_hosts=len(host_ids), stale_hosts_7d=stale,
            open_incidents_critical=critical_incidents, open_detections_new=new_detections,
            disabled_prevention_policies=disabled_policies, notes=" ".join(notes),
        )
        return ActionResult.success(data=audit, summary=" ".join(notes))
    except cs.ClientFail as e:
        return ActionResult.error(e.payload["error"], retryable=e.payload.get("retryable", False))
