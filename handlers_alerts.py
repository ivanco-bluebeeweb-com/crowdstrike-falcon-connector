"""Detections (sensor-visibility events) and Incidents (CrowdScore-correlated
groupings) -- the two alert streams analysts triage day to day."""
from __future__ import annotations

import crowdstrike_client as cs
from imperal_sdk import ActionResult

from app import ext, chat
from handlers_connection import _resolve_connection, _get_token
from schemas import (
    ListDetectionsParams, DetectionIdParams, UpdateDetectionStatusParams,
    ListIncidentsParams, IncidentIdParams, UpdateIncidentParams,
    FalconDetection, DetectionList, FalconIncident, IncidentList, DeleteResult,
)


def _no_conn() -> ActionResult:
    return ActionResult.error("No CrowdStrike Falcon tenant is connected yet.")


def _to_detection(d: dict) -> FalconDetection:
    behaviors = d.get("behaviors", []) or []
    b0 = behaviors[0] if behaviors else {}
    return FalconDetection(
        detection_id=d.get("detection_id", ""),
        hostname=d.get("device", {}).get("hostname", "") if isinstance(d.get("device"), dict) else "",
        severity=str(d.get("max_severity_displayname", d.get("max_severity", ""))),
        status=d.get("status", ""),
        tactic=b0.get("tactic", ""),
        technique=b0.get("technique", ""),
        created=d.get("first_behavior", d.get("created_timestamp", "")),
    )


def _to_incident(d: dict) -> FalconIncident:
    return FalconIncident(
        incident_id=d.get("incident_id", ""),
        state=d.get("state", ""),
        status=str(d.get("status", "")),
        fine_score=int(d.get("fine_score", 0) or 0),
        hosts_count=len(d.get("hosts", []) or []),
        created=d.get("created", ""),
    )


@chat.function("list_detections", "List sensor-visibility Detections in the connected Falcon tenant, optionally filtered by an FQL expression (e.g. \"status:'new'\").", action_type="read", chain_callable=True, data_model=DetectionList, event="crowdstrike-falcon-connector.list_detections")
async def list_detections(ctx, params: ListDetectionsParams) -> ActionResult:
    """List sensor-visibility Detections in the connected Falcon tenant, optionally filtered by an FQL expression."""
    conn = await _resolve_connection(ctx, params.connection_id)
    if not conn:
        return _no_conn()
    token = await _get_token(ctx, conn)
    try:
        query = {"limit": params.limit}
        if params.filter_expr:
            query["filter"] = params.filter_expr
        ids_resp = await cs.api_get(ctx, conn["region"], token, "/detects/queries/detects/v1", params=query)
        ids = ids_resp.get("resources", []) if isinstance(ids_resp, dict) else []
        if not ids:
            return ActionResult.success(data=DetectionList(detections=[]), summary="No detections found.")
        details = await cs.api_post(ctx, conn["region"], token, "/detects/entities/summaries/GET/v1", json={"ids": ids})
        items = details.get("resources", []) if isinstance(details, dict) else []
        out = DetectionList(detections=[_to_detection(d) for d in items])
        return ActionResult.success(data=out, summary=f"Found {len(out.detections)} detection(s).")
    except cs.ClientFail as e:
        return ActionResult.error(e.payload["error"], retryable=e.payload.get("retryable", False))


@chat.function("get_detection", "Read one Detection in full by its detection id.", action_type="read", chain_callable=True, data_model=FalconDetection, event="crowdstrike-falcon-connector.get_detection")
async def get_detection(ctx, params: DetectionIdParams) -> ActionResult:
    """Read one Detection in full by its detection id."""
    conn = await _resolve_connection(ctx, params.connection_id)
    if not conn:
        return _no_conn()
    token = await _get_token(ctx, conn)
    try:
        details = await cs.api_post(ctx, conn["region"], token, "/detects/entities/summaries/GET/v1", json={"ids": [params.detection_id]})
        items = details.get("resources", []) if isinstance(details, dict) else []
        if not items:
            return ActionResult.error("No such detection.")
        d = _to_detection(items[0])
        return ActionResult.success(data=d, summary=f"Detection {d.detection_id} ({d.severity}).")
    except cs.ClientFail as e:
        return ActionResult.error(e.payload["error"], retryable=e.payload.get("retryable", False))


@chat.function("update_detection_status", "Update a Detection's triage status (new/in_progress/true_positive/false_positive/ignored), optionally with a comment and/or assignee.", action_type="write", chain_callable=True, data_model=DeleteResult, event="crowdstrike-falcon-connector.update_detection_status", effects=["crowdstrike.detection.updated"])
async def update_detection_status(ctx, params: UpdateDetectionStatusParams) -> ActionResult:
    """Update a Detection's triage status, optionally with a comment and/or assignee."""
    conn = await _resolve_connection(ctx, params.connection_id)
    if not conn:
        return _no_conn()
    token = await _get_token(ctx, conn)
    try:
        payload = {"ids": [params.detection_id], "status": params.status}
        if params.comment:
            payload["comment"] = params.comment
        if params.assign_to_uuid:
            payload["assigned_to_uuid"] = params.assign_to_uuid
        await cs.api_patch(ctx, conn["region"], token, "/detects/entities/detects/v2", json=payload)
        return ActionResult.success(
            data=DeleteResult(ok=True, detail=f"Detection set to {params.status}."),
            summary=f"Detection updated to '{params.status}'.",
            refresh_panels=["crowdstrike_detections"],
        )
    except cs.ClientFail as e:
        return ActionResult.error(e.payload["error"], retryable=e.payload.get("retryable", False))


@chat.function("list_incidents", "List correlated Incidents (CrowdScore groupings of related detections) in the connected Falcon tenant.", action_type="read", chain_callable=True, data_model=IncidentList, event="crowdstrike-falcon-connector.list_incidents")
async def list_incidents(ctx, params: ListIncidentsParams) -> ActionResult:
    """List correlated Incidents (CrowdScore groupings) in the connected Falcon tenant."""
    conn = await _resolve_connection(ctx, params.connection_id)
    if not conn:
        return _no_conn()
    token = await _get_token(ctx, conn)
    try:
        query = {"limit": params.limit}
        if params.filter_expr:
            query["filter"] = params.filter_expr
        ids_resp = await cs.api_get(ctx, conn["region"], token, "/incidents/queries/incidents/v1", params=query)
        ids = ids_resp.get("resources", []) if isinstance(ids_resp, dict) else []
        if not ids:
            return ActionResult.success(data=IncidentList(incidents=[]), summary="No incidents found.")
        details = await cs.api_post(ctx, conn["region"], token, "/incidents/entities/incidents/GET/v1", json={"ids": ids})
        items = details.get("resources", []) if isinstance(details, dict) else []
        out = IncidentList(incidents=[_to_incident(d) for d in items])
        return ActionResult.success(data=out, summary=f"Found {len(out.incidents)} incident(s).")
    except cs.ClientFail as e:
        return ActionResult.error(e.payload["error"], retryable=e.payload.get("retryable", False))


@chat.function("get_incident", "Read one Incident in full by its incident id.", action_type="read", chain_callable=True, data_model=FalconIncident, event="crowdstrike-falcon-connector.get_incident")
async def get_incident(ctx, params: IncidentIdParams) -> ActionResult:
    """Read one Incident in full by its incident id."""
    conn = await _resolve_connection(ctx, params.connection_id)
    if not conn:
        return _no_conn()
    token = await _get_token(ctx, conn)
    try:
        details = await cs.api_post(ctx, conn["region"], token, "/incidents/entities/incidents/GET/v1", json={"ids": [params.incident_id]})
        items = details.get("resources", []) if isinstance(details, dict) else []
        if not items:
            return ActionResult.error("No such incident.")
        inc = _to_incident(items[0])
        return ActionResult.success(data=inc, summary=f"Incident {inc.incident_id} (score {inc.fine_score}).")
    except cs.ClientFail as e:
        return ActionResult.error(e.payload["error"], retryable=e.payload.get("retryable", False))


@chat.function("update_incident", "Update an Incident's status and/or add a tag/comment.", action_type="write", chain_callable=True, data_model=DeleteResult, event="crowdstrike-falcon-connector.update_incident", effects=["crowdstrike.incident.updated"])
async def update_incident(ctx, params: UpdateIncidentParams) -> ActionResult:
    """Update an Incident's status and/or add a tag/comment."""
    conn = await _resolve_connection(ctx, params.connection_id)
    if not conn:
        return _no_conn()
    token = await _get_token(ctx, conn)
    try:
        actions = []
        if params.status:
            actions.append({"action_name": "update_status", "action_parameters": [{"name": "update_status", "value": params.status}]})
        if params.add_tag:
            actions.append({"action_name": "add_tag", "action_parameters": [{"name": "add_tag", "value": params.add_tag}]})
        if params.add_comment:
            actions.append({"action_name": "add_comment", "action_parameters": [{"name": "add_comment", "value": params.add_comment}]})
        if not actions:
            return ActionResult.error("Nothing to update -- provide status, add_tag, or add_comment.")
        await cs.api_post(ctx, conn["region"], token, "/incidents/entities/incident-actions/v1", json={"ids": [params.incident_id], "action_parameters": actions[0]["action_parameters"], "action_name": actions[0]["action_name"]})
        return ActionResult.success(
            data=DeleteResult(ok=True, detail="Incident updated."),
            summary="Incident updated.",
            refresh_panels=["crowdstrike_incidents"],
        )
    except cs.ClientFail as e:
        return ActionResult.error(e.payload["error"], retryable=e.payload.get("retryable", False))
