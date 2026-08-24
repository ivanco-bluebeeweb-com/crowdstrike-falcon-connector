"""Hosts (endpoint fleet) management: list/get hosts, network containment
(contain/lift containment -- the core EDR "stop the bleeding" action),
hide/unhide from the console.
"""
from __future__ import annotations

import crowdstrike_client as cs
from imperal_sdk import ActionResult

from app import ext, chat
from handlers_connection import _resolve_connection, _get_token
from schemas import (
    ListHostsParams, HostIdParams, HostActionParams,
    FalconHost, HostList, DeleteResult,
)


def _no_conn_error() -> ActionResult:
    return ActionResult.error("No CrowdStrike Falcon tenant is connected yet.")


def _to_host(d: dict) -> FalconHost:
    return FalconHost(
        host_id=d.get("device_id", ""),
        hostname=d.get("hostname", ""),
        platform_name=d.get("platform_name", ""),
        os_version=d.get("os_version", ""),
        last_seen=d.get("last_seen", ""),
        status=d.get("status", d.get("connection_status", "unknown")),
    )


@chat.function("list_hosts", "List endpoints (hosts/sensors) in the connected Falcon tenant, optionally filtered by an FQL expression.", action_type="read", chain_callable=True, data_model=HostList, event="crowdstrike-falcon-connector.list_hosts")
async def list_hosts(ctx, params: ListHostsParams) -> ActionResult:
    """List endpoints (hosts/sensors) in the connected Falcon tenant, optionally filtered by an FQL expression."""
    conn = await _resolve_connection(ctx, params.connection_id)
    if not conn:
        return _no_conn_error()
    token = await _get_token(ctx, conn)
    try:
        query = {"limit": params.limit}
        if params.filter_expr:
            query["filter"] = params.filter_expr
        ids_resp = await cs.api_get(ctx, conn["region"], token, "/devices/queries/devices/v1", params=query)
        ids = ids_resp.get("resources", []) if isinstance(ids_resp, dict) else []
        if not ids:
            return ActionResult.success(data=HostList(hosts=[]), summary="No hosts found.")
        details = await cs.api_post(ctx, conn["region"], token, "/devices/entities/devices/v2", json={"ids": ids})
        items = details.get("resources", []) if isinstance(details, dict) else []
        hosts = [_to_host(d) for d in items]
        return ActionResult.success(data=HostList(hosts=hosts), summary=f"Found {len(hosts)} host(s).")
    except cs.ClientFail as e:
        return ActionResult.error(e.payload["error"], retryable=e.payload.get("retryable", False))


@chat.function("get_host", "Read one endpoint (host/sensor) in full by its Falcon device id.", action_type="read", chain_callable=True, data_model=FalconHost, event="crowdstrike-falcon-connector.get_host")
async def get_host(ctx, params: HostIdParams) -> ActionResult:
    """Read one endpoint (host/sensor) in full by its Falcon device id."""
    conn = await _resolve_connection(ctx, params.connection_id)
    if not conn:
        return _no_conn_error()
    token = await _get_token(ctx, conn)
    try:
        details = await cs.api_post(ctx, conn["region"], token, "/devices/entities/devices/v2", json={"ids": [params.host_id]})
        items = details.get("resources", []) if isinstance(details, dict) else []
        if not items:
            return ActionResult.error("No such host.")
        host = _to_host(items[0])
        return ActionResult.success(data=host, summary=f"Loaded host {host.hostname or params.host_id}.")
    except cs.ClientFail as e:
        return ActionResult.error(e.payload["error"], retryable=e.payload.get("retryable", False))


async def _host_action(ctx, params: HostActionParams, action_name: str, summary: str) -> ActionResult:
    conn = await _resolve_connection(ctx, params.connection_id)
    if not conn:
        return _no_conn_error()
    token = await _get_token(ctx, conn)
    try:
        await cs.api_post(
            ctx, conn["region"], token, "/devices/entities/devices-actions/v2",
            json={"action_name": action_name, "ids": params.host_ids},
        )
        return ActionResult.success(
            data=DeleteResult(ok=True, detail=f"{action_name} applied to {len(params.host_ids)} host(s)."),
            summary=summary.format(n=len(params.host_ids)),
            refresh_panels=["crowdstrike_hosts"],
        )
    except cs.ClientFail as e:
        return ActionResult.error(e.payload["error"], retryable=e.payload.get("retryable", False))


@chat.function("contain_hosts", "Network-contain one or more hosts -- isolates them from the network except for traffic to the Falcon cloud. The core incident-response 'stop the bleeding' action.", action_type="destructive", chain_callable=True, data_model=DeleteResult, event="crowdstrike-falcon-connector.contain_hosts", effects=["crowdstrike.host.contained"])
async def contain_hosts(ctx, params: HostActionParams) -> ActionResult:
    """Network-contain one or more hosts -- isolates them from the network except for traffic to the Falcon cloud."""
    return await _host_action(ctx, params, "contain", "Network-contained {n} host(s).")


@chat.function("lift_containment", "Lift network containment on one or more hosts, restoring normal network access.", action_type="write", chain_callable=True, data_model=DeleteResult, event="crowdstrike-falcon-connector.lift_containment", effects=["crowdstrike.host.contained"])
async def lift_containment(ctx, params: HostActionParams) -> ActionResult:
    """Lift network containment on one or more hosts, restoring normal network access."""
    return await _host_action(ctx, params, "lift_containment", "Lifted containment on {n} host(s).")


@chat.function("hide_hosts", "Hide one or more hosts from the Falcon console (does not uninstall the sensor).", action_type="write", chain_callable=True, data_model=DeleteResult, event="crowdstrike-falcon-connector.hide_hosts", effects=["crowdstrike.host.hidden"])
async def hide_hosts(ctx, params: HostActionParams) -> ActionResult:
    """Hide one or more hosts from the Falcon console (does not uninstall the sensor)."""
    return await _host_action(ctx, params, "hide_host", "Hid {n} host(s) from the console.")


@chat.function("unhide_hosts", "Unhide one or more previously hidden hosts.", action_type="write", chain_callable=True, data_model=DeleteResult, event="crowdstrike-falcon-connector.unhide_hosts", effects=["crowdstrike.host.unhidden"])
async def unhide_hosts(ctx, params: HostActionParams) -> ActionResult:
    """Unhide one or more previously hidden hosts."""
    return await _host_action(ctx, params, "unhide_host", "Unhid {n} host(s).")
