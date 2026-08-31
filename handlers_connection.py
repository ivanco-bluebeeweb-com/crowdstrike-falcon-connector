"""Connection management: connect/disconnect CrowdStrike Falcon tenants.
Same shape as Ansible Automation Platform Connector's / Okta Connector's
connection handlers -- async, one secret holding a JSON array, proactive
OAuth2 token caching per connection (see crowdstrike_client.py).
"""
from __future__ import annotations

import json
import time
import uuid

from imperal_sdk import ActionResult

import crowdstrike_client as cs
from app import ext, chat
from schemas import (
    NoParams, ConnectionRefParams,
    ConnectCrowdstrikeParams, CrowdstrikeConnection, ConnectionList,
    DisconnectCrowdstrikeParams, DeleteResult,
)

_CONN_SECRET = "crowdstrike_connections"
_TOKEN_CACHE: dict[str, dict] = {}


async def _load_connections(ctx) -> list[dict]:
    raw = await ctx.secrets.get(_CONN_SECRET)
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except (TypeError, ValueError):
        return []
    return data if isinstance(data, list) else []


async def _save_connections(ctx, items: list[dict]) -> None:
    await ctx.secrets.set(_CONN_SECRET, json.dumps(items))


async def _resolve_connection(ctx, connection_id: str = "") -> dict | None:
    conns = await _load_connections(ctx)
    if not conns:
        return None
    if connection_id:
        for c in conns:
            if c.get("id") == connection_id:
                return c
        return None
    return conns[0]


async def _get_token(ctx, conn: dict) -> str:
    """Return a cached, still-valid OAuth2 token for this connection, or
    fetch a fresh one and cache it. Proactive refresh: re-auth once the
    cached token is within 60s of expiry (handled inside cs.get_token)."""
    cid = conn["id"]
    cached = _TOKEN_CACHE.get(cid)
    if cached and cached.get("expires_at", 0) > time.time():
        return cached["access_token"]
    fresh = await cs.get_token(ctx, conn["region"], conn["client_id"], conn["client_secret"])
    _TOKEN_CACHE[cid] = fresh
    return fresh["access_token"]


def _mask(client_id: str) -> str:
    if len(client_id) <= 6:
        return "***"
    return client_id[:4] + "…" + client_id[-2:]


@chat.function("connect_crowdstrike", "Connect your own CrowdStrike Falcon tenant by saving its cloud region and an OAuth2 API Client (Client ID + Secret), after checking they actually work.", action_type="write", chain_callable=True, data_model=CrowdstrikeConnection, event="crowdstrike-falcon-connector.connect_crowdstrike", effects=["crowdstrike.provider.connected"])
async def connect_crowdstrike(ctx, params: ConnectCrowdstrikeParams) -> ActionResult:
    """Connect your own CrowdStrike Falcon tenant by saving its cloud region and an OAuth2 API Client (Client ID + Secret), after checking they actually work."""
    try:
        token_info = await cs.get_token(ctx, params.region, params.client_id, params.client_secret)
    except cs.ClientFail as e:
        return ActionResult.error(e.payload["error"], retryable=e.payload.get("retryable", False))

    conns = await _load_connections(ctx)
    conn_id = str(uuid.uuid4())
    entry = {
        "id": conn_id,
        "label": params.label or f"Falcon ({params.region})",
        "region": params.region.lower(),
        "client_id": params.client_id,
        "client_secret": params.client_secret,
    }
    conns.append(entry)
    await _save_connections(ctx, conns)
    _TOKEN_CACHE[conn_id] = token_info

    return ActionResult.success(
        data=CrowdstrikeConnection(
            connection_id=conn_id, label=entry["label"], region=entry["region"],
            client_id_masked=_mask(params.client_id),
        ),
        summary=f"Connected CrowdStrike Falcon tenant '{entry['label']}' ({entry['region']}).",
        refresh_panels=["crowdstrike_sidebar", "crowdstrike_settings"],
    )


@chat.function("disconnect_crowdstrike", "Disconnect a CrowdStrike Falcon tenant: deletes the saved OAuth2 Client ID/Secret. Nothing in CrowdStrike itself is changed.", action_type="write", chain_callable=True, data_model=DeleteResult, event="crowdstrike-falcon-connector.disconnect_crowdstrike", effects=["crowdstrike.provider.disconnected"])
async def disconnect_crowdstrike(ctx, params: DisconnectCrowdstrikeParams) -> ActionResult:
    """Disconnect a CrowdStrike Falcon tenant: deletes the saved OAuth2 Client ID/Secret. Nothing in CrowdStrike itself is changed."""
    conns = await _load_connections(ctx)
    remaining = [c for c in conns if c.get("id") != params.connection_id]
    if len(remaining) == len(conns):
        return ActionResult.error("No such connection.")
    await _save_connections(ctx, remaining)
    _TOKEN_CACHE.pop(params.connection_id, None)
    return ActionResult.success(
        data=DeleteResult(ok=True, detail="Disconnected."),
        summary="CrowdStrike Falcon tenant disconnected.",
        refresh_panels=["crowdstrike_sidebar", "crowdstrike_settings"],
    )


@chat.function("list_connections", "List the connected CrowdStrike Falcon tenants (region + masked Client ID).", action_type="read", chain_callable=True, data_model=ConnectionList, event="crowdstrike-falcon-connector.list_connections")
async def list_connections(ctx, params: NoParams) -> ActionResult:
    """List the connected CrowdStrike Falcon tenants (region + masked Client ID)."""
    conns = await _load_connections(ctx)
    items = [
        CrowdstrikeConnection(
            connection_id=c["id"], label=c.get("label", ""), region=c.get("region", ""),
            client_id_masked=_mask(c.get("client_id", "")),
        )
        for c in conns
    ]
    return ActionResult.success(data=ConnectionList(connections=items), summary="Connections listed.")
