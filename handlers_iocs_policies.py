"""Custom IOCs (Indicators of Compromise) and Prevention Policies -- the two
fleet-wide configuration surfaces that shape how Falcon detects/blocks."""
from __future__ import annotations

import crowdstrike_client as cs
from imperal_sdk import ActionResult

from app import ext, chat
from handlers_connection import _resolve_connection, _get_token
from schemas import (
    ListIocsParams, CreateIocParams, IocIdParams,
    ListPreventionPoliciesParams, PolicyIdParams, SetPreventionPolicyEnabledParams,
    FalconIoc, IocList, PreventionPolicy, PolicyList, DeleteResult,
)


def _no_conn() -> ActionResult:
    return ActionResult.error("No CrowdStrike Falcon tenant is connected yet.")


def _to_ioc(d: dict) -> FalconIoc:
    return FalconIoc(
        ioc_id=d.get("id", ""), ioc_type=d.get("type", ""), value=d.get("value", ""),
        action=d.get("action", ""), description=d.get("description", ""),
    )


def _to_policy(d: dict) -> PreventionPolicy:
    return PreventionPolicy(
        policy_id=d.get("id", ""), name=d.get("name", ""),
        enabled=bool(d.get("enabled", False)), platform_name=d.get("platform_name", ""),
    )


@chat.function("list_iocs", "List custom IOCs (Indicators of Compromise) configured on the connected Falcon tenant.", action_type="read", chain_callable=True, data_model=IocList, event="crowdstrike-falcon-connector.list_iocs")
async def list_iocs(ctx, params: ListIocsParams) -> ActionResult:
    """List custom IOCs (Indicators of Compromise) configured on the connected Falcon tenant."""
    conn = await _resolve_connection(ctx, params.connection_id)
    if not conn:
        return _no_conn()
    token = await _get_token(ctx, conn)
    try:
        query = {"limit": params.limit}
        if params.types:
            query["types"] = params.types
        resp = await cs.api_get(ctx, conn["region"], token, "/iocs/combined/indicator/v1", params=query)
        items = resp.get("resources", []) if isinstance(resp, dict) else []
        out = IocList(iocs=[_to_ioc(d) for d in items])
        return ActionResult.success(data=out, summary=f"Found {len(out.iocs)} IOC(s).")
    except cs.ClientFail as e:
        return ActionResult.error(e.payload["error"], retryable=e.payload.get("retryable", False))


@chat.function("create_ioc", "Create a new custom IOC (hash/domain/IP) with a detect/prevent/allow action applied fleet-wide (or to selected platforms).", action_type="write", chain_callable=True, data_model=FalconIoc, event="crowdstrike-falcon-connector.create_ioc", effects=["crowdstrike.ioc.created"])
async def create_ioc(ctx, params: CreateIocParams) -> ActionResult:
    """Create a new custom IOC (hash/domain/IP) with a detect/prevent/allow action applied fleet-wide (or to selected platforms)."""
    conn = await _resolve_connection(ctx, params.connection_id)
    if not conn:
        return _no_conn()
    token = await _get_token(ctx, conn)
    try:
        payload = {
            "indicators": [{
                "type": params.ioc_type, "value": params.value, "action": params.action,
                "description": params.description, "platforms": params.platforms or ["windows", "mac", "linux"],
            }]
        }
        resp = await cs.api_post(ctx, conn["region"], token, "/iocs/entities/indicators/v1", json=payload)
        items = resp.get("resources", []) if isinstance(resp, dict) else []
        if not items:
            return ActionResult.error("CrowdStrike did not return the created IOC.")
        return ActionResult.success(
            data=_to_ioc(items[0]), summary=f"Created IOC ({params.ioc_type}: {params.value}, action={params.action}).",
            refresh_panels=["crowdstrike_iocs"],
        )
    except cs.ClientFail as e:
        return ActionResult.error(e.payload["error"], retryable=e.payload.get("retryable", False))


@chat.function("delete_ioc", "Permanently delete a custom IOC. Cannot be undone.", action_type="destructive", chain_callable=True, data_model=DeleteResult, event="crowdstrike-falcon-connector.delete_ioc", effects=["crowdstrike.ioc.deleted"])
async def delete_ioc(ctx, params: IocIdParams) -> ActionResult:
    """Permanently delete a custom IOC. Cannot be undone."""
    conn = await _resolve_connection(ctx, params.connection_id)
    if not conn:
        return _no_conn()
    token = await _get_token(ctx, conn)
    try:
        await cs.api_delete(ctx, conn["region"], token, "/iocs/entities/indicators/v1", params={"ids": params.ioc_id})
        return ActionResult.success(data=DeleteResult(ok=True, detail="IOC deleted."), summary="IOC deleted.", refresh_panels=["crowdstrike_iocs"])
    except cs.ClientFail as e:
        return ActionResult.error(e.payload["error"], retryable=e.payload.get("retryable", False))


@chat.function("list_prevention_policies", "List Prevention Policies configured on the connected Falcon tenant, optionally filtered by an FQL expression.", action_type="read", chain_callable=True, data_model=PolicyList, event="crowdstrike-falcon-connector.list_prevention_policies")
async def list_prevention_policies(ctx, params: ListPreventionPoliciesParams) -> ActionResult:
    """List Prevention Policies configured on the connected Falcon tenant, optionally filtered by an FQL expression."""
    conn = await _resolve_connection(ctx, params.connection_id)
    if not conn:
        return _no_conn()
    token = await _get_token(ctx, conn)
    try:
        query = {"limit": 100}
        if params.filter_expr:
            query["filter"] = params.filter_expr
        resp = await cs.api_get(ctx, conn["region"], token, "/policy/combined/prevention/v1", params=query)
        items = resp.get("resources", []) if isinstance(resp, dict) else []
        out = PolicyList(policies=[_to_policy(d) for d in items])
        return ActionResult.success(data=out, summary=f"Found {len(out.policies)} prevention polic(y/ies).")
    except cs.ClientFail as e:
        return ActionResult.error(e.payload["error"], retryable=e.payload.get("retryable", False))


@chat.function("get_prevention_policy", "Read one Prevention Policy in full by its id.", action_type="read", chain_callable=True, data_model=PreventionPolicy, event="crowdstrike-falcon-connector.get_prevention_policy")
async def get_prevention_policy(ctx, params: PolicyIdParams) -> ActionResult:
    """Read one Prevention Policy in full by its id."""
    conn = await _resolve_connection(ctx, params.connection_id)
    if not conn:
        return _no_conn()
    token = await _get_token(ctx, conn)
    try:
        resp = await cs.api_get(ctx, conn["region"], token, "/policy/entities/prevention/v1", params={"ids": params.policy_id})
        items = resp.get("resources", []) if isinstance(resp, dict) else []
        if not items:
            return ActionResult.error("No such prevention policy.")
        p = _to_policy(items[0])
        return ActionResult.success(data=p, summary=f"Policy '{p.name}' ({'enabled' if p.enabled else 'disabled'}).")
    except cs.ClientFail as e:
        return ActionResult.error(e.payload["error"], retryable=e.payload.get("retryable", False))


@chat.function("set_prevention_policy_enabled", "Enable or disable a Prevention Policy without deleting it.", action_type="write", chain_callable=True, data_model=DeleteResult, event="crowdstrike-falcon-connector.set_prevention_policy_enabled", effects=["crowdstrike.policy.updated"])
async def set_prevention_policy_enabled(ctx, params: SetPreventionPolicyEnabledParams) -> ActionResult:
    """Enable or disable a Prevention Policy without deleting it."""
    conn = await _resolve_connection(ctx, params.connection_id)
    if not conn:
        return _no_conn()
    token = await _get_token(ctx, conn)
    try:
        await cs.api_patch(ctx, conn["region"], token, "/policy/entities/prevention/v1", json={
            "resources": [{"id": params.policy_id, "settings": [], "enabled": params.enabled}]
        })
        state = "enabled" if params.enabled else "disabled"
        return ActionResult.success(
            data=DeleteResult(ok=True, detail=f"Policy {state}."), summary=f"Prevention policy {state}.",
            refresh_panels=["crowdstrike_policies"],
        )
    except cs.ClientFail as e:
        return ActionResult.error(e.payload["error"], retryable=e.payload.get("retryable", False))
