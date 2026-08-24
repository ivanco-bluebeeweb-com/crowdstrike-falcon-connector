"""CrowdStrike Falcon Connector -- center panels for Incidents/Detections/
Hosts/IOCs/Prevention Policies, per UI_COMPONENT_PLAN.md."""
from __future__ import annotations

from imperal_sdk import ui

from app import ext
from handlers_connection import _load_connections, _resolve_connection, _get_token
import crowdstrike_client as cs


def _sev_badge(sev: str) -> ui.UINode:
    s = (sev or "").lower()
    variant = "error" if s in ("critical", "high") else ("warning" if s == "medium" else "default")
    return ui.Badge(text=sev or "unknown", variant=variant)


@ext.panel("crowdstrike_incidents", slot="center", title="Incidents", center_overlay=True)
async def crowdstrike_incidents(ctx, **kwargs) -> ui.UINode:
    connections = await _load_connections(ctx)
    if not connections:
        return ui.Empty(message="Nothing to show here", icon="ShieldAlert")
    conn = connections[0]
    token = await _get_token(ctx, conn)
    try:
        resp = await cs.api_get(ctx, conn["region"], token, "/incidents/queries/incidents/v1", params={"limit": 50})
        ids = resp.get("resources", []) if isinstance(resp, dict) else []
        if not ids:
            return ui.Empty(message="No incidents found", icon="ShieldCheck")
        details = await cs.api_post(ctx, conn["region"], token, "/incidents/entities/incidents/GET/v1", json={"ids": ids})
        rows = []
        for d in details.get("resources", []) if isinstance(details, dict) else []:
            rows.append({
                "id": d.get("incident_id", "")[:12],
                "state": d.get("state", ""),
                "score": d.get("fine_score", 0),
                "hosts": len(d.get("hosts", []) or []),
                "created": d.get("created", ""),
            })
        rows.sort(key=lambda r: r.get("score", 0), reverse=True)
    except cs.ClientFail as e:
        return ui.Alert(type="error", message=e.payload["error"])
    return ui.Stack(direction="v", gap=3, align="stretch", children=[
        ui.Header(text="Incidents", level=2),
        ui.Stats(items=[
            {"label": "Открытых", "value": str(len([r for r in rows if r["state"] == "open"]))},
            {"label": "Всего", "value": str(len(rows))},
        ]),
        ui.DataTable(
            rows=rows,
            columns=[
                ui.DataColumn(key="id", label="ID"),
                ui.DataColumn(key="state", label="Статус"),
                ui.DataColumn(key="score", label="CrowdScore"),
                ui.DataColumn(key="hosts", label="Хостов"),
                ui.DataColumn(key="created", label="Создан"),
            ],
        ) if rows else ui.Empty(message="No incidents found", icon="ShieldCheck"),
    ])


@ext.panel("crowdstrike_detections", slot="center", title="Detections", center_overlay=True)
async def crowdstrike_detections(ctx, **kwargs) -> ui.UINode:
    connections = await _load_connections(ctx)
    if not connections:
        return ui.Empty(message="Nothing to show here", icon="Radar")
    conn = connections[0]
    token = await _get_token(ctx, conn)
    try:
        resp = await cs.api_get(ctx, conn["region"], token, "/detects/queries/detects/v1", params={"limit": 50})
        ids = resp.get("resources", []) if isinstance(resp, dict) else []
        if not ids:
            return ui.Empty(message="No detections found", icon="ShieldCheck")
        details = await cs.api_post(ctx, conn["region"], token, "/detects/entities/summaries/GET/v1", json={"ids": ids})
        rows = []
        for d in details.get("resources", []) if isinstance(details, dict) else []:
            device = d.get("device", {}) or {}
            rows.append({
                "id": d.get("detection_id", "")[:16],
                "host": device.get("hostname", ""),
                "severity": str(d.get("max_severity_displayname", "")),
                "status": d.get("status", ""),
                "created": d.get("first_behavior", ""),
            })
    except cs.ClientFail as e:
        return ui.Alert(type="error", message=e.payload["error"])
    return ui.Stack(direction="v", gap=3, align="stretch", children=[
        ui.Header(text="Detections", level=2),
        ui.DataTable(
            rows=rows,
            columns=[
                ui.DataColumn(key="id", label="ID"),
                ui.DataColumn(key="host", label="Хост"),
                ui.DataColumn(key="severity", label="Severity"),
                ui.DataColumn(key="status", label="Статус"),
                ui.DataColumn(key="created", label="Обнаружено"),
            ],
        ) if rows else ui.Empty(message="No detections found", icon="ShieldCheck"),
    ])


@ext.panel("crowdstrike_hosts", slot="center", title="Hosts", center_overlay=True)
async def crowdstrike_hosts(ctx, **kwargs) -> ui.UINode:
    connections = await _load_connections(ctx)
    if not connections:
        return ui.Empty(message="Nothing to show here", icon="Monitor")
    conn = connections[0]
    token = await _get_token(ctx, conn)
    try:
        ids_resp = await cs.api_get(ctx, conn["region"], token, "/devices/queries/devices/v1", params={"limit": 100})
        ids = ids_resp.get("resources", []) if isinstance(ids_resp, dict) else []
        rows = []
        if ids:
            details = await cs.api_post(ctx, conn["region"], token, "/devices/entities/devices/v2", json={"ids": ids})
            for d in details.get("resources", []) if isinstance(details, dict) else []:
                rows.append({
                    "hostname": d.get("hostname", ""),
                    "platform": d.get("platform_name", ""),
                    "os": d.get("os_version", ""),
                    "status": d.get("status", d.get("connection_status", "unknown")),
                    "last_seen": d.get("last_seen", ""),
                })
    except cs.ClientFail as e:
        return ui.Alert(type="error", message=e.payload["error"])
    return ui.Stack(direction="v", gap=3, align="stretch", children=[
        ui.Header(text="Hosts", level=2),
        ui.DataTable(
            rows=rows,
            columns=[
                ui.DataColumn(key="hostname", label="Хост"),
                ui.DataColumn(key="platform", label="Платформа"),
                ui.DataColumn(key="os", label="ОС"),
                ui.DataColumn(key="status", label="Статус"),
                ui.DataColumn(key="last_seen", label="Последний раз онлайн"),
            ],
        ) if rows else ui.Empty(message="No hosts found", icon="Monitor"),
    ])


@ext.panel("crowdstrike_iocs", slot="center", title="Custom IOCs", center_overlay=True)
async def crowdstrike_iocs(ctx, **kwargs) -> ui.UINode:
    connections = await _load_connections(ctx)
    if not connections:
        return ui.Empty(message="Nothing to show here", icon="Fingerprint")
    conn = connections[0]
    token = await _get_token(ctx, conn)
    try:
        resp = await cs.api_get(ctx, conn["region"], token, "/iocs/combined/indicator/v1", params={"limit": 100})
        items = resp.get("resources", []) if isinstance(resp, dict) else []
        rows = [{"type": i.get("type", ""), "value": i.get("value", ""), "action": i.get("action", ""), "description": i.get("description", "")} for i in items]
    except cs.ClientFail as e:
        return ui.Alert(type="error", message=e.payload["error"])
    return ui.Stack(direction="v", gap=3, align="stretch", children=[
        ui.Header(text="Custom IOCs", level=2),
        ui.DataTable(
            rows=rows,
            columns=[
                ui.DataColumn(key="type", label="Тип"),
                ui.DataColumn(key="value", label="Значение"),
                ui.DataColumn(key="action", label="Действие"),
                ui.DataColumn(key="description", label="Описание"),
            ],
        ) if rows else ui.Empty(message="No custom IOCs configured", icon="Fingerprint"),
    ])


@ext.panel("crowdstrike_policies", slot="center", title="Prevention Policies", center_overlay=True)
async def crowdstrike_policies(ctx, **kwargs) -> ui.UINode:
    connections = await _load_connections(ctx)
    if not connections:
        return ui.Empty(message="Nothing to show here", icon="ShieldHalf")
    conn = connections[0]
    token = await _get_token(ctx, conn)
    try:
        ids_resp = await cs.api_get(ctx, conn["region"], token, "/policy/queries/prevention/v1", params={"limit": 100})
        ids = ids_resp.get("resources", []) if isinstance(ids_resp, dict) else []
        rows = []
        if ids:
            details = await cs.api_post(ctx, conn["region"], token, "/policy/entities/prevention/v1", json={"ids": ids})
            for d in details.get("resources", []) if isinstance(details, dict) else []:
                rows.append({"name": d.get("name", ""), "platform": d.get("platform_name", ""), "enabled": "Да" if d.get("enabled") else "Нет"})
        rows.sort(key=lambda r: r["enabled"])  # disabled first, most operationally risky
    except cs.ClientFail as e:
        return ui.Alert(type="error", message=e.payload["error"])
    return ui.Stack(direction="v", gap=3, align="stretch", children=[
        ui.Header(text="Prevention Policies", level=2),
        ui.DataTable(
            rows=rows,
            columns=[
                ui.DataColumn(key="name", label="Название"),
                ui.DataColumn(key="platform", label="Платформа"),
                ui.DataColumn(key="enabled", label="Включена"),
            ],
        ) if rows else ui.Empty(message="No prevention policies found", icon="ShieldHalf"),
    ])


@ext.panel("crowdstrike_connect_help", slot="overlay", title="Как создать API Client?")
async def crowdstrike_connect_help(ctx, **kwargs) -> ui.UINode:
    return ui.Markdown(text=(
        "**Falcon Console > Support and resources > API Clients and Keys > "
        "Create API client**\n\n"
        "Рекомендуемые scope под функции этого приложения:\n"
        "- Hosts: **Read** (и Write для containment)\n"
        "- Detections: **Read/Write**\n"
        "- Incidents: **Read/Write**\n"
        "- IOC (Indicators): **Read/Write**\n"
        "- Prevention Policies: **Read/Write**\n"
        "- Real Time Response: **Read/Write**\n"
        "- Spotlight Vulnerabilities: **Read**\n\n"
        "Скопируйте `Client ID` и `Client Secret` сразу после создания -- "
        "secret показывается только один раз."
    ))
