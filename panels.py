"""CrowdStrike Falcon Connector panels.

SIDEBAR CONTENT -- NO CARDS ANYWHERE, per ~/UI_INTERFACE_STANDARD.md's "left
sidebar, no decorated cards" rule (same convention as Okta Connector's /
PagerDuty Connector's panels.py). Every section is a plain ui.Stack, stacked
vertically and left-aligned, no Card border/background/shadow. Disconnect
lives only in "App settings" (panels_settings.py). The one secondary "App
settings" button is always the LAST element at the bottom of the sidebar.

Per Vlad's standing rule: every input carries its own label (not just a
placeholder), placeholders are contextually specific, the form container is
stretched to the full width of the left sidebar with its contents stretched
to fill it, and the sidebar carries NO instructions that duplicate the "How
do I set this up?" modal.
"""
from __future__ import annotations

from imperal_sdk import ui

from app import ext
from handlers_connection import _load_connections


def _field(label: str, node: ui.UINode) -> ui.UINode:
    return ui.Stack(direction="v", gap=1, align="stretch", children=[
        ui.Text(label, variant="caption"),
        node,
    ])


def _settings_button() -> ui.UINode:
    return ui.Button(
        "App settings", variant="secondary", size="sm", full_width=True,
        icon="Settings", on_click=ui.Call("__panel__crowdstrike_settings"),
    )


@ext.panel("crowdstrike_sidebar", slot="left", title="CrowdStrike Falcon")
async def crowdstrike_sidebar(ctx, **kwargs) -> ui.UINode:
    connections = await _load_connections(ctx)
    if not connections:
        return ui.Stack(direction="v", gap=3, align="stretch", children=[
            ui.Button("Как создать API Client?", variant="ghost", size="sm", icon="HelpCircle",
                      on_click=ui.Call("__panel__crowdstrike_connect_help")),
            ui.Form(action="connect_crowdstrike", submit_label="Подключить", children=[
                _field("Регион облака", ui.Select(param_name="region", options=["us-1", "us-2", "eu-1", "us-gov-1"], value="us-1")),
                _field("Название тенанта", ui.Input(param_name="label", placeholder="Например: Acme SOC")),
                _field("Client ID", ui.Input(param_name="client_id", placeholder="OAuth2 API Client ID из Falcon Console")),
                _field("Client Secret", ui.Password(param_name="client_secret", placeholder="OAuth2 API Client Secret")),
            ]),
        ])
    c = connections[0]
    return ui.Stack(direction="v", gap=1, align="stretch", children=[
        ui.Text(f"{c.get('label') or c.get('region', '')}", variant="subtitle"),
        ui.Divider(),
        ui.Button("Incidents", variant="ghost", full_width=True, icon="ShieldAlert", on_click=ui.Call("__panel__crowdstrike_incidents")),
        ui.Button("Detections", variant="ghost", full_width=True, icon="Eye", on_click=ui.Call("__panel__crowdstrike_detections")),
        ui.Button("Hosts", variant="ghost", full_width=True, icon="Monitor", on_click=ui.Call("__panel__crowdstrike_hosts")),
        ui.Button("IOCs", variant="ghost", full_width=True, icon="Fingerprint", on_click=ui.Call("__panel__crowdstrike_iocs")),
        ui.Button("Prevention Policies", variant="ghost", full_width=True, icon="ShieldCheck", on_click=ui.Call("__panel__crowdstrike_policies")),
        ui.Button("Vulnerabilities", variant="ghost", full_width=True, icon="Bug", on_click=ui.Call("__panel__crowdstrike_vulns")),
        ui.Divider(),
        _settings_button(),
    ])


@ext.panel("crowdstrike_connect_help", slot="center", title="Подключение CrowdStrike Falcon", center_overlay=True)
async def crowdstrike_connect_help(ctx, **kwargs) -> ui.UINode:
    return ui.Stack(direction="v", gap=3, align="stretch", children=[
        ui.Header(text="Как создать OAuth2 API Client", level=2),
        ui.Markdown(text=(
            "1. В Falcon Console перейдите в **Support and resources > API Clients and Keys**.\n"
            "2. Нажмите **Add new API client**, дайте название.\n"
            "3. Отметьте нужные scope: `Hosts: Read/Write`, `Detections: Read/Write`, "
            "`Incidents: Read/Write`, `IOC: Read/Write`, `Prevention Policies: Read/Write`, "
            "`Real Time Response (Admin): Read/Write`, `Spotlight Vulnerabilities: Read`.\n"
            "4. Скопируйте **Client ID** и **Client Secret** (секрет показывается один раз).\n"
            "5. Убедитесь, что выбран правильный регион облака (US-1/US-2/EU-1/US-GOV-1) — "
            "он виден в адресной строке вашей Falcon Console."
        )),
    ])


@ext.panel("crowdstrike_center", slot="center", title="CrowdStrike Falcon")
async def crowdstrike_center(ctx, **kwargs) -> ui.UINode:
    return ui.Empty(message="Nothing to show here", icon="ShieldAlert")
