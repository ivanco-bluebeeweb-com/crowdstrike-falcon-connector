"""CrowdStrike Falcon Connector extension declaration.

CrowdStrike Falcon is a cloud-native EDR/XDR platform. This connector talks
to the Falcon APIs (OAuth2 REST, organized into service collections: Hosts,
Detects, Alerts, Incidents, IOC, Prevention Policy, Real Time Response,
Spotlight Vulnerabilities) documented at falconpy.io / developer.crowdstrike.com.

WHY BYOK (bring-your-own OAuth2 API Client) -- same reasoning as Okta
Connector / PagerDuty Connector. Falcon is the user's OWN security tenant --
Imperal cannot broker access to someone else's EDR estate centrally. The
user creates their own API Client in Falcon Console (scoped to only the
collections they want to use) and pastes client_id/client_secret once,
Vault-encrypted via ctx.secrets.

WHY A REGION FIELD IS MANDATORY -- CrowdStrike runs separate cloud regions
(US-1, US-2, EU-1, US-GOV-1) with different base URLs. There is no way to
auto-detect a tenant's region from the client_id alone, so it is a required
field of connect_crowdstrike, not an afterthought.
"""
from __future__ import annotations

from imperal_sdk import ChatExtension, Extension

ext = Extension(
    "crowdstrike-falcon-connector",
    version="0.1.0",
    display_name="CrowdStrike Falcon",
    description=(
        "Connect your own CrowdStrike Falcon tenant (OAuth2 API Client) to "
        "manage Hosts, Detections, Alerts, Incidents, custom IOCs, Prevention "
        "Policies, and Real Time Response sessions across your endpoint fleet."
    ),
    icon="icon.svg",
    capabilities=["crowdstrike:read", "crowdstrike:write"],
    actions_explicit=True,
    system=False,
)

chat = ChatExtension(
    ext,
    tool_name="crowdstrike_falcon",
    description=(
        "CrowdStrike Falcon Connector -- manage Hosts, Detections, Alerts, "
        "Incidents, IOCs, Prevention Policies, and Real Time Response for a "
        "connected Falcon tenant."
    ),
)

ext.secret(
    "crowdstrike_connections",
    "JSON list of connected CrowdStrike Falcon tenants (region + encrypted OAuth2 client credentials). Managed only through connect_crowdstrike and disconnect_crowdstrike.",
    required=True,
    write_mode="both",
    max_bytes=65536,
    rotation_hint_days=90,
)(lambda: None)


@ext.health_check
async def health_check(ctx) -> dict:
    """Report whether at least one Falcon tenant connection is saved."""
    import json

    raw = await ctx.secrets.get("crowdstrike_connections")
    connections = []
    if raw:
        try:
            connections = json.loads(raw)
        except (TypeError, ValueError):
            connections = []
    if not isinstance(connections, list) or not connections:
        return {"status": "not_connected", "detail": "No CrowdStrike Falcon tenant connected yet."}
    return {"status": "ok", "detail": f"{len(connections)} Falcon tenant(s) connected."}
