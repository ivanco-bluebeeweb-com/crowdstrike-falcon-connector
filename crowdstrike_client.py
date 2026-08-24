"""CrowdStrike Falcon HTTP client -- OAuth2 client-credentials auth against a
user's own Falcon tenant, thin wrappers around the Falcon APIs (falconpy.io /
developer.crowdstrike.com), organized by service collection.

WHY OAUTH2 CLIENT CREDENTIALS, NOT A STATIC API KEY.

Falcon APIs authenticate every call with a short-lived Bearer token obtained
via POST /oauth2/token using a client_id/client_secret pair created in
Falcon Console > Support and resources > API Clients and Keys. The token
expires in ~30 minutes, so this client proactively re-authenticates when a
cached token is close to expiry, same principle as any OAuth2 client-
credentials connector in this portfolio (see AUTH_AND_CREDENTIALS_STANDARD.md).

WHY A REGION-KEYED BASE URL MAP.

CrowdStrike runs isolated cloud regions with different API hosts:
  US-1:      api.crowdstrike.com
  US-2:      api.us-2.crowdstrike.com
  EU-1:      api.eu-1.crowdstrike.com
  US-GOV-1:  api.laggar.gcw.crowdstrike.com
A client_id from one region will not authenticate against another region's
host -- this is the most common first-connect failure, so the region is a
required, explicit field rather than guessed.

WHY 401 vs 403 ARE HANDLED DIFFERENTLY.

A 401 means the OAuth2 token itself is invalid/expired. A 403 means the
token is valid but the underlying API Client lacks the specific scope
(e.g. Incidents: Write) needed for this call -- a fixable, more specific
cause (add the scope in Falcon Console) that must be reported distinctly
from "wrong credentials".
"""
from __future__ import annotations

import time

TOKEN_MISSING = "CS_TOKEN_MISSING"
AUTH_REJECTED = "CS_AUTH_REJECTED"
SCOPE_DENIED = "CS_SCOPE_DENIED"
NOT_FOUND = "CS_NOT_FOUND"
VALIDATION_FAILED = "CS_VALIDATION_FAILED"
RESPONSE_UNEXPECTED = "CS_RESPONSE_UNEXPECTED"
UNREACHABLE = "CS_UNREACHABLE"
RATE_LIMITED = "CS_RATE_LIMITED"
BACKEND_5XX = "CS_BACKEND_5XX"

_MESSAGES = {
    TOKEN_MISSING: "No CrowdStrike Falcon tenant is connected yet.",
    AUTH_REJECTED: "CrowdStrike rejected the Client ID/Secret for this region. Check the credentials and the selected cloud region, then reconnect.",
    SCOPE_DENIED: "CrowdStrike accepted the API Client, but it lacks the required scope for this operation. Add the missing scope to the API Client in Falcon Console > Support and resources > API Clients and Keys.",
    NOT_FOUND: "CrowdStrike has no such host/detection/incident/IOC, or this API Client cannot access it.",
    VALIDATION_FAILED: "CrowdStrike rejected the request as invalid.",
    RESPONSE_UNEXPECTED: "CrowdStrike returned a response the connector could not safely interpret.",
    UNREACHABLE: "Could not reach the CrowdStrike Falcon API for this region.",
    RATE_LIMITED: "CrowdStrike is rate-limiting requests; try again shortly.",
    BACKEND_5XX: "CrowdStrike returned a server error; try again shortly.",
}
_RETRYABLE = {RATE_LIMITED, BACKEND_5XX}

REGION_HOSTS = {
    "us-1": "api.crowdstrike.com",
    "us-2": "api.us-2.crowdstrike.com",
    "eu-1": "api.eu-1.crowdstrike.com",
    "us-gov-1": "api.laggar.gcw.crowdstrike.com",
}


def fail(code: str, detail: str = "") -> dict:
    message = _MESSAGES.get(code, code)
    if detail:
        message = f"{message} ({detail})"
    return {"ok": False, "error_code": code, "error": message, "retryable": code in _RETRYABLE}


class ClientFail(Exception):
    def __init__(self, payload: dict):
        super().__init__(payload.get("error", "CrowdStrike Falcon request failed"))
        self.payload = payload


def base_url(region: str) -> str:
    host = REGION_HOSTS.get((region or "us-1").lower(), REGION_HOSTS["us-1"])
    return f"https://{host}"


def _check_status(resp, action: str):
    if resp.status_code in (200, 201, 202, 204):
        return resp.body if isinstance(resp.body, (dict, list)) else {}
    if resp.status_code == 401:
        raise ClientFail(fail(AUTH_REJECTED, action))
    if resp.status_code == 403:
        raise ClientFail(fail(SCOPE_DENIED, action))
    if resp.status_code == 404:
        raise ClientFail(fail(NOT_FOUND, action))
    if resp.status_code == 429:
        raise ClientFail(fail(RATE_LIMITED, action))
    if resp.status_code >= 500:
        raise ClientFail(fail(BACKEND_5XX, action))
    if resp.status_code == 400:
        raise ClientFail(fail(VALIDATION_FAILED, action))
    raise ClientFail(fail(RESPONSE_UNEXPECTED, f"{action}: HTTP {resp.status_code}"))


async def get_token(ctx, region: str, client_id: str, client_secret: str) -> dict:
    """Exchange client_id/client_secret for a short-lived OAuth2 token.
    Called both by connect_crowdstrike (to validate before saving) and by
    _authed_headers (to refresh a stale token before each batch of calls)."""
    resp = await ctx.http.post(
        f"{base_url(region)}/oauth2/token",
        headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
        data={"client_id": client_id, "client_secret": client_secret},
    )
    if resp.status_code != 201 and resp.status_code != 200:
        if resp.status_code in (400, 401, 403):
            raise ClientFail(fail(AUTH_REJECTED, "token exchange"))
        raise ClientFail(fail(RESPONSE_UNEXPECTED, f"token exchange: HTTP {resp.status_code}"))
    body = resp.body if isinstance(resp.body, dict) else {}
    token = body.get("access_token", "")
    if not token:
        raise ClientFail(fail(AUTH_REJECTED, "no access_token in response"))
    expires_in = int(body.get("expires_in", 1740) or 1740)
    return {"access_token": token, "expires_at": time.time() + expires_in - 60}


def _headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}", "Accept": "application/json", "Content-Type": "application/json"}


async def api_get(ctx, region: str, token: str, path: str, *, params: dict | None = None):
    resp = await ctx.http.get(f"{base_url(region)}{path}", headers=_headers(token), params=params or {})
    return _check_status(resp, f"GET {path}")


async def api_post(ctx, region: str, token: str, path: str, *, json: dict | None = None):
    resp = await ctx.http.post(f"{base_url(region)}{path}", headers=_headers(token), json=json or {})
    return _check_status(resp, f"POST {path}")


async def api_patch(ctx, region: str, token: str, path: str, *, json: dict | None = None):
    resp = await ctx.http.patch(f"{base_url(region)}{path}", headers=_headers(token), json=json or {})
    return _check_status(resp, f"PATCH {path}")


async def api_delete(ctx, region: str, token: str, path: str, *, params: dict | None = None):
    resp = await ctx.http.delete(f"{base_url(region)}{path}", headers=_headers(token), params=params or {})
    return _check_status(resp, f"DELETE {path}")
