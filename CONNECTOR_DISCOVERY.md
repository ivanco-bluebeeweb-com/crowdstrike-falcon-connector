# CrowdStrike Falcon Connector — Connector Discovery

**Discovery date:** 2026-08-24
**Release scope:** maximum functionality against the publicly documented Falcon
platform APIs (per standing "максимальный функционал" instruction).
**Related task:** BBW Imperal Apps #2509.

## 1. What CrowdStrike Falcon actually is

CrowdStrike Falcon is a cloud-native EDR/XDR platform: a lightweight sensor on
each endpoint streams telemetry to the CrowdStrike cloud, which runs behavioral
detection, generates **Detections** (sensor-level events) and **Incidents**
(correlated groupings of related detections), lets analysts respond in real
time (isolate a host, kill a process, run RTR commands), and manages fleet-wide
**Prevention Policies** and **IOCs** (custom indicators of compromise).

Falcon exposes almost all of this through **Falcon APIs** — a single OAuth2
REST surface organized into "Service Collections" (each collection = one
functional area, e.g. Hosts, Detects, Incidents, IOC, Prevention Policy, Real
Time Response, Spotlight Vulnerabilities).

## 2. Chosen integration surface

**Falcon APIs (OAuth2 REST)**, organized as service collections:

- **OAuth2** (`/oauth2/token`) — client-credentials token exchange.
- **Hosts** (`/devices/*`) — list/get sensors (endpoints), hide/unhide a host,
  host group management.
- **Detects** (`/detects/*`) — list/get Detections (sensor-visibility events,
  legacy but still the primary alert stream for many tenants), update status
  (new/in_progress/true_positive/false_positive/ignored), assign to a user.
- **Alerts** (`/alerts/*`, newer unified alert API — supersedes Detects for
  newer tenants) — list/get, update status, assign.
- **Incidents** (`/incidents/*`) — list/get correlated incidents (CrowdScore
  severity), update status, add tags/comments.
- **IOC / Custom Indicators** (`/iocs/*`) — create/list/update/delete custom
  IOCs (hash, domain, IP) with an action (detect/prevent/allow).
- **Prevention Policies** (`/policy/*`) — list/get prevention policies,
  toggle enabled state, list/set host-group assignment.
- **Real Time Response (RTR)** (`/real-time-response/*`) — start a session on
  a host, run a read-only or active-responder command, get command output,
  end session (all gated behind explicit confirmation — this is live remote
  execution on the user's endpoint).
- **Spotlight Vulnerabilities** (`/spotlight/*`) — list vulnerabilities found
  on hosts by CVE/severity, useful as a value-add "top exposure" report.
- **Sensor Download** (`/sensors/*`) — list available sensor installer
  versions/platforms (read-only, useful for a "deploy sensor" instructional
  flow, not itself capable of pushing an install).
- **User/Roles** (`/user-management/*`) — list Falcon console users, useful
  for assignment dropdowns.

Not in scope for v1 (Tier 2/future): Falcon Fusion SOAR workflow authoring,
Falcon Discover (asset/app inventory beyond hosts), Falcon Cloud Security
(CSPM), Falcon Intelligence (threat intel feeds) — each is effectively a
separate product module with its own API surface and would deserve its own
discovery pass.

## 3. Auth model

**OAuth2 Client Credentials.** User creates an API Client in Falcon Console
(Support and resources > API Clients and Keys) with scoped read/write
permissions per collection they want to use, and pastes `client_id` +
`client_secret` + selected **cloud region** into Imperal.

- Region is NOT auto-detected — CrowdStrike runs fully separate cloud
  environments with distinct base URLs:
  - `api.crowdstrike.com` (US-1)
  - `api.us-2.crowdstrike.com` (US-2)
  - `api.eu-1.crowdstrike.com` (EU-1)
  - `api.laggar.gcw.crowdstrike.com` (US-GOV-1, FedRAMP)
  Wrong region = confusing 401 with no useful message from CrowdStrike itself.
  This connector's connect form makes the region an explicit required Select,
  not a guess.
- Token lifetime is short (~30 min per CrowdStrike docs) — this connector
  proactively refreshes ahead of expiry rather than waiting for a 401, same
  pattern as other OAuth2 client-credentials connectors in the portfolio
  (Okta OAuth2 Service App mode, ServiceNow OAuth2 mode).
- Every API Client's scopes are set at creation time in the Falcon Console —
  a client scoped read-only on Incidents will get a clean 403 on any
  incident-write call; the connector surfaces CrowdStrike's own error detail
  rather than a generic "unauthorized".

## 4. Safety notes (see APP_SAFETY_CHECKLIST.md)

- `contain_host` / `lift_containment` (network isolation) instantly cuts a
  live endpoint off the network except for the Falcon channel — destructive-
  adjacent, requires explicit confirmation copy naming the host.
- `run_rtr_command` with an active-responder command can delete files, kill
  processes, or modify the registry on a live production endpoint — always
  behind explicit confirmation, and read-only RTR commands (ls, ps, netstat)
  are surfaced as the safe/default path in the UI.
- `create_ioc` with `action=prevent` can start blocking a hash/domain/IP
  fleet-wide the moment it's saved — confirmation copy states the blast
  radius (affects every host in policy scope, not just one).
- `update_prevention_policy` (disabling a prevention policy) is a fleet-wide
  security posture change — explicit confirmation required.

## 5. Value-add reports (beyond raw API passthrough)

- `audit_falcon_estate` — aggregated health snapshot: hosts not seen in N
  days (stale sensors), open critical/high incidents, prevention policies
  disabled, top CVEs by host count from Spotlight.
- `get_containment_status_report` — currently-isolated hosts, so an admin
  can see at a glance what's cut off from network right now.
