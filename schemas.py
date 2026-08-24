"""Pydantic input contracts and SDL result entities for CrowdStrike Falcon Connector."""
from __future__ import annotations

from imperal_sdk import sdl
from pydantic import BaseModel, Field


class NoParams(BaseModel):
    pass


class ConnectionRefParams(BaseModel):
    connection_id: str = Field("", description="Optional saved Falcon tenant connection ID. Omit to use the first connected tenant.")


class ConnectCrowdstrikeParams(BaseModel):
    label: str = Field("", description="Friendly tenant label, e.g. 'Acme SOC'.")
    region: str = Field(..., description="Falcon cloud region: 'us-1', 'us-2', 'eu-1', or 'us-gov-1'.")
    client_id: str = Field(..., description="OAuth2 API Client ID from Falcon Console > Support and resources > API Clients and Keys.")
    client_secret: str = Field(..., description="OAuth2 API Client Secret.")


class DisconnectCrowdstrikeParams(ConnectionRefParams):
    connection_id: str = Field(..., description="Saved Falcon tenant connection ID to remove from Imperal.")


class ListHostsParams(ConnectionRefParams):
    filter_expr: str = Field("", description="Optional FQL filter, e.g. \"platform_name:'Windows'\".")
    limit: int = Field(50, description="Max hosts to return (1-500).")


class HostIdParams(ConnectionRefParams):
    host_id: str = Field(..., description="Falcon host (device/agent) id.")


class HostActionParams(ConnectionRefParams):
    host_ids: list[str] = Field(..., description="One or more Falcon host ids to act on.")


class ListDetectionsParams(ConnectionRefParams):
    filter_expr: str = Field("", description="Optional FQL filter, e.g. \"status:'new'\".")
    limit: int = Field(50, description="Max detections to return (1-500).")


class DetectionIdParams(ConnectionRefParams):
    detection_id: str = Field(..., description="Falcon detection id.")


class UpdateDetectionStatusParams(DetectionIdParams):
    status: str = Field(..., description="New status: 'new', 'in_progress', 'true_positive', 'false_positive', or 'ignored'.")
    comment: str = Field("", description="Optional analyst comment to attach.")
    assign_to_uuid: str = Field("", description="Optional Falcon user UUID to assign the detection to.")


class ListIncidentsParams(ConnectionRefParams):
    filter_expr: str = Field("", description="Optional FQL filter, e.g. \"state:'open'\".")
    limit: int = Field(50, description="Max incidents to return (1-500).")


class IncidentIdParams(ConnectionRefParams):
    incident_id: str = Field(..., description="Falcon incident id.")


class UpdateIncidentParams(IncidentIdParams):
    status: str = Field("", description="New status: 'new', 'in_progress', 'closed', 'reopened'.")
    add_tag: str = Field("", description="Optional tag to add.")
    add_comment: str = Field("", description="Optional comment to add.")


class ListIocsParams(ConnectionRefParams):
    types: str = Field("", description="Optional comma-separated IOC types filter, e.g. 'sha256,domain'.")
    limit: int = Field(50, description="Max IOCs to return (1-500).")


class CreateIocParams(ConnectionRefParams):
    ioc_type: str = Field(..., description="IOC type: 'sha256', 'md5', 'domain', 'ipv4', 'ipv6'.")
    value: str = Field(..., description="The indicator value itself (hash, domain, or IP).")
    action: str = Field("detect", description="Action Falcon takes when this IOC is observed: 'detect', 'prevent', or 'allow'.")
    description: str = Field("", description="Optional description of why this IOC was added.")
    platforms: list[str] = Field(default_factory=list, description="Platforms this IOC applies to, e.g. ['windows', 'mac', 'linux']. Empty = all.")


class IocIdParams(ConnectionRefParams):
    ioc_id: str = Field(..., description="Falcon custom IOC id.")


class ListPreventionPoliciesParams(ConnectionRefParams):
    pass


class PolicyIdParams(ConnectionRefParams):
    policy_id: str = Field(..., description="Falcon Prevention Policy id.")


class SetPreventionPolicyEnabledParams(PolicyIdParams):
    enabled: bool = Field(..., description="True to enable the Prevention Policy, False to disable it.")


class RtrSessionParams(ConnectionRefParams):
    host_id: str = Field(..., description="Falcon host id to start a Real Time Response session on.")


class RtrCommandParams(ConnectionRefParams):
    session_id: str = Field(..., description="Active RTR session id from start_rtr_session.")
    command: str = Field(..., description="RTR command to run, e.g. 'ls', 'ps', 'ipconfig'.")
    command_string: str = Field("", description="Full command string with arguments, e.g. 'ls C:\\\\Users'.")


class ListVulnerabilitiesParams(ConnectionRefParams):
    filter_expr: str = Field("", description="Optional FQL filter, e.g. \"cve.severity:'CRITICAL'\".")
    limit: int = Field(50, description="Max vulnerabilities to return (1-500).")


# ---- SDL entities ----

class CrowdstrikeConnection(sdl.Entity):
    connection_id: str
    label: str
    region: str
    client_id_masked: str


class ConnectionList(sdl.Entity):
    connections: list[CrowdstrikeConnection]


class FalconHost(sdl.Entity):
    host_id: str
    hostname: str
    platform_name: str
    os_version: str
    last_seen: str
    status: str


class HostList(sdl.Entity):
    hosts: list[FalconHost]


class FalconDetection(sdl.Entity):
    detection_id: str
    hostname: str
    severity: str
    status: str
    tactic: str
    technique: str
    created: str


class DetectionList(sdl.Entity):
    detections: list[FalconDetection]


class FalconIncident(sdl.Entity):
    incident_id: str
    state: str
    status: str
    fine_score: int
    hosts_count: int
    created: str


class IncidentList(sdl.Entity):
    incidents: list[FalconIncident]


class FalconIoc(sdl.Entity):
    ioc_id: str
    ioc_type: str
    value: str
    action: str
    description: str


class IocList(sdl.Entity):
    iocs: list[FalconIoc]


class PreventionPolicy(sdl.Entity):
    policy_id: str
    name: str
    enabled: bool
    platform_name: str


class PolicyList(sdl.Entity):
    policies: list[PreventionPolicy]


class RtrSession(sdl.Entity):
    session_id: str
    host_id: str
    status: str


class RtrCommandResult(sdl.Entity):
    session_id: str
    command: str
    stdout: str
    stderr: str


class Vulnerability(sdl.Entity):
    vuln_id: str
    cve_id: str
    severity: str
    hostname: str
    status: str


class VulnerabilityList(sdl.Entity):
    vulnerabilities: list[Vulnerability]


class EstateAudit(sdl.Entity):
    region: str
    total_hosts: int
    stale_hosts_7d: int
    open_incidents_critical: int
    open_detections_new: int
    disabled_prevention_policies: int
    notes: str


class DeleteResult(sdl.Entity):
    ok: bool
    detail: str
