"""CrowdStrike Falcon Connector entrypoint."""
from __future__ import annotations

import handlers_connection  # noqa: F401
import handlers_hosts  # noqa: F401
import handlers_alerts  # noqa: F401
import handlers_iocs_policies  # noqa: F401
import handlers_rtr_audit  # noqa: F401
import panels  # noqa: F401
import panels_center  # noqa: F401
import panels_settings  # noqa: F401
from app import ext

extension = ext
