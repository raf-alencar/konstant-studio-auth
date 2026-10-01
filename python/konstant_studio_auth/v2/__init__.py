"""konstant_studio_auth.v2 -- control-plane auth. Import explicitly:
`from konstant_studio_auth.v2 import create_auth`. The v1 modules in the package root are
unchanged and this subpackage is never imported by them, so adopters without v2's
needs are unaffected.
"""

from .adapters.fastapi import fastapi_adapter
from .auth import Auth, Principal, Result, parse_permission
from .config import ConfigError
from .events_webhook import verify_signature
from .service_keys import route_allowed


def create_auth(**opts):
    core = Auth(**opts)
    core.fastapi = fastapi_adapter(core)
    core.require_permission = core.fastapi.require_permission
    core.require_approver = core.fastapi.require_approver
    core.require_service_caller = core.fastapi.require_service_caller
    core.events_webhook = core.fastapi.events_webhook
    return core


__all__ = ["create_auth", "Principal", "Result", "ConfigError", "parse_permission", "route_allowed", "verify_signature"]
