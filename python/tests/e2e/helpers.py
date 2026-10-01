"""Shared by the e2e tests: reads the state file written by scripts/scratch_platform.py (a scratch
copy of the C0b platform branch on a scratch database) and builds libraries and credentials
against it. Everything in it is fake and per-run.
"""

import json
import os
import subprocess
import time
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from konstant_studio_auth.v2 import create_auth
from world import VECTORS, ClerkKeys, SilentLogger, World, mint_clerk_token

STATE_PATH = Path(os.environ.get("SCRATCH_STATE") or Path(__file__).resolve().parents[3] / ".scratch" / "state-py.json")


def load_state():
    return json.loads(STATE_PATH.read_text()) if STATE_PATH.exists() else None


def make_context():
    state = load_state()
    if state is None:
        msg = f"no scratch platform running (state file {STATE_PATH} absent; scripts/scratch_platform.py start)"
        if os.environ.get("REQUIRE_SCRATCH") == "1":
            pytest.fail("REQUIRE_SCRATCH=1 but " + msg)
        pytest.skip(msg)
    world = World(include_transient=False)
    world.now_ms = int(time.time() * 1000)  # the platform evaluates windows and expiries against its own clock
    keys = SimpleNamespace(
        trusted=SimpleNamespace(kid=state["clerk_kid"], pem=state["clerk_private_key_pem"]), foreign=ClerkKeys().foreign
    )
    return SimpleNamespace(state=state, world=world, keys=keys)


def library_for(ctx, **extra):
    st = ctx.state
    opts = dict(
        service=VECTORS["config"]["service"], platform_url=st["platform_url"], platform_key=st["service_key"],
        clerk={"issuer": st["issuer"], "jwks_url": st["jwks_url"], "authorized_parties": [st["authorized_party"]]},
        poll_interval_seconds=0, logger=SilentLogger(),
    )
    opts.update(extra)
    return create_auth(**opts)


def platform_authorize(ctx, body):
    """What the platform itself says, asked directly with the shared scratch key."""
    r = httpx.post(f"{ctx.state['platform_url']}/v1/authorize", headers={"X-API-Key": ctx.state["shared_key"]}, json=body, timeout=10)
    return r.status_code, r.json()


def token_for(ctx, ref, spec=None):
    return mint_clerk_token(ctx.keys, ctx.world.principal(ref)["user_id"], int(time.time() * 1000), ctx.state["issuer"], ctx.state["authorized_party"], spec)


def bearer(ctx, ref, spec=None):
    return {"authorization": f"Bearer {token_for(ctx, ref, spec)}"}


def psql(ctx, sql):
    return subprocess.run(
        ["psql", ctx.state["database_url"], "-v", "ON_ERROR_STOP=1", "-qAt", "-c", sql], check=True, capture_output=True, text=True
    ).stdout
