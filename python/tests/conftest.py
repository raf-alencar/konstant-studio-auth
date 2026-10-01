import sys
from pathlib import Path

import pytest

# Make `import konstant_studio_auth` work without installing the package.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from world import VECTORS, ClerkKeys, FakePlatform, SilentLogger, World  # noqa: E402
from konstant_studio_auth.v2 import create_auth  # noqa: E402

JWKS_URL = "http://jwks.vectors.test/jwks.json"
CFG = VECTORS["config"]


@pytest.fixture(scope="session")
def clerk_keys():
    return ClerkKeys()


@pytest.fixture(scope="session")
def world():
    return World()


class Harness:
    """A create_auth() wired to a FakePlatform with a controllable clock."""

    def __init__(self, world, keys, **overrides):
        self.world = world
        self.clock = world.now_ms
        self.fake = FakePlatform(world, keys, JWKS_URL)
        opts = dict(
            service=CFG["service"],
            platform_url="http://platform.vectors.test",
            platform_key="stgs_fake-service-key-for-tests",
            clerk={"issuer": CFG["clerk"]["issuer"], "jwks_url": JWKS_URL, "authorized_parties": CFG["clerk"]["authorized_parties"]},
            snapshot={"ttl_seconds": CFG["snapshot_ttl_seconds"], "stale_read_ttl_seconds": CFG["stale_read_ttl_seconds"]},
            poll_interval_seconds=0,
            now=lambda: self.clock,
            transport=self.fake.transport,
            logger=SilentLogger(),
        )
        opts.update(overrides)
        self.auth = create_auth(**opts)

    def advance(self, seconds):
        self.clock += int(seconds * 1000)

    def now(self):
        return self.clock


@pytest.fixture
def make_harness(world, clerk_keys):
    made = []

    def make(**overrides):
        h = Harness(world, clerk_keys, **overrides)
        made.append(h)
        return h

    yield make
