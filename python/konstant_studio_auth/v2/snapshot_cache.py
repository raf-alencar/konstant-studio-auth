"""Cached permission snapshot for ONE service, kept current by ETag
revalidation and by polling the change feed. Rules come from the snapshot
body itself (docs/control-plane.md "Snapshot and caching rules"):
  - fresh for ttl_seconds, then revalidate with If-None-Match (304 = unchanged);
  - platform unreachable: the cached copy may still answer READ checks for
    at most stale_read_ttl_seconds, then nothing may be answered from it.
"""

import asyncio

from .platform_client import PlatformUnavailable

RETRY_AFTER_FAILURE_MS = 1000


class SnapshotView:
    __slots__ = ("state", "snapshot", "age_seconds")

    def __init__(self, state, snapshot=None, age_seconds=None):
        self.state = state
        self.snapshot = snapshot
        self.age_seconds = age_seconds


class _Entry:
    __slots__ = ("body", "etag", "fetched_at")

    def __init__(self, body, etag, fetched_at):
        self.body = body
        self.etag = etag
        self.fetched_at = fetched_at


class SnapshotCache:
    def __init__(self, client, service, ttl_seconds, stale_read_ttl_seconds, now, poll_interval_seconds, logger):
        self.client = client
        self.service = service
        self.default_ttl = ttl_seconds
        self.default_stale = stale_read_ttl_seconds
        self.now = now  # the MONOTONIC clock: only ages are measured with it
        self.poll_interval_seconds = poll_interval_seconds
        self.logger = logger
        self.entry = None
        self.cursor = 0
        self._inflight = None
        self._task = None
        self._failed_at = None

    def _body_or_default(self, key, default):
        v = self.entry.body.get(key) if self.entry else None
        return default if v is None else v

    def _ttl_ms(self):
        return self._body_or_default("ttl_seconds", self.default_ttl) * 1000

    def _stale_ms(self):
        return self._body_or_default("stale_read_ttl_seconds", self.default_stale) * 1000

    async def get(self):
        """-> SnapshotView with state 'fresh' | 'stale' | 'none'.

        fresh: inside the TTL (or just revalidated)
        stale: past the TTL, platform unreachable, still inside the stale-read window
        none:  nothing usable (never loaded, or older than the stale-read window)
        """
        if self.entry and self.now() - self.entry.fetched_at < self._ttl_ms():
            return self._view("fresh")
        # After a failed refresh, do not make every request wait out a timeout:
        # go straight to the stale/none answer for a moment.
        backing_off = self._failed_at is not None and self.now() - self._failed_at < RETRY_AFTER_FAILURE_MS
        if not backing_off:
            try:
                await self.refresh()
                self._failed_at = None
                return self._view("fresh")
            except PlatformUnavailable:
                self._failed_at = self.now()
        if self.entry and self.now() - self.entry.fetched_at <= self._stale_ms():
            return self._view("stale")
        return SnapshotView("none")

    def _view(self, state):
        return SnapshotView(state, self.entry.body, int((self.now() - self.entry.fetched_at) // 1000))

    async def refresh(self, fresh=False):
        """One refresh at a time; concurrent callers share it. `fresh` means "I know something changed
        after any request already in flight started": wait for that one, then run another, so a
        change is never lost by joining a request that was built before it."""
        if self._inflight is not None and fresh:
            try:
                await asyncio.shield(self._inflight)
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 - the next one decides
                pass
        if self._inflight is None:
            task = asyncio.ensure_future(self._refresh())
            self._inflight = task

            def _clear(t):
                if self._inflight is t:
                    self._inflight = None
                if not t.cancelled():
                    t.exception()  # mark retrieved even if every awaiter was cancelled

            task.add_done_callback(_clear)
        # shield: one caller timing out must not cancel the refresh the others share.
        return await asyncio.shield(self._inflight)

    async def _refresh(self):
        res = await self.client.snapshot(self.service, self.entry.etag if self.entry else None)
        if res.get("not_modified") and self.entry:
            self.entry.fetched_at = self.now()
            return
        if res.get("not_modified"):
            raise PlatformUnavailable("304 without a cached snapshot")
        self.entry = _Entry(res["body"], res["etag"], self.now())
        # Events the snapshot already reflects are harmless to re-see, so start the
        # cursor at the snapshot's own version.
        self.cursor = max(self.cursor, res["body"].get("version") or 0)

    async def poll_once(self):
        """Ask the change feed whether anything happened since the snapshot; if so,
        refetch now instead of waiting out the TTL. Returns True when it refreshed."""
        feed = await self.client.events(self.cursor)
        if feed.get("events"):
            # Move the cursor only once the refresh has succeeded: if it fails, the next poll
            # must see the same events again instead of losing them until the TTL runs out.
            await self.refresh(fresh=True)
            self.cursor = max(self.cursor, feed["next_cursor"])
            return True
        return False

    def invalidate(self):
        if self.entry:
            self.entry.fetched_at = 0

    def start_polling(self):
        if self._task or not self.poll_interval_seconds:
            return
        self._task = asyncio.ensure_future(self._poll_loop())

    async def _poll_loop(self):
        while True:
            await asyncio.sleep(self.poll_interval_seconds)
            try:
                await self.poll_once()
            except asyncio.CancelledError:
                raise
            except Exception as err:  # noqa: BLE001 - a failed poll must never kill the loop
                self.logger.warning(f"change-feed poll failed: {err}")

    def stop(self):
        if self._task:
            self._task.cancel()
        self._task = None
