// Cached permission snapshot for ONE service, kept current by ETag
// revalidation and by polling the change feed. Rules come from the snapshot
// body itself (docs/control-plane.md "Snapshot and caching rules"):
//   - fresh for ttl_seconds, then revalidate with If-None-Match (304 = unchanged);
//   - platform unreachable: the cached copy may still answer READ checks for
//     at most stale_read_ttl_seconds, then nothing may be answered from it.

const { PlatformUnavailable } = require('./platform-client');

const RETRY_AFTER_FAILURE_MS = 1000;

class SnapshotCache {
  constructor({ client, service, ttlSeconds, staleReadTtlSeconds, now, pollIntervalSeconds, logger }) {
    // `now` here is the MONOTONIC clock: only ages are measured with it.
    this.client = client;
    this.service = service;
    this.defaultTtl = ttlSeconds;
    this.defaultStale = staleReadTtlSeconds;
    this.now = now;
    this.pollIntervalSeconds = pollIntervalSeconds;
    this.logger = logger;
    this.entry = null; // { body, etag, fetchedAt }
    this.cursor = 0;
    this._inflight = null;
    this._timer = null;
    this._failedAt = null;
  }

  _ttlMs() {
    return (this.entry?.body?.ttl_seconds ?? this.defaultTtl) * 1000;
  }

  _staleMs() {
    return (this.entry?.body?.stale_read_ttl_seconds ?? this.defaultStale) * 1000;
  }

  // -> { state: 'fresh' | 'stale' | 'none', snapshot?, ageSeconds? }
  //   fresh: inside the TTL (or just revalidated)
  //   stale: past the TTL, platform unreachable, still inside the stale-read window
  //   none:  nothing usable (never loaded, or older than the stale-read window)
  async get() {
    if (this.entry && this.now() - this.entry.fetchedAt < this._ttlMs()) return this._view('fresh');
    // After a failed refresh, do not make every request wait out a timeout:
    // go straight to the stale/none answer for a moment.
    const backingOff = this._failedAt !== null && this.now() - this._failedAt < RETRY_AFTER_FAILURE_MS;
    if (!backingOff) {
      try {
        await this.refresh();
        this._failedAt = null;
        return this._view('fresh');
      } catch (err) {
        if (!(err instanceof PlatformUnavailable)) throw err;
        this._failedAt = this.now();
      }
    }
    if (this.entry && this.now() - this.entry.fetchedAt <= this._staleMs()) return this._view('stale');
    return { state: 'none' };
  }

  _view(state) {
    return {
      state,
      snapshot: this.entry.body,
      ageSeconds: Math.floor((this.now() - this.entry.fetchedAt) / 1000),
    };
  }

  // One refresh at a time; concurrent callers share it. `fresh` means "I know something changed
  // after any request already in flight started": wait for that one, then run another, so a
  // change is never lost by joining a request that was built before it.
  async refresh({ fresh = false } = {}) {
    if (this._inflight && fresh) {
      try {
        await this._inflight;
      } catch {
        /* the next one decides */
      }
    }
    if (!this._inflight) {
      this._inflight = this._refresh().finally(() => {
        this._inflight = null;
      });
    }
    return this._inflight;
  }

  async _refresh() {
    const res = await this.client.snapshot(this.service, this.entry?.etag);
    if (res.notModified && this.entry) {
      this.entry.fetchedAt = this.now();
      return;
    }
    if (res.notModified) throw new PlatformUnavailable('304 without a cached snapshot');
    this.entry = { body: res.body, etag: res.etag, fetchedAt: this.now() };
    // Events the snapshot already reflects are harmless to re-see, so start the
    // cursor at the snapshot's own version.
    this.cursor = Math.max(this.cursor, res.body.version || 0);
  }

  // Ask the change feed whether anything happened since the snapshot; if so,
  // refetch now instead of waiting out the TTL. Returns true when it refreshed.
  async pollOnce() {
    const feed = await this.client.events(this.cursor);
    if (feed.events?.length) {
      // Advance the cursor only once the refresh succeeded: if it fails, the next
      // poll sees the same events again instead of the change being lost until the TTL.
      await this.refresh({ fresh: true });
      this.cursor = Math.max(this.cursor, feed.next_cursor);
      return true;
    }
    return false;
  }

  invalidate() {
    if (this.entry) this.entry.fetchedAt = 0;
  }

  startPolling() {
    if (this._timer || !this.pollIntervalSeconds) return;
    this._timer = setInterval(() => {
      this.pollOnce().catch((err) => this.logger.warn(`change-feed poll failed: ${err.message}`));
    }, this.pollIntervalSeconds * 1000);
    this._timer.unref?.();
  }

  stop() {
    if (this._timer) clearInterval(this._timer);
    this._timer = null;
  }
}

module.exports = { SnapshotCache };
