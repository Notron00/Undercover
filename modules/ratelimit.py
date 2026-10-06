"""
In-memory rate limiting for login attempts.

Keyed by IP and by account; each value is [failure_count, first_failure_time].
Nothing is logged or persisted — state lives only in memory and clears on restart.
"""

import time
import threading

LOCKOUT_THRESHOLD = 5      # failed attempts before a temporary lock
LOCKOUT_SECONDS = 60       # how long a lock lasts

_lock = threading.Lock()


def is_locked(store, key):
    """Returns True if this key is currently in a lockout window."""
    with _lock:
        entry = store.get(key)
        if entry is None:
            return False
        count, first_ts = entry
        if count < LOCKOUT_THRESHOLD:
            return False
        if time.time() - first_ts >= LOCKOUT_SECONDS:
            del store[key]  # window passed, reset
            return False
        return True


def record_failure(store, key):
    """Records one failed attempt for this key."""
    with _lock:
        entry = store.get(key)
        now = time.time()
        if entry is None or (now - entry[1]) >= LOCKOUT_SECONDS:
            store[key] = [1, now]
        else:
            entry[0] += 1


def reset_failures(store, key):
    """Clears failures for this key (called on successful login)."""
    with _lock:
        store.pop(key, None)