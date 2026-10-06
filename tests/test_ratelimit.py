import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from modules import ratelimit
from modules.ratelimit import is_locked, record_failure, reset_failures, LOCKOUT_THRESHOLD


def test_not_locked_initially():
    store = {}
    assert not is_locked(store, "1.2.3.4")


def test_locks_after_threshold():
    store = {}
    key = "1.2.3.4"
    # One below threshold: still unlocked
    for _ in range(LOCKOUT_THRESHOLD - 1):
        record_failure(store, key)
    assert not is_locked(store, key)
    # Hit the threshold: now locked
    record_failure(store, key)
    assert is_locked(store, key)


def test_reset_clears_lock():
    store = {}
    key = "1.2.3.4"
    for _ in range(LOCKOUT_THRESHOLD):
        record_failure(store, key)
    assert is_locked(store, key)
    reset_failures(store, key)
    assert not is_locked(store, key)


def test_different_keys_independent():
    store = {}
    for _ in range(LOCKOUT_THRESHOLD):
        record_failure(store, "1.1.1.1")
    assert is_locked(store, "1.1.1.1")
    assert not is_locked(store, "2.2.2.2")  # other key unaffected


def test_lock_expires(monkeypatch):
    """After the lockout window passes, the key unlocks automatically."""
    store = {}
    key = "1.2.3.4"
    for _ in range(LOCKOUT_THRESHOLD):
        record_failure(store, key)
    assert is_locked(store, key)

    # Fast-forward time past the lockout window (no real waiting)
    real_now = time.time()
    monkeypatch.setattr(ratelimit.time, "time",
                        lambda: real_now + ratelimit.LOCKOUT_SECONDS + 1)
    assert not is_locked(store, key)