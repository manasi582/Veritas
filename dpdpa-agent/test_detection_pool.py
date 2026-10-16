"""The detection worker pool: speed-up mechanics, back-pressure, recovery. Uses stand-in work, not the model."""
import asyncio
import os
import time

import pytest

from detection.pool import DetectionPool, PoolBusy, auto_worker_count, configured_queue_limit, configured_workers


def slow_detect(event, validators):
    """Runs in a worker: sleeps, then reports which process did it."""
    time.sleep(event.get("sleep", 0.2))
    return {"pid": os.getpid(), "n": event.get("n"), "validators": validators}


def crash_detect(event, validators):
    os._exit(1)            # the worker dies without answering


def make(workers, queue=5, target=slow_detect):
    return DetectionPool(workers, queue, target=target, initializer=None, warm=None)


def test_auto_picks_nothing_on_a_small_machine_and_caps_on_a_big_one():
    assert auto_worker_count(cores=1, memory_gb=4) == 0
    assert auto_worker_count(cores=2, memory_gb=8) == 0           # one spare core is not worth a process
    assert auto_worker_count(cores=4, memory_gb=16) == 3
    assert auto_worker_count(cores=32, memory_gb=256) == 4        # capped
    assert auto_worker_count(cores=8, memory_gb=6) == 2           # memory-limited: (6-2.5)/1.3
    assert auto_worker_count(cores=8, memory_gb=4) == 0


def test_settings(monkeypatch):
    monkeypatch.setenv("VERITAS_DETECTION_WORKERS", "3")
    assert configured_workers() == 3
    monkeypatch.setenv("VERITAS_DETECTION_WORKERS", "0")
    assert configured_workers() == 0
    monkeypatch.setenv("VERITAS_DETECTION_WORKERS", "-5")
    assert configured_workers() == 0
    monkeypatch.setenv("VERITAS_DETECTION_WORKERS", "lots")
    assert configured_workers() == auto_worker_count()
    monkeypatch.setenv("VERITAS_DETECTION_QUEUE", "7")
    assert configured_queue_limit(4) == 7
    monkeypatch.delenv("VERITAS_DETECTION_QUEUE")
    assert configured_queue_limit(4) == 200 and configured_queue_limit(0) == 50


def test_work_is_spread_over_separate_processes_and_runs_in_parallel():
    pool = make(3, queue=20)

    async def run():
        t0 = time.perf_counter()
        out = await asyncio.gather(*[pool.detect({"n": i, "sleep": 0.5}, {"f": "v"}) for i in range(6)])
        return out, time.perf_counter() - t0

    try:
        out, elapsed = asyncio.run(run())
    finally:
        pool.shutdown()
    assert len({o["pid"] for o in out}) == 3 and os.getpid() not in {o["pid"] for o in out}
    assert all(o["validators"] == {"f": "v"} for o in out)
    assert elapsed < 2.5, f"6 half-second jobs on 3 workers took {elapsed:.1f}s (serial would be 3s plus start-up)"
    assert pool.stats()["completed"] == 6 and pool.stats()["rejected"] == 0


def test_thread_mode_runs_in_this_process():
    pool = make(0)
    try:
        out = asyncio.run(pool.detect({"n": 1, "sleep": 0}, None))
    finally:
        pool.shutdown()
    assert out["pid"] == os.getpid() and pool.mode == "thread"


def test_too_many_waiting_events_are_refused_not_queued_forever():
    pool = make(0, queue=3)               # one running plus three waiting = four in all

    async def run():
        jobs = [asyncio.ensure_future(pool.detect({"n": i, "sleep": 0.3}, None)) for i in range(4)]
        await asyncio.sleep(0.05)
        with pytest.raises(PoolBusy):
            await pool.detect({"n": 99}, None)
        return await asyncio.gather(*jobs)

    try:
        done = asyncio.run(run())
    finally:
        pool.shutdown()
    assert [d["n"] for d in done] == [0, 1, 2, 3]                  # none of the accepted ones was lost
    assert pool.stats()["rejected"] == 1 and pool.stats()["in_flight"] == 0


def test_the_event_loop_stays_free_while_detection_runs():
    pool = make(0)

    async def run():
        job = asyncio.ensure_future(pool.detect({"n": 1, "sleep": 0.6}, None))
        ticks = 0
        t0 = time.perf_counter()
        while not job.done():
            await asyncio.sleep(0.02)
            ticks += 1
        return ticks, time.perf_counter() - t0

    try:
        ticks, elapsed = asyncio.run(run())
    finally:
        pool.shutdown()
    assert ticks > 10, "the loop was blocked while detection ran"


def test_a_worker_that_dies_is_replaced_and_the_event_is_not_lost():
    pool = make(2, target=crash_detect)

    async def run():
        # first attempt kills a worker; the pool restarts, the retry (still the crashing target) fails the second time
        with pytest.raises(Exception):
            await pool.detect({"n": 1}, None)
        pool._target = slow_detect                                   # the cause is gone
        return await pool.detect({"n": 2, "sleep": 0}, None)

    try:
        out = asyncio.run(run())
    finally:
        pool.shutdown()
    assert out["n"] == 2 and pool.stats()["restarts"] >= 1 and pool.stats()["in_flight"] == 0
