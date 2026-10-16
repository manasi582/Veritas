"""
Detection worker pool.

Finding personal data in a line (the language-model step) is the expensive part of handling an event,
and Python runs it on one core at a time. This module runs it in several worker PROCESSES, so a server
with more cores takes more events per second, and so that a busy moment does not freeze the rest of
the API (the web server's event loop only waits; it does not compute).

  VERITAS_DETECTION_WORKERS   number of worker processes. "auto" (default) picks from the cores and
                              the memory of this machine; 0 runs detection in one background thread
                              of the main process (the original behaviour, with the same queue limit).
  VERITAS_DETECTION_QUEUE     how many events may wait for a free worker before new ones are refused
                              with "busy, retry" (default: 50 per worker, at least 50).

A refused event is not lost: the agent keeps it and retries (HTTP 503 with Retry-After). What is
bounded is how long anyone waits, and how much memory waiting events can take.

Each worker holds its own copy of the language model (about 1 GB), which is why "auto" is cautious.
Workers never read the organization settings: the main process hands them what they need with each
event, so a policy change takes effect at once.
"""
from __future__ import annotations

import asyncio
import logging
import multiprocessing
import os
import sys
import threading
import time
from concurrent.futures import BrokenExecutor, Executor, ProcessPoolExecutor, ThreadPoolExecutor
from typing import Callable, Dict, Optional

logger = logging.getLogger("detection.pool")

APPROX_WORKER_GB = 1.3        # language model + analyzer in one worker process
RESERVED_GB = 2.5             # the main server, the operating system
MAX_AUTO_WORKERS = 4
QUEUE_PER_WORKER = 50
RETRY_AFTER_SECONDS = 1


class PoolBusy(Exception):
    """Too many events are already waiting. The caller should answer 503 with Retry-After."""


def physical_memory_gb() -> Optional[float]:
    try:
        if hasattr(os, "sysconf") and "SC_PHYS_PAGES" in os.sysconf_names:
            return os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES") / 1e9
        if sys.platform == "win32":
            import ctypes

            class _Mem(ctypes.Structure):
                _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                            ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                            ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                            ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                            ("sullAvailExtendedVirtual", ctypes.c_ulonglong)]
            m = _Mem(); m.dwLength = ctypes.sizeof(m)
            ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(m))
            return m.ullTotalPhys / 1e9
    except Exception:
        pass
    return None


def auto_worker_count(cores: Optional[int] = None, memory_gb: Optional[float] = None) -> int:
    """
    One worker per spare core, as many as the memory allows, at most 4. Fewer than 2 would only
    move the work to another process without making it faster, so that becomes 0 (a thread).
    """
    cores = cores if cores is not None else (os.cpu_count() or 1)
    memory_gb = memory_gb if memory_gb is not None else physical_memory_gb()
    n = min(cores - 1, MAX_AUTO_WORKERS)
    if memory_gb is not None:
        n = min(n, int((memory_gb - RESERVED_GB) / APPROX_WORKER_GB))
    return n if n >= 2 else 0


def configured_workers() -> int:
    raw = os.environ.get("VERITAS_DETECTION_WORKERS", "").strip().lower()
    if raw in ("", "auto"):
        return auto_worker_count()
    try:
        return max(0, min(64, int(raw)))
    except ValueError:
        logger.warning("VERITAS_DETECTION_WORKERS=%r is not a number or 'auto'; using auto", raw)
        return auto_worker_count()


def configured_queue_limit(workers: int) -> int:
    default = max(QUEUE_PER_WORKER, QUEUE_PER_WORKER * max(workers, 1))
    raw = os.environ.get("VERITAS_DETECTION_QUEUE", "").strip()
    try:
        return max(1, int(raw)) if raw else default
    except ValueError:
        return default


# ---------------------------------------------------------------- what runs inside a worker

def _init_worker() -> None:
    """Load the language model once per worker, before the first event arrives."""
    from detection.analyzer_engine import get_analyzer_engine
    get_analyzer_engine()


def worker_detect(event, validators):
    """Runs in a worker process (or the thread): the detection of one event."""
    from detection.engine import detect_event
    return detect_event(event, validators=validators)


def _warm(_=None) -> int:
    from detection.analyzer_engine import analyze_text
    analyze_text("Warm-up line for Rahul Sharma, phone +91 98765 43210")
    return os.getpid()


# ---------------------------------------------------------------- the pool

class DetectionPool:
    def __init__(self, workers: int, queue_limit: int, target: Callable = worker_detect,
                 initializer: Optional[Callable] = _init_worker, warm: Optional[Callable] = _warm):
        self.workers = workers
        self.queue_limit = queue_limit
        self._target = target
        self._initializer = initializer
        self._warm = warm
        self._executor: Optional[Executor] = None
        self._lock = threading.Lock()
        self._in_flight = 0
        self.completed = 0
        self.rejected = 0
        self.restarts = 0
        self.ready_workers = 0
        self.started_at: Optional[float] = None

    # -- lifecycle
    @property
    def mode(self) -> str:
        return "pool" if self.workers > 0 else "thread"

    def _make_executor(self) -> Executor:
        if self.workers > 0:
            ctx = multiprocessing.get_context("spawn")        # no fork from a running web server
            return ProcessPoolExecutor(max_workers=self.workers, mp_context=ctx, initializer=self._initializer)
        return ThreadPoolExecutor(max_workers=1, thread_name_prefix="veritas-detect")

    def start(self) -> None:
        with self._lock:
            if self._executor is None:
                self._executor = self._make_executor()
                self.started_at = time.time()
        if self._warm is not None:
            threading.Thread(target=self._warm_up, name="veritas-detect-warmup", daemon=True).start()

    def _warm_up(self) -> None:
        """Start every worker and let it load the model, without making a real event wait for that."""
        try:
            n = max(self.workers, 1)
            futures = [self._executor.submit(self._warm, i) for i in range(n)]
            pids = {f.result(timeout=600) for f in futures}
            self.ready_workers = len(pids) if self.workers > 0 else 1
            logger.info("Detection ready: %s", f"{self.workers} worker processes" if self.workers else "one background thread")
        except Exception as e:
            logger.warning("Detection warm-up did not finish: %s", e)

    def shutdown(self) -> None:
        with self._lock:
            ex, self._executor = self._executor, None
        if ex is not None:
            ex.shutdown(wait=False, cancel_futures=True)

    def _restart(self) -> None:
        with self._lock:
            old, self._executor = self._executor, self._make_executor()
            self.restarts += 1
        logger.error("A detection worker died; the pool was restarted (restart %d)", self.restarts)
        if old is not None:
            try:
                old.shutdown(wait=False, cancel_futures=True)
            except Exception:
                pass

    # -- the one call
    async def detect(self, event, validators):
        if self._executor is None:
            self.start()
        with self._lock:
            if self._in_flight >= (self.workers or 1) + self.queue_limit:      # running plus waiting
                self.rejected += 1
                raise PoolBusy()
            self._in_flight += 1
        try:
            loop = asyncio.get_running_loop()
            for attempt in (1, 2):
                try:
                    result = await loop.run_in_executor(self._executor, self._target, event, validators)
                    self.completed += 1
                    return result
                except BrokenExecutor:
                    if attempt == 2:
                        raise
                    self._restart()
        finally:
            with self._lock:
                self._in_flight -= 1

    def stats(self) -> Dict[str, object]:
        return {"mode": self.mode, "workers": self.workers, "ready_workers": self.ready_workers,
                "in_flight": self._in_flight, "queue_limit": self.queue_limit,
                "completed": self.completed, "rejected": self.rejected, "restarts": self.restarts}


# ---------------------------------------------------------------- the server's one pool

_pool: Optional[DetectionPool] = None
_pool_lock = threading.Lock()


def get_pool() -> DetectionPool:
    global _pool
    with _pool_lock:
        if _pool is None:
            workers = configured_workers()
            _pool = DetectionPool(workers, configured_queue_limit(workers))
        return _pool


def reset_pool() -> None:
    """For tests: stop and forget the pool."""
    global _pool
    with _pool_lock:
        pool, _pool = _pool, None
    if pool is not None:
        pool.shutdown()
