"""Async Task Queue: run heavy scans on worker threads so the UI never freezes.

Bounded on purpose (a flood of scan requests must not exhaust memory); failures are kept on the
job and reported, never swallowed. Works from plain threads and from asyncio (wait_async).
"""
from __future__ import annotations

import asyncio
import itertools
import queue
import threading
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Callable

from . import ScannerError

MAX_FINISHED_JOBS = 200


class QueueFullError(ScannerError):
    pass


@dataclass
class ScanJob:
    job_id: str
    status: str = "queued"          # queued | running | done | error | cancelled
    result: Any = None
    error: str = ""
    _done: threading.Event = field(default_factory=threading.Event, repr=False, compare=False)

    @property
    def finished(self) -> bool:
        return self.status in {"done", "error", "cancelled"}


class AsyncTaskQueue:
    def __init__(self, workers: int = 1, max_queue: int = 100) -> None:
        if not 1 <= workers <= 8 or max_queue < 1:
            raise ValueError("Jumlah worker/antrean tidak valid")
        self._queue: queue.Queue[tuple[ScanJob, Callable[..., Any], tuple, dict] | None] = queue.Queue(maxsize=max_queue)
        self._jobs: OrderedDict[str, ScanJob] = OrderedDict()
        self._lock = threading.Lock()
        self._counter = itertools.count(1)
        self._threads = [threading.Thread(target=self._run, name=f"kt-scan-{i}", daemon=True) for i in range(workers)]
        self._closed = False
        for thread in self._threads:
            thread.start()

    def submit(self, func: Callable[..., Any], *args: Any, **kwargs: Any) -> str:
        with self._lock:
            if self._closed:
                raise ScannerError("Antrean pemindaian sudah dihentikan.")
            job = ScanJob(job_id=f"job-{next(self._counter):06d}")
            try:
                self._queue.put_nowait((job, func, args, kwargs))
            except queue.Full as exc:
                raise QueueFullError("Antrean pemindaian penuh; tunggu pekerjaan sebelumnya selesai.") from exc
            self._jobs[job.job_id] = job
            self._trim()
        return job.job_id

    def _trim(self) -> None:
        finished = [k for k, v in self._jobs.items() if v.finished]
        while len(finished) > MAX_FINISHED_JOBS:
            self._jobs.pop(finished.pop(0), None)

    def get(self, job_id: str) -> ScanJob | None:
        with self._lock:
            return self._jobs.get(job_id)

    def cancel(self, job_id: str) -> bool:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None or job.status != "queued":
                return False
            job.status = "cancelled"
            job._done.set()
            return True

    def wait(self, job_id: str, timeout: float | None = None) -> ScanJob:
        job = self.get(job_id)
        if job is None:
            raise KeyError(job_id)
        job._done.wait(timeout)
        return job

    async def wait_async(self, job_id: str, timeout: float | None = None) -> ScanJob:
        return await asyncio.to_thread(self.wait, job_id, timeout)

    def _run(self) -> None:
        while True:
            item = self._queue.get()
            if item is None:
                return
            job, func, args, kwargs = item
            with self._lock:
                if job.status == "cancelled":
                    continue
                job.status = "running"
            try:
                job.result = func(*args, **kwargs)
                job.status = "done"
            except BaseException as exc:  # noqa: BLE001 - recorded on the job, not lost
                job.error = f"{type(exc).__name__}: {str(exc)[:300]}"
                job.status = "error"
            finally:
                job._done.set()

    def shutdown(self, wait: bool = True) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
        for _ in self._threads:
            self._queue.put(None)
        if wait:
            for thread in self._threads:
                thread.join(timeout=5)
