"""
RedHawk Engine implementation

This module provides the Engine class which manages task registration and
execution using a thread pool. It is written to be a backwards compatible
replacement for the previously-removed implementation. An alias
`RedHawkEngine = Engine` is provided for compatibility.

Features:
- register/unregister tasks by name
- synchronous or asynchronous execution of registered tasks
- lifecycle management (start / stop / restart)
- simple status reporting
- context-manager support
- factory from configuration mapping

The implementation aims to be stable and dependency-light (uses stdlib only).
"""
from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from typing import Any, Callable, Dict, Mapping, Optional

__all__ = ["Engine", "RedHawkEngine"]

DEFAULT_WORKERS = 4
DEFAULT_NAME = "RedHawkEngine"
_DEFAULT_SHUTDOWN_WAIT = 5.0


class Engine:
    """Core engine for RedHawk.

    The Engine manages a pool of worker threads and a registry of named
    callable tasks. Tasks may be executed synchronously via run_task or
    submitted for asynchronous execution via submit_task.

    Example:
        engine = Engine()
        engine.register_task("hello", lambda name: print(f"hello {name}"))
        engine.run_task("hello", "world")

    The class is intentionally small and stable so it can be used as a
    dependable building block for tooling and CLI code.
    """

    version = "1.0.0"

    def __init__(
        self,
        name: str = DEFAULT_NAME,
        max_workers: int = DEFAULT_WORKERS,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self.name = name
        self.max_workers = max(1, int(max_workers))
        self._logger = logger or logging.getLogger(self.__class__.__name__)
        self._tasks: Dict[str, Callable[..., Any]] = {}
        self._executor: Optional[ThreadPoolExecutor] = None
        self._executor_lock = threading.RLock()
        self._running = False
        self._start_time: Optional[float] = None

        # Ensure logger has at least a NullHandler to avoid noisy output
        if not self._logger.handlers:
            self._logger.addHandler(logging.NullHandler())

    # --- lifecycle ---
    def _ensure_executor(self) -> None:
        with self._executor_lock:
            if self._executor is None:
                self._logger.debug("Creating ThreadPoolExecutor (%d workers)", self.max_workers)
                self._executor = ThreadPoolExecutor(max_workers=self.max_workers)

    def start(self) -> None:
        """Start the engine. Subsequent task submissions will run."""
        with self._executor_lock:
            if self._running:
                self._logger.debug("Engine already running")
                return
            self._ensure_executor()
            self._running = True
            self._start_time = time.time()
            self._logger.info("%s started with %d worker(s)", self.name, self.max_workers)

    def stop(self, wait: bool = True, timeout: Optional[float] = _DEFAULT_SHUTDOWN_WAIT) -> None:
        """Stop the engine and shutdown the worker pool.

        Args:
            wait: whether to wait for currently submitted tasks to finish.
            timeout: maximum number of seconds to wait for shutdown if wait is True.
        """
        with self._executor_lock:
            if not self._running and self._executor is None:
                self._logger.debug("Engine not running")
                return

            self._running = False
            exec_ref = self._executor
            self._executor = None

        if exec_ref is not None:
            self._logger.info("Shutting down executor (wait=%s, timeout=%s)", wait, timeout)
            exec_ref.shutdown(wait=wait, timeout=timeout if wait else None)
            self._logger.info("Executor shut down")

        self._start_time = None

    def restart(self) -> None:
        """Restart the engine: stop then start again."""
        self._logger.debug("Restarting engine")
        self.stop()
        self.start()

    # --- task registry ---
    def register_task(self, name: str, func: Callable[..., Any]) -> None:
        """Register a callable as a named task.

        A ValueError is raised if the name is already registered.
        """
        if not callable(func):
            raise TypeError("func must be callable")
        if name in self._tasks:
            raise ValueError(f"Task '{name}' is already registered")
        self._tasks[name] = func
        self._logger.debug("Registered task '%s'", name)

    def unregister_task(self, name: str) -> None:
        """Unregister a previously-registered task.

        If the task is not registered this is a no-op.
        """
        if name in self._tasks:
            del self._tasks[name]
            self._logger.debug("Unregistered task '%s'", name)

    def get_task(self, name: str) -> Optional[Callable[..., Any]]:
        """Return the callable registered for name or None if missing."""
        return self._tasks.get(name)

    # --- execution ---
    def submit_task(self, name: str, *args: Any, **kwargs: Any) -> Future:
        """Submit a registered task for asynchronous execution.

        Raises KeyError if the task name is unknown.
        """
        func = self._tasks.get(name)
        if func is None:
            raise KeyError(f"Unknown task '{name}'")

        # Ensure we have an executor
        self._ensure_executor()
        if self._executor is None:
            # Shouldn't happen, _ensure_executor ensures an executor is set
            raise RuntimeError("Executor unavailable")

        self.start()
        self._logger.debug("Submitting task '%s' to executor", name)
        return self._executor.submit(self._run_safe, func, *args, **kwargs)

    def run_task(self, name: str, *args: Any, **kwargs: Any) -> Any:
        """Run a registered task synchronously and return its result.

        This convenience method will execute the task in the calling thread.
        Raises KeyError if the task name is unknown.
        """
        func = self._tasks.get(name)
        if func is None:
            raise KeyError(f"Unknown task '{name}'")
        self._logger.debug("Running task '%s' synchronously", name)
        return self._run_safe(func, *args, **kwargs)

    def _run_safe(self, func: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        """Execute func(*args, **kwargs) capturing/logging exceptions."""
        try:
            return func(*args, **kwargs)
        except Exception as exc:  # pragma: no cover - defensive logging
            self._logger.exception("Task raised an exception: %s", exc)
            raise

    # --- configuration and factories ---
    def configure(self, *, max_workers: Optional[int] = None, name: Optional[str] = None) -> None:
        """Dynamically update engine configuration.

        Note: changing max_workers will take effect when the engine is
        restarted.
        """
        if max_workers is not None:
            self.max_workers = max(1, int(max_workers))
            self._logger.debug("Configured max_workers=%d", self.max_workers)
        if name:
            self.name = name
            self._logger.debug("Configured name=%s", self.name)

    @classmethod
    def from_config(cls, cfg: Mapping[str, Any]) -> "Engine":
        """Construct an Engine from a mapping-like config.

        Recognized keys: name, max_workers.
        """
        name = cfg.get("name", DEFAULT_NAME)
        max_workers = cfg.get("max_workers", DEFAULT_WORKERS)
        logger = cfg.get("logger")
        return cls(name=name, max_workers=max_workers, logger=logger)

    # --- utilities ---
    def status(self) -> Dict[str, Any]:
        """Return a snapshot of engine status useful for health checks."""
        return {
            "name": self.name,
            "running": bool(self._running),
            "registered_tasks": list(self._tasks.keys()),
            "tasks_count": len(self._tasks),
            "max_workers": self.max_workers,
            "uptime": (time.time() - self._start_time) if self._start_time else None,
            "version": self.version,
        }

    @classmethod
    def get_version(cls) -> str:
        """Return the engine implementation version."""
        return cls.version

    # --- context manager support ---
    def __enter__(self) -> "Engine":
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        # Attempt a graceful stop; allow exceptions to propagate
        self.stop()


# Backwards compatible alias
RedHawkEngine = Engine
