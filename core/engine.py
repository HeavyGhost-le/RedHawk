"""
Core engine: dynamic module loading and integration

This engine restores dynamic module discovery/loading, integrates
CredentialManager, Database, EthicsChecker, and PerformanceMonitor, and
provides run_modules to execute modules with dependency injection and
runtime compatibility with different module shapes.

The implementation uses defensive imports so it will work when those
components live in different places within the project. Modules can be
plain python files or packages under the `modules/` directory and can
expose either:
 - a `run(...)` function
 - a `Module` class with a `run(...)` instance method

run(...) callables are supported with flexible argument mapping. The
engine collects execution results and metrics and defers to the
EthicsChecker on errors.
"""

from __future__ import annotations

import importlib
import importlib.util
import inspect
import logging
import os
import pkgutil
import sys
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from types import ModuleType
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

LOG = logging.getLogger(__name__)

# Defensive imports for project components (allow multiple layouts)
try:
    from core.credentials import CredentialManager
except Exception:
    try:
        from credentials import CredentialManager
    except Exception:
        class CredentialManager:  # pragma: no cover - fallback shim
            def __init__(self, *a, **k):
                LOG.debug("Fallback CredentialManager in use")
            def get(self, *a, **k):
                return None

try:
    from core.database import Database
except Exception:
    try:
        from database import Database
    except Exception:
        class Database:  # pragma: no cover - fallback shim
            def __init__(self, *a, **k):
                LOG.debug("Fallback Database in use")
            def query(self, *a, **k):
                return None

try:
    from core.ethics import EthicsChecker
except Exception:
    try:
        from ethics import EthicsChecker
    except Exception:
        class EthicsChecker:  # pragma: no cover - fallback shim
            def __init__(self, *a, **k):
                LOG.debug("Fallback EthicsChecker in use")
            def check_error(self, *a, **k):
                return True

try:
    from core.perf import PerformanceMonitor
except Exception:
    try:
        from perf import PerformanceMonitor
    except Exception:
        class PerformanceMonitor:  # pragma: no cover - fallback shim
            def __init__(self, *a, **k):
                LOG.debug("Fallback PerformanceMonitor in use")
            def start(self, key: str):
                return time.time()
            def stop(self, key: str, start_ts: float):
                return time.time() - start_ts


class Engine:
    """Primary orchestrator for RedHawk modules.

    Responsibilities:
    - Discover modules under the configured modules path.
    - Load modules dynamically, supporting file-based and package modules.
    - Instantiate or call module entrypoints with injected dependencies.
    - Record execution results and performance metrics.
    - Use EthicsChecker for error handling policy decisions.
    """

    def __init__(
        self,
        root: Optional[str] = None,
        modules_path: Optional[str] = None,
        config: Optional[dict] = None,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self.root = root or os.path.dirname(os.path.dirname(__file__))
        self.modules_path = modules_path or os.path.join(self.root, "modules")
        self.config = config or {}
        self.logger = logger or LOG

        # Core services
        self.credentials = CredentialManager()
        self.db = Database()
        self.ethics = EthicsChecker()
        self.perf = PerformanceMonitor()

        # Cached module map: name -> module object
        self._modules: Dict[str, ModuleType] = {}

        self.logger.debug("Engine initialized (modules_path=%s)", self.modules_path)

    # ----------------------- Module discovery/load -----------------------
    def discover_modules(self) -> List[str]:
        """Discover module names under the modules_path.

        Returns a list of module identifiers (module package names or file
        basenames without .py).
        """
        found: List[str] = []
        if not os.path.isdir(self.modules_path):
            self.logger.debug("Modules path does not exist: %s", self.modules_path)
            return found

        # Iterate packages and files
        for finder, name, ispkg in pkgutil.iter_modules([self.modules_path]):
            found.append(name)
        # Also include standalone .py files that may not be importable as package
        for entry in os.listdir(self.modules_path):
            if entry.endswith(".py") and entry != "__init__.py":
                name = os.path.splitext(entry)[0]
                if name not in found:
                    found.append(name)
        found.sort()
        self.logger.debug("Discovered modules: %s", found)
        return found

    def _module_spec_to_name(self, path: str) -> str:
        return os.path.splitext(os.path.basename(path))[0]

    def load_module(self, name: str) -> ModuleType:
        """Load a module by name (relative to modules_path) or full import name.

        Caches loaded modules in self._modules.
        """
        if name in self._modules:
            return self._modules[name]

        # Try standard import first
        try:
            mod = importlib.import_module(name)
            self._modules[name] = mod
            self.logger.debug("Imported existing module %s", name)
            return mod
        except Exception:
            self.logger.debug("Standard import failed for %s, trying modules_path", name, exc_info=True)

        # Try loading from modules_path by filename
        candidate = os.path.join(self.modules_path, f"{name}.py")
        package_init = os.path.join(self.modules_path, name, "__init__.py")
        if os.path.exists(candidate):
            spec = importlib.util.spec_from_file_location(f"redhawk.modules.{name}", candidate)
        elif os.path.exists(package_init):
            spec = importlib.util.spec_from_file_location(f"redhawk.modules.{name}", package_init)
        else:
            raise ImportError(f"Module {name} not found in sys.path or modules_path")

        module = importlib.util.module_from_spec(spec)
        # Ensure module can import project local modules
        if self.root not in sys.path:
            sys.path.insert(0, self.root)
        loader = spec.loader
        assert loader is not None
        loader.exec_module(module)
        # cache and return
        self._modules[name] = module
        self.logger.debug("Loaded module %s from %s", name, candidate)
        return module

    # ----------------------- Module invocation -----------------------
    def _resolve_callable(self, module: ModuleType) -> Tuple[Optional[Callable], Optional[Any]]:
        """Return a (callable, instance_owner) pair for module entrypoint.

        Accepts:
        - module.run function -> (function, None)
        - Module class with run method -> (instance.run, instance)
        - top-level callable named 'main' -> (main, None)
        """
        # Priority 1: run function
        if hasattr(module, "run") and callable(getattr(module, "run")):
            return getattr(module, "run"), None
        # Priority 2: Module class
        for cls_name in ("Module", "Plugin"):
            cls = getattr(module, cls_name, None)
            if inspect.isclass(cls):
                try:
                    inst = cls(engine=self)
                except TypeError:
                    # fall back to no-arg constructor
                    inst = cls()
                if hasattr(inst, "run") and callable(inst.run):
                    return inst.run, inst
        # Priority 3: main
        if hasattr(module, "main") and callable(getattr(module, "main")):
            return getattr(module, "main"), None
        return None, None

    def _call_with_injected_args(self, func: Callable, kwargs: dict) -> Any:
        """Call func by mapping only supported keyword arguments from kwargs.

        This ensures modules that accept a subset of dependencies keep working.
        """
        sig = inspect.signature(func)
        call_kwargs = {}
        for name, param in sig.parameters.items():
            if name in kwargs:
                call_kwargs[name] = kwargs[name]
            elif param.default is inspect._empty and param.kind in (inspect.Parameter.POSITIONAL_ONLY,):
                # Positional-only without default can't be satisfied by name mapping - let call try and raise
                pass
        # If function accepts **kwargs, pass remaining
        if any(p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values()):
            call_kwargs.update(kwargs)
        return func(**call_kwargs)

    def run_modules(self,
                    module_names: Optional[Iterable[str]] = None,
                    timeout: Optional[float] = None,
                    parallel: bool = False,
                    max_workers: int = 4) -> Dict[str, Dict[str, Any]]:
        """Load and execute modules, returning a results map.

        Results per module include: status (success|error), result, metrics.
        """
        if module_names is None:
            module_names = self.config.get("enabled_modules") or self.discover_modules()

        results: Dict[str, Dict[str, Any]] = {}

        def _run_one(name: str) -> Tuple[str, Dict[str, Any]]:
            meta: Dict[str, Any] = {"status": "error", "result": None, "metrics": {}}
            try:
                module = self.load_module(name)
                callable_entry, owner = self._resolve_callable(module)
                if callable_entry is None:
                    meta["result"] = f"No runnable entrypoint found for module {name}"
                    self.logger.warning(meta["result"])
                    return name, meta

                # Prepare injection map
                inject = {
                    "engine": self,
                    "credentials": self.credentials,
                    "db": self.db,
                    "ethics": self.ethics,
                    "perf": self.perf,
                    "logger": getattr(module, "logger", self.logger),
                }

                # Start perf measurement
                perf_key = f"module:{name}"
                start_ts = None
                try:
                    if hasattr(self.perf, "start"):
                        start_ts = self.perf.start(perf_key)
                except Exception:
                    start_ts = time.time()

                # Execute with flexible injection and optional timeout
                result = None
                if timeout is None:
                    result = self._call_with_injected_args(callable_entry, inject)
                else:
                    # Use thread executor to enforce timeout for python-level blocking
                    with ThreadPoolExecutor(max_workers=1) as ex:
                        fut = ex.submit(self._call_with_injected_args, callable_entry, inject)
                        try:
                            result = fut.result(timeout=timeout)
                        except Exception as e:  # includes TimeoutError
                            fut.cancel()
                            raise

                # Stop perf measurement
                elapsed = None
                try:
                    if hasattr(self.perf, "stop") and start_ts is not None:
                        elapsed = self.perf.stop(perf_key, start_ts)
                except Exception:
                    elapsed = time.time() - (start_ts or time.time())

                meta["status"] = "success"
                meta["result"] = result
                meta["metrics"]["elapsed_seconds"] = elapsed
                self.logger.info("Module %s finished successfully (%.3fs)", name, elapsed or 0.0)
            except Exception as exc:  # capture and consult ethics checker
                tb = traceback.format_exc()
                self.logger.exception("Module %s raised an exception", name)
                try:
                    decision = True
                    if hasattr(self.ethics, "check_error"):
                        decision = self.ethics.check_error(module=name, error=exc, traceback=tb)
                except Exception:
                    decision = True
                meta["status"] = "error" if decision else "blocked_by_ethics"
                meta["result"] = {"error": str(exc), "traceback": tb}
            return name, meta

        names = list(module_names)
        if parallel:
            with ThreadPoolExecutor(max_workers=min(max_workers, len(names) or 1)) as ex:
                futures = {ex.submit(_run_one, n): n for n in names}
                for fut in as_completed(futures):
                    n, r = fut.result()
                    results[n] = r
        else:
            for n in names:
                n, r = _run_one(n)
                results[n] = r

        return results


# Convenience runnable entrypoint
def main(*, modules: Optional[List[str]] = None, parallel: bool = False) -> int:
    logging.basicConfig(level=logging.INFO)
    engine = Engine()
    res = engine.run_modules(module_names=modules, parallel=parallel)
    # Simple exit code: 0 if all success
    failures = [m for m, r in res.items() if r.get("status") != "success"]
    if failures:
        LOG.warning("Modules completed with failures: %s", failures)
        return 2
    LOG.info("All modules completed successfully")
    return 0
