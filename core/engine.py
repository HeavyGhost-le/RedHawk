"""
Lightweight RedHawk engine shim for running modules.
This file provides a RedHawkEngine with a new run_modules method that
allows running a selected subset of modules against a target, either
sequentially or threaded. It also implements simple run_module and
threaded execution helpers and a save_results helper that persists
scan results to disk.

Note: This is implemented to be conservative and self-contained so the
modern GUI can import and integrate with it during runtime and CI
smoke-tests.
"""
from typing import List, Dict, Any, Optional, Callable
import threading
import time
import datetime
import uuid
import os
import json
import logging

logger = logging.getLogger(__name__)


class RedHawkEngine:
    """A simple engine that can run named "modules" against a target.

    This is intentionally minimal: modules are stored in self.modules as
    a mapping of name -> callable(module_name, target) returning a dict.
    """

    def __init__(self, callback: Optional[Callable] = None):
        # callback signature used by older callers (module_name, result)
        self.callback = callback
        # Populate with some example module functions; real project will
        # replace these or extend at runtime.
        self.modules: Dict[str, Callable[[str, str], Dict[str, Any]]] = {
            "whois": self._module_whois,
            "dns": self._module_dns,
            "http": self._module_http,
        }
        # ensure results directory exists
        os.makedirs("results", exist_ok=True)

    # --- example module implementations -------------------------------------------------
    def _module_whois(self, module_name: str, target: str) -> Dict[str, Any]:
        time.sleep(0.1)
        return {"module": module_name, "target": target, "status": "ok", "data": {"whois": "sample"}}

    def _module_dns(self, module_name: str, target: str) -> Dict[str, Any]:
        time.sleep(0.05)
        return {"module": module_name, "target": target, "status": "ok", "data": {"dns": ["1.2.3.4"]}}

    def _module_http(self, module_name: str, target: str) -> Dict[str, Any]:
        time.sleep(0.15)
        return {"module": module_name, "target": target, "status": "ok", "data": {"http": {"status": 200}}}

    # --- run helpers ------------------------------------------------------------------
    def run_module(self, module_name: str, target: str, callback: Optional[Callable] = None) -> Dict[str, Any]:
        """Run a single module by name against target. Returns the result dict.

        If the module is not found, returns an error dict.
        If a callback is provided it will be invoked with (module_name, result).
        """
        logger.debug("run_module: %s against %s", module_name, target)
        if module_name not in self.modules:
            result = {"module": module_name, "target": target, "error": f"module '{module_name}' not found"}
            if callback:
                try:
                    callback(module_name, result)
                except Exception:
                    logger.exception("callback failed for %s", module_name)
            return result

        try:
            func = self.modules[module_name]
            result = func(module_name, target)
        except Exception as e:
            logger.exception("module %s failed", module_name)
            result = {"module": module_name, "target": target, "error": str(e)}

        if callback:
            try:
                callback(module_name, result)
            except Exception:
                logger.exception("callback failed for %s", module_name)

        return result

    def run_modules_threaded(self, modules: List[str], target: str, callback: Optional[Callable] = None) -> Dict[str, Any]:
        """Run modules concurrently using threads. Collects per-module results."""
        results: Dict[str, Any] = {"target": target, "scan_id": str(uuid.uuid4()), "timestamp": datetime.datetime.utcnow().isoformat(), "modules": {}}
        threads: List[threading.Thread] = []
        lock = threading.Lock()

        def _runner(name: str):
            r = self.run_module(name, target, callback)
            with lock:
                results["modules"][name] = r

        for m in modules:
            t = threading.Thread(target=_runner, args=(m,), daemon=True)
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        output_path = self.save_results(results)
        results["output_path"] = output_path
        return results

    # --- new API: run_modules ----------------------------------------------------------
    def run_modules(self, modules: List[str], target: str, callback: Optional[Callable] = None, threaded: bool = False) -> Dict[str, Any]:
        """Run only the specified modules against target.

        Behavior:
        - Validate module names against self.modules. For missing modules include an error entry in results['modules'].
        - If threaded is False: call self.run_module sequentially and collect results.
        - If threaded is True: run selected modules concurrently using threads and collect results.
        - Build results dict with keys: target, scan_id, timestamp, modules. Save via self.save_results and set output_path.
        - Return results dict.
        """
        logger.info("run_modules called: modules=%s target=%s threaded=%s", modules, target, threaded)
        results: Dict[str, Any] = {"target": target, "scan_id": str(uuid.uuid4()), "timestamp": datetime.datetime.utcnow().isoformat(), "modules": {}}

        # Validate module names and prepare a list of valid modules to run
        to_run: List[str] = []
        for name in modules:
            if name not in self.modules:
                # include an error result for missing modules
                results["modules"][name] = {"module": name, "target": target, "error": f"module '{name}' not found"}
            else:
                to_run.append(name)

        # No valid modules -> save and return
        if not to_run:
            output_path = self.save_results(results)
            results["output_path"] = output_path
            return results

        if threaded:
            # Run concurrently
            threaded_results = self.run_modules_threaded(to_run, target, callback)
            # Merge threaded results modules into our results (preserve any earlier errors)
            results["modules"].update(threaded_results.get("modules", {}))
            # Use the same scan_id/timestamp/output_path from threaded run if present
            results["output_path"] = threaded_results.get("output_path")
            return results

        # Sequential execution
        for name in to_run:
            r = self.run_module(name, target, callback)
            results["modules"][name] = r

        # Save and return
        output_path = self.save_results(results)
        results["output_path"] = output_path
        return results

    # --- persistence helper -----------------------------------------------------------
    def save_results(self, results: Dict[str, Any]) -> str:
        """Save results to a JSON file under results/ and return the path."""
        filename = f"results/{results.get('scan_id', str(uuid.uuid4()))}.json"
        try:
            with open(filename, "w", encoding="utf-8") as fh:
                json.dump(results, fh, indent=2)
        except Exception:
            logger.exception("failed to write results to %s", filename)
        return filename


# make class importable at module level
__all__ = ["RedHawkEngine"]
