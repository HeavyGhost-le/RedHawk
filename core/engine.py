"""
Comprehensive engine implementation for RedHawk.

Provides:
- Module discovery via package name or directory (get_available_modules)
- Running single modules with sync/async entrypoints, including support for
  modules that return async context managers (run_module / run_module_async)
- Convenience functions to run multiple modules concurrently (run_modules)
  or all discovered modules (run_all_modules)
- Saving results to disk in JSON format (save_results)

Module expectations
-------------------
A discovered module should expose at least one of the following callables:
- async def run(entry, **kwargs)
- def run(entry, **kwargs)
- async def main(entry, **kwargs)
- def main(entry, **kwargs)

Alternatively a module may expose a context manager class or factory that is
awaitable via async with. For example:

async def run(entry):
    async with SomeAsyncContext(entry) as result:
        return result

or directly return an async context manager from run(); the engine will detect
that and enter it.

The engine will capture exceptions and return structured result objects so a
calling system can decide how to proceed.
"""
from __future__ import annotations

import asyncio
import importlib
import inspect
import json
import logging
import pkgutil
import sys
import traceback
from contextlib import AsyncExitStack
from datetime import datetime
from pathlib import Path
from types import ModuleType
from typing import Any, Dict, Iterable, List, Optional, Tuple

logger = logging.getLogger(__name__)


class ModuleRunError(Exception):
    """Raised when a module fails to run."""


def _is_async_context_manager(obj: Any) -> bool:
    """Return True if obj implements the async context manager protocol.

    We check for __aenter__ and __aexit__.
    """
    return hasattr(obj, "__aenter__") and hasattr(obj, "__aexit__")


async def _enter_async_context_if_needed(ret: Any) -> Any:
    """If ret is an async context manager, enter it and return the yielded value.

    Note: the caller is responsible for exiting the context manager. To make
    resource management deterministic we exit immediately after retrieving the
    yielded value (i.e. use async with immediately). If a module intends to
    keep resources open across the engine lifetime it should provide an
    alternative mechanism.
    """
    if _is_async_context_manager(ret):
        async with ret as value:
            return value
    return ret


def get_available_modules(
    package: str = "modules", modules_dir: Optional[Path] = None
) -> Dict[str, str]:
    """Discover available modules.

    The discovery will attempt multiple strategies in this order:
    1. Try importing the named package and enumerate its submodules via
       pkgutil.iter_modules on the package.__path__.
    2. If that fails and modules_dir is provided, scan that directory for
       Python files (ignoring __init__.py) and return module names based on
       filenames.

    Returns a dict mapping module_name -> import_path (useful for later
    importing with importlib.import_module).
    """
    modules: Dict[str, str] = {}

    # Strategy 1: package import
    try:
        pkg = importlib.import_module(package)
        if hasattr(pkg, "__path__"):
            for finder, name, ispkg in pkgutil.iter_modules(pkg.__path__):
                modules[name] = f"{package}.{name}"
            if modules:
                return modules
    except Exception:
        logger.debug("Package import failed for %s", package, exc_info=True)

    # Strategy 2: directory scan
    if modules_dir:
        modules_dir = Path(modules_dir)
        if modules_dir.is_dir():
            for p in sorted(modules_dir.iterdir()):
                if p.name.startswith("_"):
                    continue
                if p.is_file() and p.suffix in (".py",):
                    if p.name == "__init__.py":
                        continue
                    name = p.stem
                    modules[name] = name
                elif p.is_dir():
                    if (p / "__init__.py").exists():
                        modules[p.name] = p.name
    return modules


def _import_module_by_path(import_path: str) -> ModuleType:
    """Import a module by full import path (e.g. 'modules.foo')."""
    return importlib.import_module(import_path)


async def run_module_async(
    module_name: str,
    entry: Any = None,
    *,
    package: str = "modules",
    modules_dir: Optional[Path] = None,
    timeout: Optional[float] = None,
    import_path: Optional[str] = None,
    **kwargs,
) -> Dict[str, Any]:
    """Run a single module asynchronously.

    The function attempts to import the module from the specified package or
    directory. It looks for a callable named 'run' or 'main' and handles the
    following cases:
    - sync function -> called in threadpool
    - async coroutine function -> awaited
    - callable that returns an async context manager -> entered and value
      extracted

    Returns a structured result dict with keys:
    - name: module_name
    - ok: bool
    - result: value returned by module (if ok)
    - error: string with traceback (if not ok)
    - meta: additional metadata (duration, timestamp)
    """
    t0 = datetime.utcnow()
    meta: Dict[str, Any] = {"started_at": t0.isoformat() + "Z"}

    # Determine import path
    try:
        if import_path is None:
            available = get_available_modules(package, modules_dir)
            if module_name in available:
                import_path = available[module_name]
            else:
                # fallback: try f"{package}.{module_name}" even if discovery
                import_path = f"{package}.{module_name}"

        module = _import_module_by_path(import_path)
    except Exception as exc:  # noqa: BLE001 (we want to capture all import errors)
        tb = traceback.format_exc()
        logger.error("Failed to import module %s (%s): %s", module_name, import_path, exc)
        return {
            "name": module_name,
            "ok": False,
            "error": tb,
            "result": None,
            "meta": {**meta, "import_path": import_path},
        }

    # Find the entrypoint
    entrypoint = None
    for candidate in ("run", "main"):
        entrypoint = getattr(module, candidate, None)
        if entrypoint is not None:
            break

    # If the module exposes a class named Module, try to use it as a factory
    if entrypoint is None and hasattr(module, "Module"):
        entrypoint = getattr(module, "Module")

    if entrypoint is None:
        err = f"No entrypoint found in module {module_name}; expected 'run' or 'main' or 'Module'"
        logger.error(err)
        return {"name": module_name, "ok": False, "error": err, "result": None, "meta": meta}

    try:
        # We support sync and async callables and classes
        if inspect.isclass(entrypoint):
            # Instantiate the class - if it is an async context manager, we'll
            # detect that when we call it.
            inst = entrypoint(entry, **kwargs) if _accepts_args(entrypoint) else entrypoint()
            call_obj = inst
        elif callable(entrypoint):
            # If function accepts (entry, **kwargs) pass them else only entry
            if _accepts_args(entrypoint):
                call_obj = lambda: entrypoint(entry, **kwargs)
            else:
                call_obj = lambda: entrypoint(entry)
        else:
            raise ModuleRunError("Entrypoint is not callable or class")

        async def _invoke():
            # If call_obj returns coroutine or value or async context manager
            maybe_coro_or_ctx = call_obj()

            # If call_obj returned a coroutine object -> await it
            if inspect.isawaitable(maybe_coro_or_ctx):
                ret = await maybe_coro_or_ctx
            else:
                # It's a plain value or an async context manager instance
                ret = maybe_coro_or_ctx

            # If ret is an async context manager, enter it and obtain the value
            if _is_async_context_manager(ret):
                # Enter and return the value yielded by the context manager
                return await _enter_async_context_if_needed(ret)

            return ret

        if timeout is not None:
            result = await asyncio.wait_for(_invoke(), timeout=timeout)
        else:
            result = await _invoke()

        t1 = datetime.utcnow()
        meta.update({"duration_s": (t1 - t0).total_seconds(), "finished_at": t1.isoformat() + "Z"})
        return {"name": module_name, "ok": True, "result": result, "error": None, "meta": meta}

    except asyncio.CancelledError:
        raise
    except Exception:
        tb = traceback.format_exc()
        logger.exception("Module %s raised an exception", module_name)
        t1 = datetime.utcnow()
        meta.update({"duration_s": (t1 - t0).total_seconds(), "finished_at": t1.isoformat() + "Z"})
        return {"name": module_name, "ok": False, "result": None, "error": tb, "meta": meta}


def _accepts_args(func_or_class: Any) -> bool:
    """Return True if the callable/class __init__ accepts at least one argument

    We use this to decide whether to call entrypoint(entry) or entrypoint().
    """
    try:
        if inspect.isclass(func_or_class):
            sig = inspect.signature(func_or_class.__init__)
            # remove 'self'
            params = list(sig.parameters.values())[1:]
        else:
            sig = inspect.signature(func_or_class)
            params = list(sig.parameters.values())
    except (TypeError, ValueError):
        return False

    # Accept if there are any positional or keyword-only parameters
    for p in params:
        if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD, p.KEYWORD_ONLY):
            return True
    return False


def run_module(
    module_name: str,
    entry: Any = None,
    *,
    package: str = "modules",
    modules_dir: Optional[Path] = None,
    timeout: Optional[float] = None,
    import_path: Optional[str] = None,
    **kwargs,
) -> Dict[str, Any]:
    """Synchronous wrapper for run_module_async. Executes an asyncio loop to
    run the module and returns the same structured result dict.
    """
    try:
        return asyncio.run(
            run_module_async(
                module_name,
                entry,
                package=package,
                modules_dir=modules_dir,
                timeout=timeout,
                import_path=import_path,
                **kwargs,
            )
        )
    except Exception:
        # If asyncio.run fails because we're already in an event loop (e.g.
        # running under another async environment), create a new task and run
        # until complete using the running loop.
        if _in_running_loop():
            loop = asyncio.get_event_loop()
            coro = run_module_async(
                module_name,
                entry,
                package=package,
                modules_dir=modules_dir,
                timeout=timeout,
                import_path=import_path,
                **kwargs,
            )
            return loop.run_until_complete(coro)
        raise


def _in_running_loop() -> bool:
    try:
        return asyncio.get_running_loop() is not None
    except RuntimeError:
        return False


async def _run_worker(
    sem: asyncio.Semaphore,
    module_name: str,
    entry: Any,
    package: str,
    modules_dir: Optional[Path],
    timeout: Optional[float],
    import_path: Optional[str],
    **kwargs,
) -> Dict[str, Any]:
    async with sem:
        return await run_module_async(
            module_name,
            entry,
            package=package,
            modules_dir=modules_dir,
            timeout=timeout,
            import_path=import_path,
            **kwargs,
        )


def run_modules(
    module_names: Iterable[str],
    entry: Any = None,
    *,
    package: str = "modules",
    modules_dir: Optional[Path] = None,
    concurrency: int = 4,
    timeout: Optional[float] = None,
    import_paths: Optional[Dict[str, str]] = None,
    **kwargs,
) -> List[Dict[str, Any]]:
    """Run multiple modules concurrently (up to concurrency) and return list
    of results in the same order as module_names.

    module_names: iterable of module name strings
    entry: passed to each module's entrypoint
    concurrency: number of workers to run concurrently
    timeout: per-module timeout (seconds)
    import_paths: optional mapping module_name -> import path
    """
    import_paths = import_paths or {}

    async def _runner():
        sem = asyncio.Semaphore(concurrency)
        tasks = [
            asyncio.create_task(
                _run_worker(
                    sem,
                    name,
                    entry,
                    package,
                    modules_dir,
                    timeout,
                    import_paths.get(name),
                    **kwargs,
                )
            )
            for name in module_names
        ]
        results = await asyncio.gather(*tasks, return_exceptions=False)
        return results

    try:
        return asyncio.run(_runner())
    except Exception:
        if _in_running_loop():
            loop = asyncio.get_event_loop()
            return loop.run_until_complete(_runner())
        raise


def run_all_modules(
    entry: Any = None,
    *,
    package: str = "modules",
    modules_dir: Optional[Path] = None,
    concurrency: int = 4,
    timeout: Optional[float] = None,
    **kwargs,
) -> List[Dict[str, Any]]:
    """Discover all available modules and run them via run_modules.

    The discovery uses get_available_modules(package, modules_dir).
    """
    available = get_available_modules(package, modules_dir)
    names = list(available.keys())
    logger.debug("Discovered modules: %s", names)
    import_paths = {k: v for k, v in available.items()}
    return run_modules(
        names,
        entry,
        package=package,
        modules_dir=modules_dir,
        concurrency=concurrency,
        timeout=timeout,
        import_paths=import_paths,
        **kwargs,
    )


def save_results(results: Iterable[Dict[str, Any]], path: Path | str, *, indent: int = 2) -> Path:
    """Save results (list/dict) to a JSON file with timestamp metadata.

    The function will create parent directories as needed. If the path exists
    it will be overwritten.

    Returns the Path to the written file.
    """
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)

    payload = {
        "saved_at": datetime.utcnow().isoformat() + "Z",
        "count": 0,
        "results": [],
    }

    for r in results:
        payload["results"].append(r)
    payload["count"] = len(payload["results"])

    with p.open("w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=indent, default=_json_default)

    logger.info("Saved %d module results to %s", payload["count"], p)
    return p


def _json_default(obj: Any) -> Any:
    # Fallback serializer for datetimes and exceptions & other objects
    if isinstance(obj, datetime):
        return obj.isoformat() + "Z"
    if isinstance(obj, BaseException):
        return {"error_type": type(obj).__name__, "args": obj.args, "repr": repr(obj)}
    try:
        return str(obj)
    except Exception:
        return repr(obj)


# Provide a simple CLI helper when executed as __main__ for quick local tests
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Run RedHawk modules via core.engine")
    parser.add_argument("modules", nargs="*", help="Module names to run (if empty run all)")
    parser.add_argument("--package", default="modules", help="Package to search for modules")
    parser.add_argument("--dir", default=None, help="Directory to search for modules (fallback)")
    parser.add_argument("--out", default="results.json", help="File to write results to")
    parser.add_argument("--concurrency", type=int, default=4, help="Max concurrency")
    args = parser.parse_args()

    if args.modules:
        res = run_modules(args.modules, package=args.package, modules_dir=Path(args.dir) if args.dir else None, concurrency=args.concurrency)
    else:
        res = run_all_modules(package=args.package, modules_dir=Path(args.dir) if args.dir else None, concurrency=args.concurrency)

    save_results(res, Path(args.out))
