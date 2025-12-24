"""
Core engine utilities for RedHawk.

This module adds richer class instantiation heuristics (so Scanner/Module classes
that accept combinations of target, engine, config are supported) and better
asyncio support: run_module will await coroutine results when possible and
provides an async variant for use from async code.

Commit message: feat(core): support async module entrypoints and richer instantiation for Scanner/Module
"""

from __future__ import annotations

import asyncio
import inspect
from typing import Any, Callable, Optional


class Engine:
    """Lightweight engine helper used to instantiate/execute modules/scanners.

    Key features added here:
    - instantiate_component: will try to construct a class by matching constructor
      parameter names (target, engine, config) and will fall back to positional
      attempts before finally calling the no-arg constructor.
    - run_module / run_module_async: will call a module's entrypoint (run/main or
      the object itself). If the result is awaitable, run_module will synchronously
      run it to completion (using asyncio.run) when called from sync code; when
      called from an already-running event loop it will schedule and return a
      Task. Prefer run_module_async from async callers to always receive the
      awaited final result.
    """

    def __init__(self, config: Optional[dict] = None) -> None:
        self.config = config or {}

    def instantiate_component(
        self,
        component: Any,
        *,
        target: Any = None,
        engine: "Engine" | None = None,
        config: Optional[dict] = None,
    ) -> Any:
        """Instantiate a class or return the object as-is.

        If `component` is a class, we try to call its constructor by matching
        parameter names. Supported parameter names that are automatically
        provided are: 'target', 'engine', 'config'. If matching by name fails,
        a few positional fallbacks are attempted.

        If component is already an instance (not a class), it is returned
        unchanged.
        """
        if not inspect.isclass(component):
            return component

        cls = component
        provided_config = config if config is not None else self.config

        # Inspect __init__ parameters (skip 'self')
        try:
            sig = inspect.signature(cls.__init__)
            params = [p.name for p in list(sig.parameters.values())[1:]]
        except (ValueError, TypeError):
            # If we can't get a signature, fall back to naive instantiation
            try:
                return cls()
            except Exception:
                raise

        # Try to instantiate by name-matching kwargs first
        kwargs = {}
        if "target" in params and target is not None:
            kwargs["target"] = target
        if "engine" in params and engine is not None:
            kwargs["engine"] = engine
        if "config" in params and provided_config is not None:
            kwargs["config"] = provided_config

        if kwargs:
            try:
                return cls(**kwargs)
            except TypeError:
                # Fall through to positional attempts
                pass

        # Positional fallback attempts. Build arg lists in commonly-used orders.
        candidates = []

        # Common orders: (target,), (target, engine), (target, engine, config),
        # (engine,), (config,)
        if "target" in params and target is not None:
            candidates.append((target,))
            if "engine" in params and engine is not None:
                candidates.append((target, engine))
                if "config" in params and provided_config is not None:
                    candidates.append((target, engine, provided_config))
        if "engine" in params and engine is not None:
            candidates.append((engine,))
        if "config" in params and provided_config is not None:
            candidates.append((provided_config,))

        for args in candidates:
            try:
                return cls(*args)
            except TypeError:
                continue

        # Last resort: no-arg constructor
        try:
            return cls()
        except Exception as exc:
            raise TypeError(
                f"Unable to instantiate {cls!r} with target/engine/config heuristics: {exc}"
            )

    async def run_module_async(self, module_or_class: Any, *args, target: Any = None, **kwargs) -> Any:
        """Asynchronously run a module entrypoint and return its final result.

        This will instantiate `module_or_class` if it is a class (using
        instantiate_component) and then try to call a sensible entrypoint:
        - instance.run(...)
        - instance.main(...)
        - instance(...) if the instance itself is callable

        If the called entrypoint returns an awaitable, it is awaited and the
        resolved value is returned.
        """
        inst = self.instantiate_component(module_or_class, target=target, engine=self, config=self.config)

        entry = None
        if hasattr(inst, "run") and callable(getattr(inst, "run")):
            entry = getattr(inst, "run")
        elif hasattr(inst, "main") and callable(getattr(inst, "main")):
            entry = getattr(inst, "main")
        elif callable(inst):
            entry = inst

        if entry is None:
            raise ValueError("Module/Scanner has no callable entrypoint (run/main/callable)")

        result = entry(*args, **kwargs)
        if inspect.isawaitable(result):
            return await result
        return result

    def run_module(self, module_or_class: Any, *args, target: Any = None, **kwargs) -> Any:
        """Run a module entrypoint from synchronous code.

        Behavior for coroutine results:
        - If there is no running event loop, asyncio.run(...) is used to run the
          coroutine to completion and the final result is returned.
        - If there is a running event loop (we're inside async code), a Task is
          scheduled and returned. In that case callers should await the returned
          Task to obtain the final result. Prefer using run_module_async from
          async callsites to always receive the awaited result instead of a Task.
        """
        # Reuse async implementation for the heavy lifting
        inst = self.instantiate_component(module_or_class, target=target, engine=self, config=self.config)

        entry = None
        if hasattr(inst, "run") and callable(getattr(inst, "run")):
            entry = getattr(inst, "run")
        elif hasattr(inst, "main") and callable(getattr(inst, "main")):
            entry = getattr(inst, "main")
        elif callable(inst):
            entry = inst

        if entry is None:
            raise ValueError("Module/Scanner has no callable entrypoint (run/main/callable)")

        result = entry(*args, **kwargs)

        # If the result is an awaitable, decide how to run it depending on loop state
        if inspect.isawaitable(result):
            try:
                # If there's a running loop, return a Task (caller should await it)
                loop = asyncio.get_running_loop()
            except RuntimeError:
                # No running loop: run to completion and return final value
                return asyncio.run(result)
            else:
                # Running loop: schedule and return Task
                return loop.create_task(result)

        return result


# Export a small convenience singleton if desired
_default_engine: Optional[Engine] = None


def get_default_engine(config: Optional[dict] = None) -> Engine:
    global _default_engine
    if _default_engine is None:
        _default_engine = Engine(config=config)
    return _default_engine
