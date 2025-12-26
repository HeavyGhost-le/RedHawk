"""
RedHawk Engine implementation

This module provides the Engine class which manages module discovery, loading,
and execution with support for both synchronous and asynchronous modules.

Features:
- Module discovery from modules/ directory
- Loading modules by import path or file path
- Resolving entrypoints (run/scan/gather/main) and class-based modules
- Instantiation heuristics for classes (inject engine, target, config)
- Support for async entrypoints and async context managers
- Bulk execution via run_modules / run_all_modules
- Results saving utility
- Backwards compatible with legacy task-based API

The implementation aims to be stable and dependency-light (uses stdlib only).
"""
from __future__ import annotations

import asyncio
import importlib.util
import inspect
import logging
import os
import sys
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Set, Union

__all__ = ["Engine", "RedHawkEngine"]

DEFAULT_WORKERS = 4
DEFAULT_NAME = "RedHawkEngine"
_DEFAULT_SHUTDOWN_WAIT = 5.0


class Engine:
    """Core engine for RedHawk.

    The Engine manages module discovery, loading, and execution with support
    for both synchronous and asynchronous modules. It also maintains backwards
    compatibility with the task-based API.

    Example:
        engine = Engine()
        modules = engine.discover_modules()
        result = engine.run_module('subdomain_wildcard', target='example.com')

    The class supports async modules with context managers:
        result = await engine.run_module_async('osint', target='example.com')
    """

    version = "2.0.0"

    def __init__(
        self,
        name: str = DEFAULT_NAME,
        max_workers: int = DEFAULT_WORKERS,
        logger: Optional[logging.Logger] = None,
        config: Optional[Dict[str, Any]] = None,
        modules_dir: Optional[str] = None,
    ) -> None:
        self.name = name
        self.max_workers = max(1, int(max_workers))
        self._logger = logger or logging.getLogger(self.__class__.__name__)
        self.config = config or {}
        
        # Module discovery
        if modules_dir is None:
            # Try to find modules directory relative to this file
            engine_dir = Path(__file__).parent
            project_root = engine_dir.parent
            modules_dir = str(project_root / "modules")
        self.modules_dir = modules_dir
        
        # Legacy task registry for backwards compatibility
        self._tasks: Dict[str, Callable[..., Any]] = {}
        
        # Module cache: name -> module object or class
        self._modules: Dict[str, Any] = {}
        
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

    # --- module discovery and loading ---
    def discover_modules(self) -> Dict[str, str]:
        """Discover available modules from the modules directory.
        
        Returns:
            Dictionary mapping module name to file path
        """
        modules = {}
        
        if not os.path.isdir(self.modules_dir):
            self._logger.warning(f"Modules directory not found: {self.modules_dir}")
            return modules
        
        try:
            for filename in os.listdir(self.modules_dir):
                if filename.endswith('.py') and not filename.startswith('_'):
                    module_name = filename[:-3]  # Remove .py extension
                    module_path = os.path.join(self.modules_dir, filename)
                    modules[module_name] = module_path
                    self._logger.debug(f"Discovered module: {module_name}")
        except Exception as e:
            self._logger.error(f"Error discovering modules: {e}")
        
        return modules
    
    def get_available_modules(self) -> List[str]:
        """Get list of available module names.
        
        Returns:
            List of module names
        """
        return list(self.discover_modules().keys())
    
    def load_module(self, module_name: str, module_path: Optional[str] = None) -> Any:
        """Load a module by name or path.
        
        Args:
            module_name: Name of the module (without .py extension)
            module_path: Optional path to module file. If not provided, will
                        search in modules directory.
        
        Returns:
            The loaded module object
        """
        # Check cache first
        if module_name in self._modules:
            return self._modules[module_name]
        
        # Determine module path
        if module_path is None:
            discovered = self.discover_modules()
            if module_name not in discovered:
                raise ValueError(f"Module '{module_name}' not found")
            module_path = discovered[module_name]
        
        try:
            # Load module dynamically
            spec = importlib.util.spec_from_file_location(module_name, module_path)
            if spec is None or spec.loader is None:
                raise ImportError(
                    f"Cannot load module '{module_name}' from {module_path}. "
                    f"Check file exists and is valid Python."
                )
            
            module = importlib.util.module_from_spec(spec)
            # Add to sys.modules for import resolution (intentional for caching)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)
            
            # Cache the module
            self._modules[module_name] = module
            self._logger.debug(f"Loaded module: {module_name}")
            
            return module
        except Exception as e:
            # Clean up sys.modules on failure to prevent namespace pollution
            if module_name in sys.modules:
                del sys.modules[module_name]
            self._logger.error(f"Error loading module {module_name}: {e}")
            raise
    
    def _resolve_entrypoint(self, module_obj: Any, target: str, config: Optional[Dict] = None) -> Any:
        """Resolve and prepare entrypoint from a module.
        
        Supports:
        - Class-based modules: Scanner, OSINTScanner, Module, Plugin
        - Function entrypoints: run, scan, gather, main
        
        Args:
            module_obj: The loaded module object
            target: Target for the scan
            config: Optional configuration
        
        Returns:
            Callable entrypoint or instantiated class
        """
        config = config or self.config
        
        # Try to find class-based modules
        for class_name in ['Scanner', 'OSINTScanner', 'Module', 'Plugin']:
            if hasattr(module_obj, class_name):
                cls = getattr(module_obj, class_name)
                if inspect.isclass(cls):
                    # Instantiate with heuristics
                    return self._instantiate_class(cls, target, config)
        
        # Try to find function entrypoints
        for func_name in ['run', 'scan', 'gather', 'main']:
            if hasattr(module_obj, func_name):
                func = getattr(module_obj, func_name)
                if callable(func):
                    return func
        
        # Return the module itself as fallback
        return module_obj
    
    def _instantiate_class(self, cls: type, target: str, config: Dict) -> Any:
        """Instantiate a class with intelligent parameter injection.
        
        Tries to inject engine, target, and config parameters based on
        what the class constructor accepts.
        """
        sig = inspect.signature(cls.__init__)
        params = sig.parameters
        
        kwargs = {}
        
        # Check what parameters the class accepts
        if 'target' in params:
            kwargs['target'] = target
        if 'config' in params:
            kwargs['config'] = config
        if 'engine' in params:
            kwargs['engine'] = self
        
        try:
            instance = cls(**kwargs)
            self._logger.debug(f"Instantiated {cls.__name__} with {kwargs.keys()}")
            return instance
        except Exception as e:
            self._logger.warning(f"Error instantiating {cls.__name__} with {kwargs}: {e}, trying without args")
            # Fallback: try instantiating without args
            return cls()
    
    def _call_entrypoint(self, entrypoint: Any, target: str, config: Optional[Dict] = None, **kwargs) -> Any:
        """Call an entrypoint with intelligent parameter injection.
        
        Args:
            entrypoint: The callable or object to invoke
            target: Target for the scan
            config: Optional configuration
            **kwargs: Additional keyword arguments
        
        Returns:
            Result from the entrypoint
        """
        config = config or self.config
        
        # If entrypoint is a class instance, look for methods
        if not callable(entrypoint):
            for method_name in ['run', 'scan', 'gather', 'main']:
                if hasattr(entrypoint, method_name):
                    method = getattr(entrypoint, method_name)
                    if callable(method):
                        entrypoint = method
                        break
        
        if not callable(entrypoint):
            raise TypeError(f"Entrypoint is not callable: {entrypoint}")
        
        # Determine what parameters the entrypoint accepts
        try:
            sig = inspect.signature(entrypoint)
            params = sig.parameters
            
            call_kwargs = {}
            
            # Inject parameters based on signature
            if 'target' in params:
                call_kwargs['target'] = target
            if 'config' in params:
                call_kwargs['config'] = config
            if 'engine' in params:
                call_kwargs['engine'] = self
            
            # Add any additional kwargs that match parameter names
            for key, value in kwargs.items():
                if key in params:
                    call_kwargs[key] = value
            
            # Call the entrypoint
            result = entrypoint(**call_kwargs)
            return result
        except Exception as e:
            self._logger.warning(f"Error calling with signature injection: {e}, trying direct call")
            # Fallback: try calling with target only
            try:
                return entrypoint(target)
            except Exception:
                # Last resort: call with no args
                return entrypoint()

    # --- module execution ---
    async def run_module_async(
        self,
        module_name: str,
        target: str,
        config: Optional[Dict] = None,
        callback: Optional[Callable] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """Run a module asynchronously.
        
        Supports async modules with async context managers and async entrypoints.
        
        Args:
            module_name: Name of the module to run
            target: Target for the scan
            config: Optional configuration
            callback: Optional callback(module_name, result) to call with results
            **kwargs: Additional arguments to pass to the module
        
        Returns:
            Dictionary with module results
        """
        start_time = time.time()
        result = {
            'module': module_name,
            'target': target,
            'status': 'unknown',
            'result': None,
            'error': None,
            'duration': 0
        }
        
        try:
            # Load the module
            module_obj = self.load_module(module_name)
            
            # Resolve entrypoint
            entrypoint = self._resolve_entrypoint(module_obj, target, config)
            
            # Check if entrypoint is an async context manager
            if hasattr(entrypoint, '__aenter__') and hasattr(entrypoint, '__aexit__'):
                async with entrypoint as ctx:
                    # Look for async methods in the context
                    for method_name in ['gather', 'run', 'scan', 'main']:
                        if hasattr(ctx, method_name):
                            method = getattr(ctx, method_name)
                            if inspect.iscoroutinefunction(method):
                                result['result'] = await method()
                                result['status'] = 'success'
                                break
                            elif callable(method):
                                result['result'] = method()
                                result['status'] = 'success'
                                break
            # Check if entrypoint itself is a coroutine function
            elif inspect.iscoroutinefunction(entrypoint):
                result['result'] = await self._call_entrypoint_async(entrypoint, target, config, **kwargs)
                result['status'] = 'success'
            # Fallback to sync execution
            else:
                result['result'] = self._call_entrypoint(entrypoint, target, config, **kwargs)
                result['status'] = 'success'
        
        except Exception as e:
            self._logger.exception(f"Error running module {module_name}: {e}")
            result['status'] = 'error'
            result['error'] = str(e)
        
        finally:
            result['duration'] = time.time() - start_time
            
            if callback:
                try:
                    callback(module_name, result)
                except Exception as e:
                    self._logger.error(f"Error in callback for {module_name}: {e}")
        
        return result
    
    def run_module(
        self,
        module_name: str,
        target: str,
        config: Optional[Dict] = None,
        callback: Optional[Callable] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """Run a module synchronously.
        
        This method handles both sync and async modules by running async modules
        in an event loop.
        
        Args:
            module_name: Name of the module to run
            target: Target for the scan
            config: Optional configuration
            callback: Optional callback(module_name, result) to call with results
            **kwargs: Additional arguments to pass to the module
        
        Returns:
            Dictionary with module results
        """
        # Check if there's an existing event loop
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # We're already in an async context, create a new task
                return asyncio.create_task(
                    self.run_module_async(module_name, target, config, callback, **kwargs)
                )
        except RuntimeError:
            # No event loop exists, we'll create one
            pass
        
        # Run in a new event loop
        return asyncio.run(self.run_module_async(module_name, target, config, callback, **kwargs))
    
    async def _call_entrypoint_async(self, entrypoint: Any, target: str, config: Optional[Dict] = None, **kwargs) -> Any:
        """Call an async entrypoint with intelligent parameter injection."""
        config = config or self.config
        
        try:
            sig = inspect.signature(entrypoint)
            params = sig.parameters
            
            call_kwargs = {}
            
            if 'target' in params:
                call_kwargs['target'] = target
            if 'config' in params:
                call_kwargs['config'] = config
            if 'engine' in params:
                call_kwargs['engine'] = self
            
            for key, value in kwargs.items():
                if key in params:
                    call_kwargs[key] = value
            
            return await entrypoint(**call_kwargs)
        except Exception as e:
            self._logger.warning(f"Error calling async entrypoint: {e}, trying fallback")
            try:
                return await entrypoint(target)
            except Exception:
                return await entrypoint()
    
    def run_modules(
        self,
        module_names: List[str],
        target: str,
        config: Optional[Dict] = None,
        callback: Optional[Callable] = None,
        **kwargs
    ) -> Dict[str, Dict[str, Any]]:
        """Run multiple modules against a target.
        
        Args:
            module_names: List of module names to run
            target: Target for the scan
            config: Optional configuration
            callback: Optional callback(module_name, result) for each module
            **kwargs: Additional arguments to pass to modules
        
        Returns:
            Dictionary mapping module names to their results
        
        Note: If called from within an async context, this will schedule
        execution but return immediately. Use await with run_modules_async
        instead for async contexts.
        """
        async def _run_all():
            tasks = [
                self.run_module_async(name, target, config, callback, **kwargs)
                for name in module_names
            ]
            results_list = await asyncio.gather(*tasks, return_exceptions=True)
            
            results = {}
            for i, name in enumerate(module_names):
                if isinstance(results_list[i], Exception):
                    results[name] = {
                        'module': name,
                        'target': target,
                        'status': 'error',
                        'error': str(results_list[i]),
                        'result': None
                    }
                else:
                    results[name] = results_list[i]
            
            return results
        
        # Check if there's an existing event loop running
        try:
            loop = asyncio.get_running_loop()
            # We're in an async context - warn and run in thread pool
            self._logger.warning(
                "run_modules called from async context - results may be delayed. "
                "Consider using async/await pattern instead."
            )
            # Run in thread pool to avoid blocking
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(asyncio.run, _run_all())
                return future.result()
        except RuntimeError:
            # No event loop, safe to create one
            return asyncio.run(_run_all())
    
    def run_all_modules(
        self,
        target: str,
        config: Optional[Dict] = None,
        callback: Optional[Callable] = None,
        **kwargs
    ) -> Dict[str, Dict[str, Any]]:
        """Run all discovered modules against a target.
        
        Args:
            target: Target for the scan
            config: Optional configuration
            callback: Optional callback(module_name, result) for each module
            **kwargs: Additional arguments to pass to modules
        
        Returns:
            Dictionary mapping module names to their results
        """
        module_names = self.get_available_modules()
        return self.run_modules(module_names, target, config, callback, **kwargs)
    
    def save_results(self, results: Dict[str, Any], output_path: Optional[str] = None) -> str:
        """Save scan results to a JSON file.
        
        Args:
            results: Results dictionary to save
            output_path: Optional output file path. If not provided, generates one.
        
        Returns:
            Path to the saved file
        """
        import json
        from datetime import datetime
        
        if output_path is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_path = f"redhawk_results_{timestamp}.json"
        
        try:
            with open(output_path, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            self._logger.info(f"Results saved to {output_path}")
            return output_path
        except Exception as e:
            self._logger.error(f"Error saving results: {e}")
            raise
    # --- legacy task registry (backwards compatibility) ---
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
    def configure(self, *, max_workers: Optional[int] = None, name: Optional[str] = None, modules_dir: Optional[str] = None) -> None:
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
        if modules_dir:
            self.modules_dir = modules_dir
            self._logger.debug("Configured modules_dir=%s", self.modules_dir)

    @classmethod
    def from_config(cls, cfg: Mapping[str, Any]) -> "Engine":
        """Construct an Engine from a mapping-like config.

        Recognized keys: name, max_workers, logger, config, modules_dir.
        """
        name = cfg.get("name", DEFAULT_NAME)
        max_workers = cfg.get("max_workers", DEFAULT_WORKERS)
        logger = cfg.get("logger")
        config = cfg.get("config")
        modules_dir = cfg.get("modules_dir")
        return cls(name=name, max_workers=max_workers, logger=logger, config=config, modules_dir=modules_dir)

    # --- utilities ---
    def status(self) -> Dict[str, Any]:
        """Return a snapshot of engine status useful for health checks."""
        return {
            "name": self.name,
            "running": bool(self._running),
            "registered_tasks": list(self._tasks.keys()),
            "tasks_count": len(self._tasks),
            "loaded_modules": list(self._modules.keys()),
            "modules_count": len(self._modules),
            "available_modules": len(self.get_available_modules()),
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
