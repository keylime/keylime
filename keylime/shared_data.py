"""Shared memory management for keylime multiprocess applications.

This module provides thread-safe shared data management between processes
using multiprocessing.Manager().
"""

import atexit
import multiprocessing as mp
import multiprocessing.process
import os
import signal
import threading
import time
from multiprocessing.managers import SyncManager
from typing import Any, Dict, List, Optional

from keylime import keylime_logging

logger = keylime_logging.init_logging("shared_data")

_RUNTIME_DIR = "/var/run/keylime"


def _ensure_runtime_dir() -> None:
    """Ensure the runtime directory exists with correct permissions.

    Under systemd, ``tmpfiles.d`` creates ``/var/run/keylime/`` at boot.
    This function provides a fallback for non-systemd execution and
    validates permissions in either case.
    """
    os.makedirs(_RUNTIME_DIR, mode=0o700, exist_ok=True)
    perms = os.stat(_RUNTIME_DIR).st_mode & 0o777
    if perms != 0o700 or not os.access(_RUNTIME_DIR, os.W_OK | os.X_OK):
        msg = f"{_RUNTIME_DIR} is not usable by the current process"
        logger.error(msg)
        raise PermissionError(msg)


def _manager_ignore_signals() -> None:
    """Ignore SIGTERM and SIGINT in the Manager's server process.

    Called as the ``initializer`` for ``SyncManager.start()`` so that
    the Manager survives process-group signals (systemd SIGTERM, Ctrl+C)
    and stays available while workers drain in-flight work.
    """
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    signal.signal(signal.SIGINT, signal.SIG_IGN)


class FlatDictView:
    """A dictionary-like view over a flat key-value store.

    This class provides dict-like access to a subset of keys in a flat store,
    identified by a namespace prefix. This avoids the nested DictProxy issues.

    Example:
        store = manager.dict()  # Flat store
        view = FlatDictView(store, lock, "sessions")
        view["123"] = "data"  # Stores as "dict:sessions:123" in flat store
        val = view["123"]  # Retrieves from "dict:sessions:123"
    """

    def __init__(self, store: Any, lock: Any, namespace: str) -> None:
        self._store = store
        self._lock = lock
        self._namespace = namespace

    def _make_key(self, key: Any) -> str:
        """Convert user key to internal flat key with namespace prefix."""
        return f"dict:{self._namespace}:{key}"

    def __getitem__(self, key: Any) -> Any:
        with self._lock:
            return self._store[self._make_key(key)]

    def __setitem__(self, key: Any, value: Any) -> None:
        flat_key = self._make_key(key)
        with self._lock:
            self._store[flat_key] = value

    def __delitem__(self, key: Any) -> None:
        flat_key = self._make_key(key)
        with self._lock:
            del self._store[flat_key]

    def __contains__(self, key: Any) -> bool:
        return self._make_key(key) in self._store

    def get(self, key: Any, default: Any = None) -> Any:
        with self._lock:
            return self._store.get(self._make_key(key), default)

    def pop(self, key: Any, default: Any = None) -> Any:
        """Remove and return value for key, or default if key not present."""
        flat_key = self._make_key(key)
        with self._lock:
            return self._store.pop(flat_key, default)

    def keys(self) -> List[Any]:
        """Return keys in this namespace."""
        prefix = f"dict:{self._namespace}:"
        all_store_keys = list(self._store.keys())
        matching_keys = [k[len(prefix) :] for k in all_store_keys if k.startswith(prefix)]
        return matching_keys

    def values(self) -> List[Any]:
        """Return values in this namespace."""
        prefix = f"dict:{self._namespace}:"
        with self._lock:
            return [v for k, v in self._store.items() if k.startswith(prefix)]

    def items(self) -> List[tuple[Any, Any]]:
        """Return (key, value) pairs in this namespace."""
        prefix = f"dict:{self._namespace}:"
        with self._lock:
            result = [(k[len(prefix) :], v) for k, v in self._store.items() if k.startswith(prefix)]
            return result

    def __len__(self) -> int:
        """Return number of items in this namespace."""
        return len(self.keys())

    def __repr__(self) -> str:
        return f"FlatDictView({self._namespace}, {len(self)} items)"


class SharedDataManager:
    """Thread-safe shared data manager for multiprocess applications.

    This class uses multiprocessing.Manager() to create proxy objects that can
    be safely accessed from multiple processes. All data stored must be pickleable.

    Example:
        manager = SharedDataManager()

        # Store simple data
        manager.set_data("config_value", "some_config")
        value = manager.get_data("config_value")

        # Work with shared dictionaries
        agent_cache = manager.get_or_create_dict("agent_cache")
        agent_cache["agent_123"] = {"last_seen": time.time()}

        # Work with shared lists
        event_log = manager.get_or_create_list("events")
        event_log.append({"type": "attestation", "agent": "agent_123"})
    """

    def __init__(self) -> None:
        """Initialize the shared data manager.

        This must be called before any process forking occurs to ensure
        all child processes inherit access to the shared data.
        """
        logger.debug("Initializing SharedDataManager")

        # Ensure /var/run/keylime/ exists with correct permissions
        # before forking the Manager server process.
        _ensure_runtime_dir()
        self._socket_path = os.path.join(_RUNTIME_DIR, f"shared_data.{os.getpid()}.sock")

        # Remove stale socket from a previous run (e.g. after a crash).
        # CPython's SocketListener does not pre-unlink before bind().
        try:
            os.unlink(self._socket_path)
        except (FileNotFoundError, PermissionError):
            pass

        # Use explicit context to ensure fork compatibility.
        # The Manager must be started BEFORE any fork() calls.
        ctx = mp.get_context("fork")
        # Use SyncManager directly (instead of the ctx.Manager() shortcut)
        # so we can pass an initializer that makes the Manager's server
        # process ignore SIGTERM and SIGINT.  Without this, systemd's
        # cgroup-wide SIGTERM (or Ctrl+C SIGINT in foreground) kills the
        # Manager before workers finish draining, causing
        # ConnectionResetError in proxy objects.  The Manager is still
        # cleanable via IPC shutdown message, process.kill(), or systemd
        # SIGKILL escalation.
        # Cannot use 'with' context manager here: the Manager must outlive
        # __init__ and persist for the lifetime of SharedDataManager.
        self._manager = SyncManager(address=self._socket_path, ctx=ctx)
        self._manager.start(  # pylint: disable=consider-using-with
            initializer=_manager_ignore_signals,
        )

        # CRITICAL FIX: Use a SINGLE flat dict instead of nested dicts
        # Nested DictProxy objects have synchronization issues
        # We'll use key prefixes like "dict:auth_sessions:session_id" instead
        self._store = self._manager.dict()  # Single flat store for all data
        self._lock = self._manager.Lock()
        self._initialized_at = time.time()

        try:
            self._parent_pid = os.getpid()
            logger.debug("SharedDataManager initialized in process %d", self._parent_pid)
        except Exception as e:
            logger.warning("Could not register PID tracking: %s", e)

        # Ensure cleanup on exit
        atexit.register(self.cleanup)

        logger.info(
            "SharedDataManager initialized successfully (socket: %s)",
            self._socket_path,
        )

    def set_data(self, key: str, value: Any) -> None:
        """Store arbitrary pickleable data by key.

        Args:
            key: Unique identifier for the data
            value: Any pickleable Python object

        Raises:
            TypeError: If value is not pickleable
        """
        with self._lock:
            try:
                self._store[key] = value
                logger.debug("Stored data for key: %s", key)
            except Exception as e:
                logger.error("Failed to store data for key '%s': %s", key, e)
                raise

    def get_data(self, key: str, default: Any = None) -> Any:
        """Retrieve data by key.

        Args:
            key: The key to retrieve
            default: Value to return if key doesn't exist

        Returns:
            The stored value or default if key doesn't exist
        """
        with self._lock:
            value = self._store.get(key, default)
            logger.debug("Retrieved data for key: %s (found: %s)", key, value is not default)
            return value

    def get_or_create_dict(self, key: str) -> Dict[str, Any]:
        """Get or create a shared dictionary.

        Args:
            key: Unique identifier for the dictionary

        Returns:
            A shared dictionary-like object that syncs across processes

        Note:
            Returns a FlatDictView that uses key prefixes in the flat store
            instead of actual nested dicts, to avoid DictProxy nesting issues.
        """
        # Mark that this namespace exists
        namespace_key = f"__namespace__{key}"
        if namespace_key not in self._store:
            with self._lock:
                self._store[namespace_key] = True

        # Return a view that operates on the flat store with key prefix
        return FlatDictView(self._store, self._lock, key)  # type: ignore[return-value,no-untyped-call]

    def get_or_create_list(self, key: str) -> List[Any]:
        """Get or create a shared list.

        Args:
            key: Unique identifier for the list

        Returns:
            A shared list (proxy object) that syncs across processes
        """
        with self._lock:
            if key not in self._store:
                self._store[key] = self._manager.list()
                logger.debug("Created new shared list for key: %s", key)
            else:
                logger.debug("Retrieved existing shared list for key: %s", key)
            return self._store[key]  # type: ignore[no-any-return]

    def delete_data(self, key: str) -> bool:
        """Delete data by key.

        Args:
            key: The key to delete

        Returns:
            True if the key existed and was deleted, False otherwise
        """
        with self._lock:
            if key in self._store:
                del self._store[key]
                logger.debug("Deleted data for key: %s", key)
                return True
            logger.debug("Key not found for deletion: %s", key)
            return False

    def has_key(self, key: str) -> bool:
        """Check if a key exists.

        Args:
            key: The key to check

        Returns:
            True if key exists, False otherwise
        """
        with self._lock:
            return key in self._store

    def get_keys(self) -> List[str]:
        """Get all stored keys.

        Returns:
            List of all keys in the store
        """
        with self._lock:
            return list(self._store.keys())

    def clear_all(self) -> None:
        """Clear all stored data. Use with caution!"""
        with self._lock:
            key_count = len(self._store)
            self._store.clear()
            logger.warning("Cleared all shared data (%d keys)", key_count)

    def get_stats(self) -> Dict[str, Any]:
        """Get statistics about stored data.

        Returns:
            Dictionary containing storage statistics
        """
        with self._lock:
            return {
                "total_keys": len(self._store),
                "initialized_at": self._initialized_at,
                "uptime_seconds": time.time() - self._initialized_at,
            }

    def cleanup(self) -> None:
        """Cleanup shared resources.

        This is automatically called on exit but can be called manually
        for explicit cleanup.  Only the parent process (the one that
        created the Manager) is allowed to shut it down; child workers
        forked from the parent skip the call to avoid the
        ``AssertionError: can only join a child process`` raised by
        ``multiprocessing`` when a non-parent tries to join.
        """
        if not hasattr(self, "_manager"):
            return

        if hasattr(self, "_parent_pid") and os.getpid() != self._parent_pid:
            logger.debug(
                "Skipping SharedDataManager shutdown in child process %d (parent is %d)",
                os.getpid(),
                self._parent_pid,
            )
            return

        logger.debug("Shutting down SharedDataManager")
        try:
            self._manager.shutdown()
            logger.info("SharedDataManager shutdown complete")
        except Exception:
            logger.exception("Error during SharedDataManager shutdown")

        # Remove socket file if it still exists.  The Manager server
        # process normally unlinks it on exit, but if it was killed
        # (SIGKILL) the file may be left behind.
        socket_path = getattr(self, "_socket_path", None)
        if socket_path:
            try:
                os.unlink(socket_path)
            except FileNotFoundError:
                pass
            except OSError as e:
                logger.debug("Could not remove socket file %s: %s", socket_path, e)

    def deregister_child(self) -> None:
        """Remove the Manager's server process from multiprocessing's child tracking.

        Must be called in each forked worker **after** ``fork()``.  Without
        this, Python's ``multiprocessing.util._exit_function`` atexit handler
        tries to ``join()`` the Manager server process in every child worker,
        causing ``AssertionError: can only join a child process`` because the
        Manager was spawned by the parent, not the child.
        """
        # The Manager's server process is stored in _manager._process
        server_process = getattr(self._manager, "_process", None)
        if server_process is not None:
            multiprocessing.process._children.discard(server_process)  # type: ignore[attr-defined]  # pylint: disable=protected-access
            logger.debug(
                "Deregistered Manager server process (pid %s) from child tracking in worker %d",
                getattr(server_process, "pid", "?"),
                os.getpid(),
            )

    def __repr__(self) -> str:
        stats = self.get_stats()
        return f"SharedDataManager(keys={stats['total_keys']}, " f"uptime={stats['uptime_seconds']:.1f}s)"

    @property
    def manager(self) -> Any:  # type: ignore[misc]
        """Access to the underlying multiprocessing Manager for advanced usage."""
        return self._manager


# Global shared memory manager instance
_global_shared_manager: Optional[SharedDataManager] = None
_manager_lock = threading.Lock()


def initialize_shared_memory() -> SharedDataManager:
    """Initialize the global shared memory manager.

    This function MUST be called before any process forking occurs to ensure
    all child processes share the same manager instance.

    For tornado/multiprocess servers, call this before starting workers.

    Returns:
        SharedDataManager: The global shared memory manager instance

    Raises:
        RuntimeError: If called after manager is already initialized
    """
    global _global_shared_manager

    with _manager_lock:
        if _global_shared_manager is not None:
            logger.warning("Shared memory manager already initialized, returning existing instance")
            return _global_shared_manager

        logger.info("Initializing global shared memory manager")
        _global_shared_manager = SharedDataManager()
        logger.info("Global shared memory manager initialized")

    return _global_shared_manager


def get_shared_memory() -> SharedDataManager:
    """Get the global shared memory manager instance.

    This function returns a singleton SharedDataManager that can be used
    throughout keylime for caching and inter-process communication.

    The manager is automatically initialized on first access and cleaned up
    on process exit.

    IMPORTANT: In multiprocess applications (like tornado with workers),
    you MUST call initialize_shared_memory() BEFORE forking workers.
    Otherwise each worker will get its own separate manager.

    Returns:
        SharedDataManager: The global shared memory manager instance
    """
    global _global_shared_manager

    if _global_shared_manager is None:
        with _manager_lock:
            if _global_shared_manager is None:
                logger.info("Initializing global shared memory manager")
                _global_shared_manager = SharedDataManager()  # type: ignore[no-untyped-call]
                logger.info("Global shared memory manager initialized")

    return _global_shared_manager


def deregister_shared_memory_child() -> None:
    """Deregister the Manager's server process in a forked child worker.

    Call this after ``tornado.process.fork_processes()`` (or any ``fork()``)
    to prevent Python's atexit handler from trying to ``join()`` the Manager
    server process in the child, which would raise
    ``AssertionError: can only join a child process``.
    """
    if _global_shared_manager is not None:
        _global_shared_manager.deregister_child()


def cleanup_global_shared_memory() -> None:
    """Cleanup the global shared memory manager.

    This is automatically called on exit but can be called manually.
    """
    global _global_shared_manager

    if _global_shared_manager is not None:
        logger.info("Cleaning up global shared memory manager")
        _global_shared_manager.cleanup()
        _global_shared_manager = None


# Convenience functions for common keylime patterns


def cache_policy(agent_id: str, checksum: str, policy: str) -> None:
    """Cache a policy in shared memory.

    Args:
        agent_id: The agent identifier
        checksum: The policy checksum
        policy: The policy content to cache
    """
    manager = get_shared_memory()
    policy_cache = manager.get_or_create_dict("policy_cache")

    if agent_id not in policy_cache:
        policy_cache[agent_id] = manager.manager.dict()  # type: ignore[attr-defined]

    policy_cache[agent_id][checksum] = policy
    logger.debug("Cached policy for agent %s with checksum %s", agent_id, checksum)


def get_cached_policy(agent_id: str, checksum: str) -> Optional[str]:
    """Retrieve cached policy.

    Args:
        agent_id: The agent identifier
        checksum: The policy checksum

    Returns:
        The cached policy content or None if not found
    """
    manager = get_shared_memory()
    policy_cache = manager.get_or_create_dict("policy_cache")
    agent_policies = policy_cache.get(agent_id, {})

    result = agent_policies.get(checksum)
    if result:
        logger.debug("Found cached policy for agent %s with checksum %s", agent_id, checksum)
    else:
        logger.debug("No cached policy found for agent %s with checksum %s", agent_id, checksum)

    return result  # type: ignore[no-any-return]


def clear_agent_policy_cache(agent_id: str) -> None:
    """Clear all cached policies for an agent.

    Args:
        agent_id: The agent identifier
    """
    manager = get_shared_memory()
    policy_cache = manager.get_or_create_dict("policy_cache")

    if agent_id in policy_cache:
        del policy_cache[agent_id]
        logger.debug("Cleared policy cache for agent %s", agent_id)


def cleanup_agent_policy_cache(agent_id: str, keep_checksum: str = "") -> None:
    """Clean up agent policy cache, keeping only the specified checksum.

    This mimics the cleanup behavior from GLOBAL_POLICY_CACHE where when
    a new policy checksum is encountered, old cached policies are removed.

    Args:
        agent_id: The agent identifier
        keep_checksum: The checksum to keep in the cache (empty string by default)
    """
    manager = get_shared_memory()
    policy_cache = manager.get_or_create_dict("policy_cache")

    if agent_id in policy_cache and len(policy_cache[agent_id]) > 1:
        # Keep only the empty entry and the specified checksum
        old_policies = dict(policy_cache[agent_id])
        policy_cache[agent_id] = manager.manager.dict()

        # Always keep the empty entry
        policy_cache[agent_id][""] = old_policies.get("", "")

        # Keep the specified checksum if it exists and is not empty
        if keep_checksum and keep_checksum in old_policies:
            policy_cache[agent_id][keep_checksum] = old_policies[keep_checksum]

        logger.debug("Cleaned up policy cache for agent %s, keeping checksum %s", agent_id, keep_checksum)


def initialize_agent_policy_cache(agent_id: str) -> Dict[str, Any]:
    """Initialize policy cache for an agent if it doesn't exist.

    Args:
        agent_id: The agent identifier

    Returns:
        The agent's policy cache dictionary
    """
    manager = get_shared_memory()
    policy_cache = manager.get_or_create_dict("policy_cache")

    if agent_id not in policy_cache:
        policy_cache[agent_id] = manager.manager.dict()  # type: ignore[attr-defined]
        policy_cache[agent_id][""] = ""
        logger.debug("Initialized policy cache for agent %s", agent_id)

    return policy_cache[agent_id]  # type: ignore[no-any-return]


def get_agent_cache(agent_id: str) -> Dict[str, Any]:
    """Get shared cache for a specific agent.

    Args:
        agent_id: The agent identifier

    Returns:
        A shared dictionary for caching agent-specific data
    """
    manager = get_shared_memory()
    return manager.get_or_create_dict(f"agent_cache:{agent_id}")


def get_verification_queue(agent_id: str) -> List[Any]:
    """Get verification queue for batching database operations.

    Args:
        agent_id: The agent identifier

    Returns:
        A shared list for queuing verification operations
    """
    manager = get_shared_memory()
    return manager.get_or_create_list(f"verification_queue:{agent_id}")


def get_shared_stats() -> Dict[str, Any]:
    """Get statistics about shared memory usage.

    Returns:
        Dictionary containing storage statistics
    """
    manager = get_shared_memory()
    return manager.get_stats()
