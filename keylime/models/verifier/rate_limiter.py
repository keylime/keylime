"""Rate limiting for API endpoints to prevent DoS attacks.

This module provides rate limiting functionality using shared memory for
multiprocess coordination, consistent with Keylime's existing shared memory
infrastructure for session management.
"""

import time
from typing import Optional, Tuple

from keylime.shared_data import get_shared_memory


class RateLimiter:
    """Rate limiter using shared memory for multiprocess coordination."""

    @staticmethod
    def check_rate_limit(identifier: str, max_requests: int, window_seconds: int) -> Tuple[bool, Optional[int]]:
        """Check if request is within rate limit.

        Args:
            identifier: Unique identifier for the rate limit (e.g., "ip:1.2.3.4" or "agent:agent1")
            max_requests: Maximum requests allowed in the time window
            window_seconds: Time window in seconds

        Returns:
            Tuple of (allowed: bool, retry_after_seconds: Optional[int])
            - allowed: True if request should be allowed
            - retry_after_seconds: If blocked, number of seconds to wait
        """
        shared_memory = get_shared_memory()
        rate_limits = shared_memory.get_or_create_dict("rate_limits")
        now = time.time()

        key = f"session_create:{identifier}"
        limit_data = rate_limits.get(key, {"requests": [], "blocked_until": None})

        # Check if currently blocked
        if limit_data.get("blocked_until") and limit_data["blocked_until"] > now:
            return False, int(limit_data["blocked_until"] - now)

        # Clean old requests outside window
        requests = [ts for ts in limit_data.get("requests", []) if ts > now - window_seconds]

        # Check if over limit
        if len(requests) >= max_requests:
            # Block for escalating duration (exponential backoff)
            block_count = limit_data.get("block_count", 0) + 1
            block_duration = min(60 * (2 ** (block_count - 1)), 3600)  # Max 1 hour
            limit_data["blocked_until"] = now + block_duration
            limit_data["block_count"] = block_count
            limit_data["requests"] = requests
            rate_limits[key] = limit_data
            return False, block_duration

        # Allow request and record timestamp
        requests.append(now)
        rate_limits[key] = {
            "requests": requests,
            "block_count": limit_data.get("block_count", 0),
            "blocked_until": None,
        }
        return True, None

    @staticmethod
    def cleanup_old_entries(max_age_seconds: int = 3600):
        """Clean up old rate limit entries from shared memory.

        Should be called periodically to prevent unbounded memory growth.

        Args:
            max_age_seconds: Remove entries with no requests newer than this age
        """
        shared_memory = get_shared_memory()
        rate_limits = shared_memory.get_or_create_dict("rate_limits")
        now = time.time()

        keys_to_delete = []
        for key, limit_data in list(rate_limits.items()):
            # Check if all requests are old and not currently blocked
            requests = limit_data.get("requests", [])
            blocked_until = limit_data.get("blocked_until")

            if not requests or (max(requests) < now - max_age_seconds and (not blocked_until or blocked_until < now)):
                keys_to_delete.append(key)

        for key in keys_to_delete:
            del rate_limits[key]
