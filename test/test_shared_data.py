"""Unit tests for shared memory infrastructure."""

import unittest

from keylime.shared_data import (
    SharedDataManager,
    cache_policy,
    cleanup_agent_policy_cache,
    cleanup_global_shared_memory,
    clear_agent_policy_cache,
    get_cached_policy,
    get_shared_memory,
    initialize_agent_policy_cache,
)


class TestSharedDataManager(unittest.TestCase):
    """Test cases for SharedDataManager class."""

    def setUp(self):
        """Set up test fixtures."""
        self.manager = SharedDataManager()

    def tearDown(self):
        """Clean up after tests."""
        if self.manager:
            self.manager.cleanup()

    def test_set_and_get_data(self):
        """Test basic set and get operations."""
        self.manager.set_data("test_key", "test_value")
        result = self.manager.get_data("test_key")
        self.assertEqual(result, "test_value")

    def test_get_nonexistent_data(self):
        """Test getting data that doesn't exist returns None."""
        result = self.manager.get_data("nonexistent_key")
        self.assertIsNone(result)

    def test_get_data_with_default(self):
        """Test getting data with default value."""
        result = self.manager.get_data("nonexistent_key", default="default_value")
        self.assertEqual(result, "default_value")

    def test_delete_data(self):
        """Test deleting data."""
        self.manager.set_data("test_key", "test_value")
        result = self.manager.delete_data("test_key")
        self.assertTrue(result)

        # Verify it's actually deleted
        self.assertIsNone(self.manager.get_data("test_key"))

    def test_delete_nonexistent_data(self):
        """Test deleting data that doesn't exist returns False."""
        result = self.manager.delete_data("nonexistent_key")
        self.assertFalse(result)

    def test_has_key(self):
        """Test checking if key exists."""
        self.manager.set_data("test_key", "test_value")
        self.assertTrue(self.manager.has_key("test_key"))
        self.assertFalse(self.manager.has_key("nonexistent_key"))

    def test_get_or_create_dict(self):
        """Test getting or creating a shared dictionary."""
        shared_dict = self.manager.get_or_create_dict("test_dict")
        shared_dict["key1"] = "value1"
        shared_dict["key2"] = "value2"

        # Retrieve the same dict
        retrieved_dict = self.manager.get_or_create_dict("test_dict")
        self.assertEqual(retrieved_dict["key1"], "value1")
        self.assertEqual(retrieved_dict["key2"], "value2")

    def test_get_or_create_list(self):
        """Test getting or creating a shared list."""
        shared_list = self.manager.get_or_create_list("test_list")
        shared_list.append("item1")
        shared_list.append("item2")

        # Retrieve the same list
        retrieved_list = self.manager.get_or_create_list("test_list")
        self.assertEqual(len(retrieved_list), 2)
        self.assertEqual(retrieved_list[0], "item1")
        self.assertEqual(retrieved_list[1], "item2")

    def test_get_stats(self):
        """Test getting manager statistics."""
        self.manager.set_data("key1", "value1")
        self.manager.set_data("key2", "value2")

        stats = self.manager.get_stats()
        self.assertIn("total_keys", stats)
        self.assertIn("uptime_seconds", stats)
        self.assertEqual(stats["total_keys"], 2)
        self.assertGreaterEqual(stats["uptime_seconds"], 0)


class TestPolicyCacheFunctions(unittest.TestCase):
    """Test cases for policy cache functions."""

    def setUp(self):
        """Set up test fixtures."""
        # Get the global shared memory manager
        self.manager = get_shared_memory()

    def tearDown(self):
        """Clean up after tests."""
        # Clean up global shared memory
        cleanup_global_shared_memory()

    def test_initialize_agent_policy_cache(self):
        """Test initializing agent policy cache."""
        agent_id = "test_agent_123"
        initialize_agent_policy_cache(agent_id)

        # Verify the cache was initialized
        policy_cache = self.manager.get_or_create_dict("policy_cache")
        self.assertIn(agent_id, policy_cache)

    def test_cache_and_get_policy(self):
        """Test caching and retrieving a policy."""
        agent_id = "test_agent_123"
        checksum = "abc123def456"
        policy_content = '{"policy": "test_policy_content"}'

        # Initialize and cache policy
        initialize_agent_policy_cache(agent_id)
        cache_policy(agent_id, checksum, policy_content)

        # Retrieve cached policy
        cached = get_cached_policy(agent_id, checksum)
        self.assertEqual(cached, policy_content)

    def test_get_nonexistent_cached_policy(self):
        """Test getting a policy that hasn't been cached."""
        agent_id = "test_agent_123"
        checksum = "nonexistent_checksum"

        initialize_agent_policy_cache(agent_id)
        cached = get_cached_policy(agent_id, checksum)
        self.assertIsNone(cached)

    def test_clear_agent_policy_cache(self):
        """Test clearing an agent's policy cache."""
        agent_id = "test_agent_123"
        checksum = "abc123def456"
        policy_content = '{"policy": "test_policy_content"}'

        # Initialize, cache, and then clear
        initialize_agent_policy_cache(agent_id)
        cache_policy(agent_id, checksum, policy_content)
        clear_agent_policy_cache(agent_id)

        # Verify it's cleared
        cached = get_cached_policy(agent_id, checksum)
        self.assertIsNone(cached)

    def test_cleanup_agent_policy_cache(self):
        """Test cleaning up old policy checksums."""
        agent_id = "test_agent_123"
        old_checksum = "old_checksum"
        new_checksum = "new_checksum"
        policy_content = '{"policy": "test"}'

        # Initialize and cache multiple policies
        initialize_agent_policy_cache(agent_id)
        cache_policy(agent_id, old_checksum, policy_content)
        cache_policy(agent_id, new_checksum, policy_content)

        # Cleanup old checksums (keeping only new_checksum)
        cleanup_agent_policy_cache(agent_id, new_checksum)

        # Verify old checksum is removed but new one remains
        self.assertIsNone(get_cached_policy(agent_id, old_checksum))
        self.assertEqual(get_cached_policy(agent_id, new_checksum), policy_content)

    def test_cache_multiple_agents(self):
        """Test caching policies for multiple agents."""
        agent1 = "agent_1"
        agent2 = "agent_2"
        checksum = "same_checksum"
        policy1 = '{"policy": "agent1_policy"}'
        policy2 = '{"policy": "agent2_policy"}'

        # Cache policies for different agents
        initialize_agent_policy_cache(agent1)
        initialize_agent_policy_cache(agent2)
        cache_policy(agent1, checksum, policy1)
        cache_policy(agent2, checksum, policy2)

        # Verify each agent has its own policy
        self.assertEqual(get_cached_policy(agent1, checksum), policy1)
        self.assertEqual(get_cached_policy(agent2, checksum), policy2)


if __name__ == "__main__":
    unittest.main()
