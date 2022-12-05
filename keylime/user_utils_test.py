import unittest

from keylime import user_utils


class TestUserUtils(unittest.TestCase):
    def test_string_to_uidgid(self) -> None:
        uid, gid = user_utils.string_to_uidgid("root")
        self.assertTrue(isinstance(uid, int))
        self.assertTrue(gid is None)

        uid, gid = user_utils.string_to_uidgid("root:")
        self.assertTrue(isinstance(uid, int))
        self.assertTrue(gid is None)

        uid, gid = user_utils.string_to_uidgid(":root")
        self.assertTrue(uid is None)
        self.assertTrue(isinstance(gid, int))

        uid, gid = user_utils.string_to_uidgid("root:root")
        self.assertTrue(isinstance(uid, int))
        self.assertTrue(isinstance(gid, int))

        with self.assertRaises(ValueError):
            uid, gid = user_utils.string_to_uidgid(":")

        uid, gid = user_utils.string_to_uidgid("100")
        self.assertTrue(uid == 100)
        self.assertTrue(gid is None)

        uid, gid = user_utils.string_to_uidgid("100:")
        self.assertTrue(uid == 100)
        self.assertTrue(gid is None)

        uid, gid = user_utils.string_to_uidgid(":200")
        self.assertTrue(uid is None)
        self.assertTrue(gid == 200)

        uid, gid = user_utils.string_to_uidgid("100:200")
        self.assertTrue(uid == 100)
        self.assertTrue(gid == 200)

        with self.assertRaises(ValueError):
            uid, gid = user_utils.string_to_uidgid("-100:200")

        with self.assertRaises(ValueError):
            uid, gid = user_utils.string_to_uidgid("nobodyever")
