import unittest

from keylime.ima.ima import EMPTY_RUNTIME_POLICY
from keylime.ima.policy import CompiledRegexList, EvalResult, IMAPolicy, IMAPolicyError


class CompiledRegexListTest(unittest.TestCase):
    def test_excludelist(self) -> None:
        exclude_list = ["/var/log", "/tmp", "/var/lib/containers", "/path/"]
        crl = CompiledRegexList.from_excludelist(exclude_list)
        self.assertEqual(len(crl), 1)

        self.assertEqual(crl.eval("/var/log/test"), EvalResult.ACCEPT)
        self.assertEqual(crl.eval("/tmp/test"), EvalResult.ACCEPT)
        self.assertEqual(crl.eval("/var/lib/containers/"), EvalResult.ACCEPT)
        self.assertEqual(crl.eval("/foo"), EvalResult.SKIP)
        self.assertEqual(crl.eval("/path"), EvalResult.SKIP)

    def test_regexlist(self) -> None:
        regex_list = ["ACCEPT:/var/log/foo/", "REJECT:/var/log/", "REJECT:/var/lib", "ACCEPT:/tmp"]
        crl = CompiledRegexList.from_list(regex_list)
        self.assertEqual(len(crl), 3)

        self.assertEqual(crl.eval("/var/log/foo/"), EvalResult.ACCEPT)
        self.assertEqual(crl.eval("/var/log/bar"), EvalResult.REJECT)
        self.assertEqual(crl.eval("/var/lib"), EvalResult.REJECT)
        self.assertEqual(crl.eval("/tmp"), EvalResult.ACCEPT)


class IMAPolicyTest(unittest.TestCase):
    def test_empty_policy(self) -> None:
        ima_policy = IMAPolicy.from_runtime_policy(EMPTY_RUNTIME_POLICY)

        exclude_list = ima_policy.get_regex_list("excludes")
        self.assertIsInstance(exclude_list, CompiledRegexList)
        assert isinstance(exclude_list, CompiledRegexList)  # for pyright
        self.assertEqual(len(exclude_list), 0)

        self.assertIsInstance(ima_policy.get_map("digests"), type({}))
        self.assertIsInstance(ima_policy.get_map("rejects"), type({}))
        with self.assertRaises(IMAPolicyError):
            ima_policy.get_map("foobar")

        self.assertIsInstance(ima_policy.get_regex_list("filters"), CompiledRegexList)
        with self.assertRaises(IMAPolicyError):
            ima_policy.get_regex_list("foobar")
