import io
import unittest
import zipfile

from keylime.tenant import UserError, check_action_list


def make_zip(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return zipfile.ZipFile(buf)


class TestCheckActionList(unittest.TestCase):
    def test_no_action_list(self):
        check_action_list(make_zip({"foo.txt": "x"}))

    def test_all_present(self):
        zf = make_zip(
            {"action_list": "local_action_a, local_action_b\n", "local_action_a.py": "", "local_action_b.py": ""}
        )
        check_action_list(zf)

    def test_missing_script(self):
        zf = make_zip({"action_list": "local_action_a,local_action_missing", "local_action_a.py": ""})
        with self.assertRaises(UserError) as ctx:
            check_action_list(zf)
        self.assertIn("local_action_missing.py", str(ctx.exception))

    def test_empty_entries_ignored(self):
        check_action_list(make_zip({"action_list": ",\n"}))


if __name__ == "__main__":
    unittest.main()
