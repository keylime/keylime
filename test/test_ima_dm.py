# pylint: disable=protected-access
import unittest

from keylime.ima import ast, ima_dm

# Note that the tests depend also on ast parsing the raw data correctly.

# Test dm_table_load events for all supported targets
table_load_verity = ast.Entry(
    "10 fdcd389a7d084c7e1af8ed6917d080b1f0ee0625 ima-buf sha256:09e8a13203b10ce8d352aaafcdaf74986a6e2940e42c44c1a6603624135e1117 dm_table_load 646d5f76657273696f6e3d342e34352e303b6e616d653d746573742c757569643d43525950542d5645524954592d63373664303733343364336134396235616230313032356433623335346466352d746573742c6d616a6f723d3235332c6d696e6f723d302c6d696e6f725f636f756e743d312c6e756d5f746172676574733d313b7461726765745f696e6465783d302c7461726765745f626567696e3d302c7461726765745f6c656e3d3230343830382c7461726765745f6e616d653d7665726974792c7461726765745f76657273696f6e3d312e382e302c686173685f6661696c65643d562c7665726974795f76657273696f6e3d312c646174615f6465766963655f6e616d653d373a312c686173685f6465766963655f6e616d653d373a302c7665726974795f616c676f726974686d3d7368613235362c726f6f745f6469676573743d366561666665366238623031393930613165333937313236353734363865396237323263623634626139393432633664353836393438646131626434303936372c73616c743d643733386664396634323033663339376635613135353632633330323131393537303430636436373165666334363937313562663236383935363232656162632c69676e6f72655f7a65726f5f626c6f636b733d6e2c636865636b5f61745f6d6f73745f6f6e63653d6e3b"
)
table_load_linear = ast.Entry(
    "10 6cde7a2687bc348d737f1a56f256abd962c96b4d ima-buf sha256:e4a5f19a9f827c1442a76f52c91b149abbef7d327c9a20afa3768a8ac7362334 dm_table_load 646d5f76657273696f6e3d342e34352e303b6e616d653d6964656e746974792c757569643d746573742c6d616a6f723d3235332c6d696e6f723d302c6d696e6f725f636f756e743d312c6e756d5f746172676574733d313b7461726765745f696e6465783d302c7461726765745f626567696e3d302c7461726765745f6c656e3d343236383033322c7461726765745f6e616d653d6c696e6561722c7461726765745f76657273696f6e3d312e342e302c6465766963655f6e616d653d3235343a322c73746172743d303b"
)
table_load_snapshot = ast.Entry(
    "10 e63f7fc6ac88ff78154d2841c23a6205dad7cca4 ima-buf sha256:97fb89def8c8938f90b5b79441654beb84663f64974e76956d950f9e93da7cb2 dm_table_load 646d5f76657273696f6e3d342e34352e303b6e616d653d736e6170332c757569643d746573742d736e61702c6d616a6f723d3235332c6d696e6f723d312c6d696e6f725f636f756e743d312c6e756d5f746172676574733d313b7461726765745f696e6465783d302c7461726765745f626567696e3d302c7461726765745f6c656e3d31303438353736302c7461726765745f6e616d653d736e617073686f742c7461726765745f76657273696f6e3d312e31362e302c736e61705f6f726967696e5f6e616d653d3235333a302c736e61705f636f775f6e616d653d3235323a302c736e61705f76616c69643d792c736e61705f6d657267655f6661696c65643d6e2c736e617073686f745f6f766572666c6f7765643d6e3b"
)
table_load_integrity = ast.Entry(
    "10 15c72d3162ffbdda697c2a0b318545fc2604455d ima-buf sha256:823424c152324a18fbbf788788f1ad97eb89863f0e86fbe63aa7df88a6e4fb12 dm_table_load 646d5f76657273696f6e3d342e34352e303b6e616d653d746573742d696e746567726974792c757569643d43525950542d494e544547524954592d746573742d696e746567726974792c6d616a6f723d3235332c6d696e6f723d312c6d696e6f725f636f756e743d312c6e756d5f746172676574733d313b7461726765745f696e6465783d302c7461726765745f626567696e3d302c7461726765745f6c656e3d3230313432342c7461726765745f6e616d653d696e746567726974792c7461726765745f76657273696f6e3d312e31302e302c6465765f6e616d653d373a302c73746172743d302c7461675f73697a653d342c6d6f64653d4a2c726563616c63756c6174653d6e2c616c6c6f775f64697363617264733d6e2c6669785f70616464696e673d792c6669785f686d61633d792c6c65676163795f726563616c63756c6174653d6e2c6a6f75726e616c5f736563746f72733d313538342c696e7465726c656176655f736563746f72733d33323736382c6275666665725f736563746f72733d3132383b"
)
table_load_crypt = ast.Entry(
    "10 a55d85d4a6059b44960938b3893f521479e7421e ima-buf sha256:19d0d1eed3d4d1127519e22d63978a1fb58cbab368e13e6204e3c12f64dd9f51 dm_table_load 646d5f76657273696f6e3d342e34352e303b6e616d653d746573742c757569643d43525950542d4c554b53322d38613536343438333362613734633134616534326661313330666138386163612d746573742c6d616a6f723d3235332c6d696e6f723d322c6d696e6f725f636f756e743d312c6e756d5f746172676574733d313b7461726765745f696e6465783d302c7461726765745f626567696e3d302c7461726765745f6c656e3d3137323034302c7461726765745f6e616d653d63727970742c7461726765745f76657273696f6e3d312e32332e302c616c6c6f775f64697363617264733d6e2c73616d655f6370755f63727970743d6e2c7375626d69745f66726f6d5f63727970745f637075733d6e2c6e6f5f726561645f776f726b71756575653d6e2c6e6f5f77726974655f776f726b71756575653d6e2c69765f6c617267655f736563746f72733d6e2c6369706865725f737472696e673d6165732d7874732d706c61696e36342c6b65795f73697a653d36342c6b65795f70617274733d312c6b65795f65787472615f73697a653d302c6b65795f6d61635f73697a653d303b"
)
table_load_cache = ast.Entry(
    "10 daa949b2e19a473922b5b27b05df9a8425842d22 ima-buf sha256:cbcb9a0db9280f4a19d8e06a9825f1effc6db3e0fa0b2c72096ce8b7a534e6df dm_table_load 646d5f76657273696f6e3d342e34352e303b6e616d653d63616368652c757569643d63616368652c6d616a6f723d3235332c6d696e6f723d342c6d696e6f725f636f756e743d312c6e756d5f746172676574733d313b7461726765745f696e6465783d302c7461726765745f626567696e3d302c7461726765745f6c656e3d323034383030302c7461726765745f6e616d653d63616368652c7461726765745f76657273696f6e3d322e322e302c6d657461646174615f6d6f64653d72772c63616368655f6d657461646174615f6465766963653d373a322c63616368655f6465766963653d373a332c63616368655f6f726967696e5f6465766963653d373a342c77726974657468726f7567683d6e2c77726974656261636b3d792c706173737468726f7567683d6e2c6d65746164617461323d6e2c6e6f5f646973636172645f70617373646f776e3d6e3b"
)
table_load_mirror = ast.Entry(
    "10 5e686ad192b519cb316ad191def2403f90b96b16 ima-buf sha256:7548978b7d86b776adf00ce11659cc0142b719be8d4b83e3b53ff6d090f73812 dm_table_load 646d5f76657273696f6e3d342e34352e303b6e616d653d6d6972726f722c757569643d746573742d6d6972726f722c6d616a6f723d3235332c6d696e6f723d352c6d696e6f725f636f756e743d312c6e756d5f746172676574733d313b7461726765745f696e6465783d302c7461726765745f626567696e3d302c7461726765745f6c656e3d323034383030302c7461726765745f6e616d653d6d6972726f722c7461726765745f76657273696f6e3d312e31342e302c6e725f6d6972726f72733d322c6d6972726f725f6465766963655f303d373a332c6d6972726f725f6465766963655f305f7374617475733d412c6d6972726f725f6465766963655f313d373a322c6d6972726f725f6465766963655f315f7374617475733d412c68616e646c655f6572726f72733d792c6b6565705f6c6f673d6e2c6c6f675f747970655f7374617475733d3b"
)

# All other dm events they from the same device as the tabel_load_verity event
device_resume = ast.Entry(
    "10 efe6f16e52cf11f16515db24956b150512048e64 ima-buf sha256:7eeb012fa22a12456b91e1162de13fba0417d566a444d11c7f1f44f03f29de86 dm_device_resume 646d5f76657273696f6e3d342e34352e303b6e616d653d746573742c757569643d43525950542d5645524954592d63373664303733343364336134396235616230313032356433623335346466352d746573742c6d616a6f723d3235332c6d696e6f723d302c6d696e6f725f636f756e743d312c6e756d5f746172676574733d313b6163746976655f7461626c655f686173683d7368613235363a303965386131333230336231306365386433353261616166636461663734393836613665323934306534326334346331613636303336323431333565313131373b63757272656e745f6465766963655f63617061636974793d3230343830383b"
)
device_remove = ast.Entry(
    "10 2b6c00a8f9bf1c14cb297854da51cc1815d9857e ima-buf sha256:a8366c157cc83cc4e83e4e6ed814c3b86b7e2ce75a82d249db85055669e1d689 dm_device_remove 646d5f76657273696f6e3d342e34352e303b6465766963655f6163746976655f6d657461646174613d6e616d653d746573742c757569643d43525950542d5645524954592d63373664303733343364336134396235616230313032356433623335346466352d746573742c6d616a6f723d3235332c6d696e6f723d302c6d696e6f725f636f756e743d312c6e756d5f746172676574733d313b6163746976655f7461626c655f686173683d7368613235363a303965386131333230336231306365386433353261616166636461663734393836613665323934306534326334346331613636303336323431333565313131372c72656d6f76655f616c6c3d6e3b63757272656e745f6465766963655f63617061636974793d3230343830383b"
)
target_update_verity = ast.Entry(
    "10 cf05b61f406363ba08d642a6b4e2c8760d68e12b ima-buf sha256:e480e9677c5865d72bbde6e84d8ea5d75ee3c87a682dd127b8bb439c643823ee dm_target_update 646d5f76657273696f6e3d342e34352e303b6e616d653d746573742c757569643d43525950542d5645524954592d63373664303733343364336134396235616230313032356433623335346466352d746573742c6d616a6f723d3235332c6d696e6f723d302c6d696e6f725f636f756e743d312c6e756d5f746172676574733d313b7461726765745f696e6465783d302c7461726765745f626567696e3d302c7461726765745f6c656e3d3230343830382c7461726765745f6e616d653d7665726974792c7461726765745f76657273696f6e3d312e382e302c686173685f6661696c65643d432c7665726974795f76657273696f6e3d312c646174615f6465766963655f6e616d653d373a312c686173685f6465766963655f6e616d653d373a302c7665726974795f616c676f726974686d3d7368613235362c726f6f745f6469676573743d366561666665366238623031393930613165333937313236353734363865396237323263623634626139393432633664353836393438646131626434303936372c73616c743d643733386664396634323033663339376635613135353632633330323131393537303430636436373165666334363937313562663236383935363232656162632c69676e6f72655f7a65726f5f626c6f636b733d6e2c636865636b5f61745f6d6f73745f6f6e63653d6e3b"
)
table_clear = ast.Entry(
    "10 6149775a61f3e878a806554865798b62295b90d0 ima-buf sha256:da71026bb20de95fd3f9d18b2b278980dcbe227a54fa8f94c8a4c26b2b2e5e55 dm_table_clear 646d5f76657273696f6e3d342e34352e303b6e616d653d746573742c757569643d43525950542d5645524954592d63373664303733343364336134396235616230313032356433623335346466352d746573743b7461626c655f636c6561723d6e6f5f646174613b00000000000000000000000000000000000063757272656e745f6465766963655f63617061636974793d3230343830383b"
)

example_policy_verity = {
    "version": 1,
    "match_on": "uuid",
    "rules": {
        "example": {
            "required": True,
            "device_resume_required": True,
            "device_rename": {"valid_name": False, "valid_uuid": False},
            "device_remove": {"allow_removal": False},
            "allow_clear": False,
            "table_load": {
                "allow_multiple_loads": False,
                "name": "test",
                "uuid": "CRYPT-VERITY-.*",
                "major": 253,
                "minor": 0,
                "minor_count": 1,
                "num_targets": 1,
                "targets": [
                    {
                        "target_index": 0,
                        "target_begin": 0,
                        "target_len": 204808,
                        "target_name": "verity",
                        "target_version": "1.8.0",
                        "hash_failed": "V",
                        "verity_version": 1,
                        "data_device_name": "7:1",
                        "hash_device_name": "7:0",
                        "verity_algorithm": "sha256",
                        "root_digest": "6eaffe6b8b01990a1e39712657468e9b722cb64ba9942c6d586948da1bd40967",
                        "salt": "d738fd9f4203f397f5a15562c30211957040cd671efc469715bf26895622eabc",
                        "ignore_zero_blocks": "n",
                        "check_at_most_once": "n",
                    }
                ],
            },
        }
    },
}

# Example data for testing renaming of a linear target
linear_table_load = ast.Entry(
    "10 65c977c3ce1fbf9e68a5a4a486847ef7ae943bb3 ima-buf sha256:cb0d66bf4c79cb9a85fffaa5f47729332a3a5a29fd0dc317a878c8786c5f4067 dm_table_load 646d5f76657273696f6e3d342e34352e303b6e616d653d746573742c757569643d2c6d616a6f723d3235332c6d696e6f723d302c6d696e6f725f636f756e743d312c6e756d5f746172676574733d313b7461726765745f696e6465783d302c7461726765745f626567696e3d302c7461726765745f6c656e3d343236383033322c7461726765745f6e616d653d6c696e6561722c7461726765745f76657273696f6e3d312e342e302c6465766963655f6e616d653d3235343a322c73746172743d303b"
)
linear_device_resume = ast.Entry(
    "10 8a869290c3456b2c983f5daef7fd864a680452a1 ima-buf sha256:513204e3560627b0751858ba0012fbe8bee2e7a5ac4765529a60b4500f9adf09 dm_device_resume 646d5f76657273696f6e3d342e34352e303b6e616d653d746573742c757569643d2c6d616a6f723d3235332c6d696e6f723d302c6d696e6f725f636f756e743d312c6e756d5f746172676574733d313b6163746976655f7461626c655f686173683d7368613235363a636230643636626634633739636239613835666666616135663437373239333332613361356132396664306463333137613837386338373836633566343036373b63757272656e745f6465766963655f63617061636974793d343236383033323b"
)
linear_rename_name = ast.Entry(
    "10 cf9f33a163183ebd4d92a42cd38305dfbc814748 ima-buf sha256:4088aee6143157dff39df843ff20467a500234f07d2c38b9312108455ea99968 dm_device_rename 646d5f76657273696f6e3d342e34352e303b6e616d653d746573742c757569643d2c6d616a6f723d3235332c6d696e6f723d302c6d696e6f725f636f756e743d312c6e756d5f746172676574733d313b6e65775f6e616d653d74657374322c6e65775f757569643d3b63757272656e745f6465766963655f63617061636974793d343236383033323b"
)
linear_rename_uuid = ast.Entry(
    "10 9f9f094b0aab1f07f967c61d0c4a18b26fad73ce ima-buf sha256:9144918395fbd350087fae06d02950c968342463734bb127533ae232bbbf1a42 dm_device_rename 646d5f76657273696f6e3d342e34352e303b6e616d653d74657374322c757569643d2c6d616a6f723d3235332c6d696e6f723d302c6d696e6f725f636f756e743d312c6e756d5f746172676574733d313b6e65775f6e616d653d74657374322c6e65775f757569643d746573745f757569643b63757272656e745f6465766963655f63617061636974793d343236383033323b"
)

example_policy_linear = {
    "version": 1,
    "match_on": "name",
    "rules": {
        "example": {
            "required": True,
            "device_resume_required": True,
            "device_rename": {"valid_name": "test|test2", "valid_uuid": "invalid"},
            "device_remove": {"allow_removal": False},
            "allow_clear": False,
            "table_load": {
                "allow_multiple_loads": False,
                "name": "test",
                "uuid": "",
                "major": 253,
                "minor": 0,
                "minor_count": 1,
                "num_targets": 1,
                "targets": [
                    {
                        "target_index": 0,
                        "target_begin": 0,
                        "target_len": 4268032,
                        "target_name": "linear",
                        "target_version": "1.4.0",
                        "device_name": "254:2",
                        "start": 0,
                    }
                ],
            },
        }
    },
}


class TestImaDM(unittest.TestCase):
    def test_parser_table_load_verity(self):
        try:
            ima_buf: ast.ImaBuf = table_load_verity.mode
            ima_dm.parse(ima_buf.data.data.decode(), ima_buf.name.name)
        except Exception as e:
            self.fail(f"Parsing failed with {str(e)}")

    def test_parser_table_load_linear(self):
        try:
            ima_buf: ast.ImaBuf = table_load_linear.mode
            ima_dm.parse(ima_buf.data.data.decode(), ima_buf.name.name)
        except Exception as e:
            self.fail(f"Parsing failed with {str(e)}")

    def test_parser_table_load_snapshot(self):
        try:
            ima_buf: ast.ImaBuf = table_load_snapshot.mode
            ima_dm.parse(ima_buf.data.data.decode(), ima_buf.name.name)
        except Exception as e:
            self.fail(f"Parsing failed with {str(e)}")

    def test_parser_table_load_integrity(self):
        try:
            ima_buf: ast.ImaBuf = table_load_integrity.mode
            ima_dm.parse(ima_buf.data.data.decode(), ima_buf.name.name)
        except Exception as e:
            self.fail(f"Parsing failed with {str(e)}")

    def test_parser_table_load_crypt(self):
        try:
            ima_buf: ast.ImaBuf = table_load_crypt.mode
            ima_dm.parse(ima_buf.data.data.decode(), ima_buf.name.name)
        except Exception as e:
            self.fail(f"Parsing failed with {str(e)}")

    def test_parser_table_load_cache(self):
        try:
            ima_buf: ast.ImaBuf = table_load_cache.mode
            ima_dm.parse(ima_buf.data.data.decode(), ima_buf.name.name)
        except Exception as e:
            self.fail(f"Parsing failed with {str(e)}")

    def test_parser_table_load_mirror(self):
        try:
            ima_buf: ast.ImaBuf = table_load_mirror.mode
            ima_dm.parse(ima_buf.data.data.decode(), ima_buf.name.name)
        except Exception as e:
            self.fail(f"Parsing failed with {str(e)}")

    def test_parser_device_resume(self):
        try:
            ima_buf: ast.ImaBuf = device_resume.mode
            ima_dm.parse(ima_buf.data.data.decode(), ima_buf.name.name)
        except Exception as e:
            self.fail(f"Parsing failed with {str(e)}")

    def test_parser_device_remove(self):
        try:
            ima_buf: ast.ImaBuf = device_remove.mode
            ima_dm.parse(ima_buf.data.data.decode(), ima_buf.name.name)
        except Exception as e:
            self.fail(f"Parsing failed with {str(e)}")

    def test_parser_device_rename(self):
        try:
            ima_buf: ast.ImaBuf = linear_rename_name.mode
            ima_dm.parse(ima_buf.data.data.decode(), ima_buf.name.name)
        except Exception as e:
            self.fail(f"Parsing failed with {str(e)}")

    def test_parser_table_clear(self):
        try:
            ima_buf: ast.ImaBuf = table_clear.mode
            ima_dm.parse(ima_buf.data.data.decode(), ima_buf.name.name)
        except Exception as e:
            self.fail(f"Parsing failed with {str(e)}")

    def test_basic_validation_verity(self):
        validator = ima_dm.DmIMAValidator(example_policy_verity)

        # Testing table load
        ima_buf: ast.ImaBuf = table_load_verity.mode
        failure = validator.validate(ima_buf.digest, ima_buf.name, ima_buf.data)
        # the table load entry itself should be valid
        self.assertFalse(
            failure, f"Validation of table load failed with: {list(map(lambda x: x.context, failure.events))}"
        )
        # The policy also requires a table resume, so the overall state is invalid
        self.assertTrue(validator.invalid())

        # Testing device resume
        ima_buf: ast.ImaBuf = device_resume.mode
        failure = validator.validate(ima_buf.digest, ima_buf.name, ima_buf.data)
        # the device resume entry itself should be valid
        self.assertFalse(
            failure, f"Validation of device resume failed with: {list(map(lambda x: x.context, failure.events))}"
        )
        # Now the all the policy should be valid
        self.assertFalse(validator.invalid())

        # Store valid state for restoring it between the next tests
        valid_state = validator.state_dump()

        # Test remove
        validator.state_load(valid_state)
        ima_buf: ast.ImaBuf = device_remove.mode
        failure = validator.validate(ima_buf.digest, ima_buf.name, ima_buf.data)
        self.assertIn("ima.validation.dm.dm_device_remove.device_removed", failure.get_event_ids())

        # Test double load
        validator.state_load(valid_state)
        ima_buf: ast.ImaBuf = table_load_verity.mode
        failure = validator.validate(ima_buf.digest, ima_buf.name, ima_buf.data)
        self.assertIn("ima.validation.dm.dm_table_load.multiple_table_loads", failure.get_event_ids())

        # Test target update
        validator.state_load(valid_state)
        ima_buf: ast.ImaBuf = target_update_verity.mode
        failure = validator.validate(ima_buf.digest, ima_buf.name, ima_buf.data)
        self.assertIn("ima.validation.dm.dm_target_update.target_data_invalid", failure.get_event_ids())

        # Test clear
        validator.state_load(valid_state)
        ima_buf: ast.ImaBuf = table_clear.mode
        failure = validator.validate(ima_buf.digest, ima_buf.name, ima_buf.data)
        self.assertIn("ima.validation.dm.dm_table_clear.table_cleared", failure.get_event_ids())

    def test_events_before_table_load(self):
        validator = ima_dm.DmIMAValidator(example_policy_verity)

        # Resume
        ima_buf: ast.ImaBuf = device_resume.mode
        failure = validator.validate(ima_buf.digest, ima_buf.name, ima_buf.data)
        self.assertIn("ima.validation.dm.dm_device_resume.resume_before_table_load", failure.get_event_ids())

        # Remove
        ima_buf: ast.ImaBuf = device_remove.mode
        failure = validator.validate(ima_buf.digest, ima_buf.name, ima_buf.data)
        self.assertIn("ima.validation.dm.dm_device_remove.remove_before_table_load", failure.get_event_ids())

        # Clear
        ima_buf: ast.ImaBuf = table_clear.mode
        failure = validator.validate(ima_buf.digest, ima_buf.name, ima_buf.data)
        self.assertIn("ima.validation.dm.dm_table_clear.clear_before_table_load", failure.get_event_ids())

        # Update
        ima_buf: ast.ImaBuf = target_update_verity.mode
        failure = validator.validate(ima_buf.digest, ima_buf.name, ima_buf.data)
        self.assertIn("ima.validation.dm.dm_target_update.update_before_table_load", failure.get_event_ids())

    def test_device_rename(self):
        validator = ima_dm.DmIMAValidator(example_policy_linear)
        ima_buf: ast.ImaBuf = linear_table_load.mode
        failure = validator.validate(ima_buf.digest, ima_buf.name, ima_buf.data)
        self.assertFalse(failure)

        ima_buf: ast.ImaBuf = linear_device_resume.mode
        failure = validator.validate(ima_buf.digest, ima_buf.name, ima_buf.data)
        self.assertFalse(failure)

        # Rename the device
        self.assertIn("test", validator.devices)
        ima_buf: ast.ImaBuf = linear_rename_name.mode
        failure = validator.validate(ima_buf.digest, ima_buf.name, ima_buf.data)
        self.assertFalse(failure)
        # Check if the device was also moved in the validator
        self.assertNotIn("test", validator.devices)
        self.assertIn("test2", validator.devices)

        # New uuid should be invalid
        ima_buf: ast.ImaBuf = linear_rename_uuid.mode
        failure = validator.validate(ima_buf.digest, ima_buf.name, ima_buf.data)
        self.assertIn("ima.validation.dm.dm_device_rename.new_uuid_invalid", failure.get_event_ids())

    def test_matching_func(self):
        for entry in [None, False, True, "test", 123]:
            self.assertTrue(ima_dm._check_attr(entry, None))

        for entry in [False, True, "test", 123]:
            self.assertFalse(ima_dm._check_attr(None, entry))

        for entry in [False, True, "test", 123]:
            self.assertTrue(ima_dm._check_attr(entry, entry))

        for x, y in zip([1, "test"], [2, "testing"]):
            self.assertFalse(ima_dm._check_attr(x, y))

        for entry in [True, "yes", "1", "y", 1]:
            self.assertTrue(ima_dm._check_attr(entry, True), f"{entry} == True, should be True but isn't.")
            self.assertFalse(ima_dm._check_attr(entry, False))

        for entry in [False, "no", "0", "n", 0]:
            self.assertTrue(ima_dm._check_attr(entry, False), f"{entry} == False, should be True but isn't.")
            self.assertFalse(ima_dm._check_attr(entry, True))

        regex = r"a|b|cc+"
        self.assertTrue(ima_dm._check_attr("a", regex))
        self.assertTrue(ima_dm._check_attr("b", regex))
        self.assertTrue(ima_dm._check_attr("cc", regex))
        self.assertTrue(ima_dm._check_attr("ccc", regex))
        self.assertFalse(ima_dm._check_attr("c", regex))

        regex = r"10|20"
        self.assertTrue(ima_dm._check_attr(10, regex))
        self.assertTrue(ima_dm._check_attr("10", regex))
        self.assertFalse(ima_dm._check_attr(30, regex))


if __name__ == "__main__":
    unittest.main()
