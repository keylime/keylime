# Keylime testing

## Pull-request testing

Individual changes to keylime are introduced using the pull-request workflow and for each pull-request update a set of test is executed.

### Keylime testsuite

These are the tests stored in [test](test) directory. Tests are run on the ubuntu-latest image through [GitHub Actions](.github/workflows/test.yml).

### End-to-end tests

E2E tests from [keylime-tests](https://github.com/RedHat-SP-Security/keylime-tests) repository are run through [Packit-as-a-Service](https://packit.dev/docs/testing-farm/) on currently supported Fedora releases, Fedora Rawhide and CentOS Stream releases. Test plan is stored in [packit-ci.fmf](packit-ci.fmf) file.

Tests are run for every pull-request update. One can also re-run all tests by adding the comment `/packit test`.

#### Pull-request code coverage measurements

During test execution we can measure Python code coverage, in particular code coverage for changes introduced in pull-request.
Such a measurement is currently enabled only on Fedora 35 release. In order to access code coverage report one has to open Packit-as-a-Service logs for Fedora 35 and display test logs of `/setup/generate_coverage_report
` task.

In the log one can see overall code coverage report.

```
Name                                                                                                                                                  Stmts   Miss  Cover
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------
/usr/local/bin/keylime_agent                                                                                                                             18      5    72%
/usr/local/bin/keylime_ima_emulator                                                                                                                      18      5    72%
/usr/local/bin/keylime_registrar                                                                                                                         18      5    72%
/usr/local/bin/keylime_tenant                                                                                                                            18      5    72%
/usr/local/bin/keylime_verifier                                                                                                                          18      5    72%
/usr/local/lib/python3.10/site-packages/keylime-6.3.1-py3.10.egg/keylime/__init__.py                                                                      0      0   100%
/usr/local/lib/python3.10/site-packages/keylime-6.3.1-py3.10.egg/keylime/agentstates.py                                                                 106     54    49%
/usr/local/lib/python3.10/site-packages/keylime-6.3.1-py3.10.egg/keylime/api_version.py                                                                  42     12    71%
/usr/local/lib/python3.10/site-packages/keylime-6.3.1-py3.10.egg/keylime/ca_impl_openssl.py                                                              53      0   100%
/usr/local/lib/python3.10/site-packages/keylime-6.3.1-py3.10.egg/keylime/ca_util.py                                                                     348    175    50%
/usr/local/lib/python3.10/site-packages/keylime-6.3.1-py3.10.egg/keylime/cloud_verifier_common.py                                                       154    129    16%
/usr/local/lib/python3.10/site-packages/keylime-6.3.1-py3.10.egg/keylime/cloud_verifier_tornado.py                                                      747    632    15%
/usr/local/lib/python3.10/site-packages/keylime-6.3.1-py3.10.egg/keylime/cmd/__init__.py                                                                  0      0   100%
/usr/local/lib/python3.10/site-packages/keylime-6.3.1-py3.10.egg/keylime/cmd/agent.py                                                                    11      4    64%
/usr/local/lib/python3.10/site-packages/keylime-6.3.1-py3.10.egg/keylime/cmd/ima_emulator_adapter.py                                                     68     10    85%
/usr/local/lib/python3.10/site-packages/keylime-6.3.1-py3.10.egg/keylime/cmd/migrations_apply.py                                                         20      6    70%
/usr/local/lib/python3.10/site-packages/keylime-6.3.1-py3.10.egg/keylime/cmd/registrar.py                                                                15      4    73%
/usr/local/lib/python3.10/site-packages/keylime-6.3.1-py3.10.egg/keylime/cmd/tenant.py                                                                   13      6    54%
/usr/local/lib/python3.10/site-packages/keylime-6.3.1-py3.10.egg/keylime/cmd/user_data_encrypt.py                                                        45     26    42%
/usr/local/lib/python3.10/site-packages/keylime-6.3.1-py3.10.egg/keylime/cmd/verifier.py                                                                 15      4    73%
/usr/local/lib/python3.10/site-packages/keylime-6.3.1-py3.10.egg/keylime/cmd_exec.py                                                                     32      4    88%
/usr/local/lib/python3.10/site-packages/keylime-6.3.1-py3.10.egg/keylime/common/__init__.py                                                               0      0   100%
/usr/local/lib/python3.10/site-packages/keylime-6.3.1-py3.10.egg/keylime/common/algorithms.py                                                            55     12    78%
/usr/local/lib/python3.10/site-packages/keylime-6.3.1-py3.10.egg/keylime/common/exception.py                                                              8      3    62%
/usr/local/lib/python3.10/site-packages/keylime-6.3.1-py3.10.egg/keylime/common/retry.py                                                                  7      6    14%
/usr/local/lib/python3.10/site-packages/keylime-6.3.1-py3.10.egg/keylime/common/states.py                                                                30      1    97%
/usr/local/lib/python3.10/site-packages/keylime-6.3.1-py3.10.egg/keylime/common/validators.py                                                            35     18    49%
/usr/local/lib/python3.10/site-packages/keylime-6.3.1-py3.10.egg/keylime/config.py                                                                      113     33    71%
/usr/local/lib/python3.10/site-packages/keylime-6.3.1-py3.10.egg/keylime/crypto.py                                                                      106     23    78%
/usr/local/lib/python3.10/site-packages/keylime-6.3.1-py3.10.egg/keylime/db/__init__.py                                                                   0      0   100%
/usr/local/lib/python3.10/site-packages/keylime-6.3.1-py3.10.egg/keylime/db/keylime_db.py                                                                60      9    85%
/usr/local/lib/python3.10/site-packages/keylime-6.3.1-py3.10.egg/keylime/db/registrar_db.py                                                              20      0   100%
/usr/local/lib/python3.10/site-packages/keylime-6.3.1-py3.10.egg/keylime/db/verifier_db.py                                                               49      0   100%
/usr/local/lib/python3.10/site-packages/keylime-6.3.1-py3.10.egg/keylime/failure.py                                                                     112     42    62%
/usr/local/lib/python3.10/site-packages/keylime-6.3.1-py3.10.egg/keylime/fs_util.py                                                                       5      1    80%
/usr/local/lib/python3.10/site-packages/keylime-6.3.1-py3.10.egg/keylime/gpg.py                                                                          17     13    24%
/usr/local/lib/python3.10/site-packages/keylime-6.3.1-py3.10.egg/keylime/ima.py                                                                         320    188    41%
/usr/local/lib/python3.10/site-packages/keylime-6.3.1-py3.10.egg/keylime/ima_ast.py                                                                     228    105    54%
/usr/local/lib/python3.10/site-packages/keylime-6.3.1-py3.10.egg/keylime/ima_file_signatures.py                                                         279    180    35%
/usr/local/lib/python3.10/site-packages/keylime-6.3.1-py3.10.egg/keylime/json.py                                                                         45     15    67%
/usr/local/lib/python3.10/site-packages/keylime-6.3.1-py3.10.egg/keylime/keylime_agent.py                                                               520    189    64%
/usr/local/lib/python3.10/site-packages/keylime-6.3.1-py3.10.egg/keylime/keylime_logging.py                                                              52     16    69%
/usr/local/lib/python3.10/site-packages/keylime-6.3.1-py3.10.egg/keylime/measured_boot.py                                                                60     41    32%
/usr/local/lib/python3.10/site-packages/keylime-6.3.1-py3.10.egg/keylime/migrations/env.py                                                               56     19    66%
/usr/local/lib/python3.10/site-packages/keylime-6.3.1-py3.10.egg/keylime/migrations/versions/1ac1513ef2a1_fix_mb_and_ima_column_types.py                 22      5    77%
/usr/local/lib/python3.10/site-packages/keylime-6.3.1-py3.10.egg/keylime/migrations/versions/257fe0f0c039_add_fields_for_revocation_context_to_.py       20      4    80%
/usr/local/lib/python3.10/site-packages/keylime-6.3.1-py3.10.egg/keylime/migrations/versions/63c30820fdc1_add_mtls_cert_and_ak_to_verifier_db.py         20      4    80%
/usr/local/lib/python3.10/site-packages/keylime-6.3.1-py3.10.egg/keylime/migrations/versions/7d5db1a6ffb0_add_agentstates_columns.py                     25      6    76%
/usr/local/lib/python3.10/site-packages/keylime-6.3.1-py3.10.egg/keylime/migrations/versions/8a44a4364f5a_initial_database_migration.py                  21      3    86%
/usr/local/lib/python3.10/site-packages/keylime-6.3.1-py3.10.egg/keylime/migrations/versions/8da20383f6e1_extend_ip_field.py                             19      3    84%
/usr/local/lib/python3.10/site-packages/keylime-6.3.1-py3.10.egg/keylime/migrations/versions/9169f80345ed_add_supported_version_to_verifiermain_.py      20      3    85%
/usr/local/lib/python3.10/site-packages/keylime-6.3.1-py3.10.egg/keylime/migrations/versions/a79c27ec1054_add_mtls_cert_field_to_registrar.py            18      3    83%
/usr/local/lib/python3.10/site-packages/keylime-6.3.1-py3.10.egg/keylime/migrations/versions/a7a64155ab3a_add_ima_filesigning_keys_column.py             18      3    83%
/usr/local/lib/python3.10/site-packages/keylime-6.3.1-py3.10.egg/keylime/migrations/versions/ae898986c6e9_add_mb_refstate_column.py                      18      3    83%
/usr/local/lib/python3.10/site-packages/keylime-6.3.1-py3.10.egg/keylime/migrations/versions/b4d024197413_add_verfier_id_to_verifiermain_table.py        22      5    77%
/usr/local/lib/python3.10/site-packages/keylime-6.3.1-py3.10.egg/keylime/migrations/versions/c3842cc9ee69_store_keyrings_learned_from_ima_log.py         19      3    84%
/usr/local/lib/python3.10/site-packages/keylime-6.3.1-py3.10.egg/keylime/migrations/versions/cc2630851a1f_receive_the_aik_tpm_from_the_agent.py          28      8    71%
/usr/local/lib/python3.10/site-packages/keylime-6.3.1-py3.10.egg/keylime/migrations/versions/eb869a77abd1_create_allowlist_table.py                      18      3    83%
/usr/local/lib/python3.10/site-packages/keylime-6.3.1-py3.10.egg/keylime/migrations/versions/eeb702f77d7d_allowlist_rename.py                            20      4    80%
/usr/local/lib/python3.10/site-packages/keylime-6.3.1-py3.10.egg/keylime/migrations/versions/f35cdd35eb83_move_v_tpm_policy_to_jsonpickletype.py         23      5    78%
/usr/local/lib/python3.10/site-packages/keylime-6.3.1-py3.10.egg/keylime/migrations/versions/f82c4252bc4f_add_ip_and_port_to_registrar.py                22      5    77%
/usr/local/lib/python3.10/site-packages/keylime-6.3.1-py3.10.egg/keylime/registrar_client.py                                                            143     50    65%
/usr/local/lib/python3.10/site-packages/keylime-6.3.1-py3.10.egg/keylime/registrar_common.py                                                            341    145    57%
/usr/local/lib/python3.10/site-packages/keylime-6.3.1-py3.10.egg/keylime/requests_client.py                                                              55     10    82%
/usr/local/lib/python3.10/site-packages/keylime-6.3.1-py3.10.egg/keylime/revocation_notifier.py                                                         144    114    21%
/usr/local/lib/python3.10/site-packages/keylime-6.3.1-py3.10.egg/keylime/secure_mount.py                                                                 59     16    73%
/usr/local/lib/python3.10/site-packages/keylime-6.3.1-py3.10.egg/keylime/tenant.py                                                                      898    376    58%
/usr/local/lib/python3.10/site-packages/keylime-6.3.1-py3.10.egg/keylime/tornado_requests.py                                                             37     30    19%
/usr/local/lib/python3.10/site-packages/keylime-6.3.1-py3.10.egg/keylime/tpm/__init__.py                                                                  0      0   100%
/usr/local/lib/python3.10/site-packages/keylime-6.3.1-py3.10.egg/keylime/tpm/tpm2_objects.py                                                            199     81    59%
/usr/local/lib/python3.10/site-packages/keylime-6.3.1-py3.10.egg/keylime/tpm/tpm_abstract.py                                                            243     75    69%
/usr/local/lib/python3.10/site-packages/keylime-6.3.1-py3.10.egg/keylime/tpm/tpm_main.py                                                                979    386    61%
/usr/local/lib/python3.10/site-packages/keylime-6.3.1-py3.10.egg/keylime/tpm_ek_ca.py                                                                    24     14    42%
/usr/local/lib/python3.10/site-packages/keylime-6.3.1-py3.10.egg/keylime/user_utils.py                                                                   54     45    17%
/usr/local/lib/python3.10/site-packages/keylime-6.3.1-py3.10.egg/keylime/web_util.py                                                                    137     35    74%
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------
TOTAL                                                                                                                                                  7602   3452    55%
```

There is also code coverage report specifically for code changes presented in a form of a patch. This way one can see which code is executed by particular E2E tests. E.g. for [PR#916](https://github.com/keylime/keylime/pull/916/files) the output looks like this.

```
diff --git a/keylime/db/keylime_db.py b/keylime/db/keylime_db.py
         index 1cd4a07..91885a7 100644
         --- a/keylime/db/keylime_db.py
         +++ b/keylime/db/keylime_db.py
         @@ -39,8 +39,9 @@ class DBEngineManager:
                  url = config.get(service, 'database_url')
                  if url:
                      logger.info('database_url is set, using it to establish database connection')
         -            engine_args['pool_size'] = int(p_sz)
         -            engine_args['max_overflow'] = int(m_ovfl)
EF       +            if not url.count('sqlite:') :
EF       +                engine_args['pool_size'] = int(p_sz)
EF       +                engine_args['max_overflow'] = int(m_ovfl)
         
                  else :
                      logger.info('database_url is not set, using multi-parameter database configuration options')
--------------------------------------------------------------------------------
Overall patch coverage: 100 %, 3 out of 3 lines are covered by a test

Legend:
  +  there are additional tests executing this line
  !  line not covered by a test
  ~  line is not being measured
  E  /functional/db-postgresql-sanity-on-localhost
  F  /functional/db-mariadb-sanity-on-localhost
```

## Local test execution

### Unit tests

The Keylime test suite can be run locally by executing [.ci/run_local.sh](.ci/run_local.sh) (requires Docker).

### E2E tests

Tests can be easily run on Fedora and CentOS Stream using the [tmt](https://tmt.readthedocs.io/en/stable/) tool.

For more details on local E2E test execution and troubleshooting please see [TESTING.md](https://github.com/RedHat-SP-Security/keylime-tests/blob/main/TESTING.md) document from keylime-tests repository.
