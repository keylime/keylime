Runtime Integrity Monitoring
============================
Keylime's runtime integrity monitoring requires the set up of Linux IMA.
More information about IMA in general can be found in the `openSUSE Wiki <https://en.opensuse.org/SDB:Ima_evm>`_.

You should refer to your Linux Distributions documentation to enable IMA, but
as a general guide most recent versions already have :code:`CONFIG_IMA` toggled to
:code:`Y` as a value during Kernel compile.

It is then just a case of deploying an :code:`ima-policy` file. On a Fedora or Debian
system, the file is located in :code:`/etc/ima/ima-policy`.

For configuration of your IMA policy, please refer to the `IMA Documentation <https://github.com/torvalds/linux/blob/v6.1/Documentation/ABI/testing/ima_policy>`_.

Within Keylime we use the following for demonstration (found in :code:`demo/ima-policies/ima-policy-keylime`)::

    # PROC_SUPER_MAGIC
    dont_measure fsmagic=0x9fa0
    # SYSFS_MAGIC
    dont_measure fsmagic=0x62656572
    # DEBUGFS_MAGIC
    dont_measure fsmagic=0x64626720
    # TMPFS_MAGIC
    dont_measure fsmagic=0x01021994
    # RAMFS_MAGIC
    dont_measure fsmagic=0x858458f6
    # SECURITYFS_MAGIC
    dont_measure fsmagic=0x73636673
    # SELINUX_MAGIC
    dont_measure fsmagic=0xf97cff8c
    # CGROUP_SUPER_MAGIC
    dont_measure fsmagic=0x27e0eb
    # OVERLAYFS_MAGIC
    # when containers are used we almost always want to ignore them
    dont_measure fsmagic=0x794c7630
    # Don't measure log, audit or tmp files
    dont_measure obj_type=var_log_t
    dont_measure obj_type=auditd_log_t
    dont_measure obj_type=tmp_t
    # MEASUREMENTS
    measure func=BPRM_CHECK
    measure func=FILE_MMAP mask=MAY_EXEC
    measure func=MODULE_CHECK uid=0

This default policy measures all executables in :code:`bprm_check` and all files :code:`mmapped`
executable in :code:`file_mmap` and module checks and skips several irrelevant files
(logs, audit, tmp, etc).

Once your :code:`ima-policy` is in place, reboot your machine (or even better have it
present in your image for first boot).

You can then verify IMA is measuring your system::

  # head -5 /sys/kernel/security/ima/ascii_runtime_measurements
  PCR                                  template-hash filedata-hash                                 filename-hint
  10 3c93cea361cd6892bc8b9e3458e22ce60ef2e632 ima-ng sha1:ac7dd11bf0e3bec9a7eb2c01e495072962fb9dfa boot_aggregate
  10 3d1452eb1fcbe51ad137f3fc21d3cf4a7c2e625b ima-ng sha1:a212d835ca43d7deedd4ee806898e77eab53dafa /usr/lib/systemd/systemd
  10 e213099a2bf6d88333446c5da617e327696f9eb4 ima-ng sha1:6da34b1b7d2ca0d5ca19e68119c262556a15171d /usr/lib64/ld-2.28.so
  10 7efd8e2a3da367f2de74b26b84f20b37c692b9f9 ima-ng sha1:af78ea0b455f654e9237e2086971f367b6bebc5f /usr/lib/systemd/libsystemd-shared-239.so
  10 784fbf69b54c99d4ae82c0be5fca365a8272414e ima-ng sha1:b0c601bf82d32ff9afa34bccbb7e8f052c48d64e /etc/ld.so.cache


Keylime Runtime Policies
------------------------

A runtime policy in its most basic form is a set of "golden" cryptographic hashes of files' un-tampered
state or of keys that may be loaded onto keyrings for IMA verification.

Keylime will load the runtime policy  into the Keylime Verifier. Keylime will then
poll tpm quotes to `PCR 10` on the agents TPM and validate the agents file(s)
state against the policy. If the object has been tampered with or an
unexpected key was loaded onto a keyring, the hashes will not match and Keylime
will place the agent into a failed state. Likewise, if any files invoke the actions
stated in :code:`ima-policy` that are not matched in the allowlist, keylime will place
the agent into a failed state.

Allowlists are contained in Keylime runtime policies - see below for more details.

Generate a Runtime Policy
~~~~~~~~~~~~~~~~~~~~~~~~~

Runtime policies heavily depend on the IMA configuration and used files by the operating system.
Keylime provides two helper scripts for getting started.

.. note::
    Those scripts only provide a reference point to get started and **not** a complete solution.
    We encourage developers / users of Keylime to be creative and
    come up with their own process for securely creating and maintaining runtime policies.


Create Runtime Policy from a Running System
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
The first script generates a runtime policy from the :code:`initramfs`, IMA log
(just for the :code:`boot aggregate`) and files located on the root filesystem of a running
system.

The :code:`create_runtime_policy.sh` script is `available here <https://github.com/keylime/keylime/blob/master/scripts/create_runtime_policy.sh>`_

Run the script as follows::

  # create_runtime_policy.sh -o runtime_policy_keylime.json 
  
For more options see the help page :code:`create_runtime_policy.sh`::

    Usage: $0 -o/--output_file FILENAME [-a/--algo ALGO] [-x/--ramdisk-location PATH] [-y/--boot_aggregate-location PATH] [-z/--rootfs-location PATH] [-e/--exclude_list FILENAME] [-s/--skip-path PATH]"

    optional arguments:
    -a/--algo                    (checksum algorithmi to be used, default: sha1sum)
    -x/--ramdisk-location        (path to initramdisk, default: /boot/, set to "none" to skip)
    -y/--boot_aggregate-location (path for IMA log, used for boot aggregate extraction, default: /sys/kernel/security/ima/ascii_runtime_measurements, set to "none" to skip)
    -z/--rootfs-location         (path to root filesystem, default: /, cannot be skipped)
    -e/--exclude_list            (filename containing a list of paths to be excluded (i.e., verifier will not try to match checksums), default: none)
    -s/--skip-path               (comma-separated path list, files found there will not have checksums calculated, default: none)
    -h/--help                    show this message and exit

Note: note, you need the OpenSSL installed to have the sha*sum CLI executables available

The resulting `runtime_policy_keylime.json` file can be directly used by
:code:`keylime_tenant` (option :code:`--runtime-policy`)

.. warning::
    It’s best practice to create the runtime policy in a secure environment.
    Ideally, this should be on a fully encrypted, air gapped computer that is
    permanently isolated from the Internet. Disable all network cards and sign
    the runtime policy hash to ensure no tampering occurs when transferring to other
    machines.


Creating more Complex Policies
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
The second script allows the user to build more complex policies by providing options to include:
keyring verification, IMA verification keys, generating allowlist from IMA measurement log
and extending existing policies.

A basic policy can be easily created by using a IMA measurement log from system::

  keylime_create_policy -m /path/to/ascii_runtime_measurements -o runtime_policy.json

For more options see the help page :code:`keylime_create_policy -h`::

    usage: keylime_create_policy [-h] [-B BASE_POLICY] [-k] [-b] [-a ALLOWLIST] [-m IMA_MEASUREMENT_LIST] [-i IGNORED_KEYRINGS] [-o OUTPUT] [--no-hashes] [-A IMA_SIGNATURE_KEYS]

    This is an experimental tool for adding items to a Keylime's IMA runtime policy

    options:
      -h, --help            show this help message and exit
      -B BASE_POLICY, --base-policy BASE_POLICY
                            Merge new data into the given JSON runtime policy
      -k, --keyrings        Create keyrings policy entries
      -b, --ima-buf         Process ima-buf entries other than those related to keyrings
      -a ALLOWLIST, --allowlist ALLOWLIST
                            Use given plain-text allowlist
      -m IMA_MEASUREMENT_LIST, --ima-measurement-list IMA_MEASUREMENT_LIST
                            Use given IMA measurement list for keyrings and critical data extraction rather than /sys/kernel/security/ima/ascii_runtime_measurements
      -i IGNORED_KEYRINGS, --ignored-keyrings IGNORED_KEYRINGS
                            Ignored the given keyring; this option may be passed multiple times
      -o OUTPUT, --output OUTPUT
                            File to write JSON policy into; default is to print to stdout
      --no-hashes           Do not add any hashes to the policy
      -A IMA_SIGNATURE_KEYS, --add-ima-signature-verification-key IMA_SIGNATURE_KEYS
                            Add the given IMA signature verification key to the Keylime-internal 'tenant_keyring'; the key should be an x509 certificate in DER or PEM format but may also be a public or private key
                            file; this option may be passed multiple times


Runtime Policy Entries for Keys
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

IMA can measure which keys are loaded onto different keyrings. Keylime has the option to verify
those keys and automatically use them for signature verification.

The hash of the an key can be generated for example with::

    sha256sum /etc/keys/ima/rsakey-rsa.crt.der


As seen the the JSON schema below, the hash (sha1 or sha256) depending on the IMA configuration
can be added as the following where in :code:`.ima` is the keyring the key gets loaded onto and
:code:`<SHA256_HASH>` is the hash of that key::

    jq '.keyrings += {".ima" : ["<SHA256_HASH>"]}'  runtime_policy.json  > runtime_policy_with_keyring.json

The following rule should be added to the IMA policy so that IMA reports keys
loaded onto keyrings .ima and .evm (since Linux 5.6)::

    measure func=KEY_CHECK keyrings=.ima|.evm


If the key should only be verified and not be used for IMA signature verification,
then it can be added to the ignore list::

    jq '.ima.ignored_keyrings += [".ima"]' runtime_policy.json > runtime_policy_ignore_ima.json

If :code:`*` is added no verified keyring is used for IMA signature verification.

Runtime Policy JSON Schema
~~~~~~~~~~~~~~~~~~~~~~~~~~

The tenant parses the allow and exclude list into a JSON object that is then sent to the verifier.
Depending of the use case the object can also be constructed manually instead of using the tenant.

.. sourcecode:: json

    {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "Keylime IMA policy",
        "type": "object",
        "properties": {
            "meta": {
                "type": "object",
                "properties": {
                    "version": {
                        "type": "integer",
                        "description": "Version number of the IMA policy schema"
                    }
                },
                "required": ["version"],
                "additionalProperties": false
            },
            "release": {
                "type": "number",
                "title": "Release version",
                "description": "Version of the IMA policy (arbitrarily chosen by the user)"
            },
            "digests": {
                "type": "object",
                "title": "File paths and their digests",
                "patternProperties": {
                    ".*": {
                        "type": "array",
                        "title": "Path of a valid file",
                        "items": {
                            "type": "string",
                            "title": "Hash of an valid file"
                        }
                    }
                }
            },
            "excludes": {
                "type": "array",
                "title": "Excluded file paths",
                "items": {
                    "type": "string",
                    "format": "regex"
                }
            },
            "keyrings": {
                "type": "object",
                "patternProperties": {
                    ".*": {
                        "type": "string",
                        "title": "Hash of the content in the keyring"
                    }
                }
            },
            "ima-buf": {
                "type": "object",
                "title": "Validation of ima-buf entries",
                "patternProperties": {
                    ".*": {
                        "type": "string",
                        "title": "Hash of the ima-buf entry"
                    }
                }
            },
            "verification-keys": {
                "type": "array",
                "title": "Public keys to verify IMA attached signatures",
                "items": {
                    "type": "string"
                }
            },
            "ima": {
                "type": "object",
                "title": "IMA validation configuration",
                "properties": {
                    "ignored_keyrings": {
                        "type": "array",
                        "title": "Ignored keyrings for key learning",
                        "description": "The IMA validation can learn the used keyrings embedded in the kernel. Use '*' to never learn any key from the IMA keyring measurements",
                        "items": {
                            "type": "string",
                            "title": "Keyring name"
                        }
                    },
                    "log_hash_alg": {
                        "type": "string",
                        "title": "IMA entry running hash algorithm",
                        "description": "The hash algorithm used for the running hash in IMA entries (second value). The kernel currently hardcodes it to sha1.",
                        "const": "sha1"
                    }
                },
                "required": ["ignored_keyrings", "log_hash_alg"],
                "additionalProperties": false
            }
        },
        "required": ["meta", "release", "digests", "excludes", "keyrings", "ima", "ima-buf", "verification-keys"],
        "additionalProperties": false
    }


Remotely Provision Agents
-------------------------

Now that we have our runtime policy available, we can send it to the verifier.

.. note::
  If you're using a TPM Emulator (for example with the ansible-keylime-tpm-emulator, you will also need
  to run the keylime ima emulator. To do this, open a terminal and run :code:`keylime_ima_emulator`

Using the :code:`keylime_tenant` we can send the runtime policy as
follows::

  touch payload  # create empty payload for example purposes
  keylime_tenant -c add --uuid <agent-uuid> -f payload --runtime-policy /path/to/policy.json

.. note::
  If your agent is already registered, you can use :code:`-c update`

How can I test this?
--------------------

Create a script that does anything (for example :code:`echo "hello world"`) that is not
present in your runtime policy. Run the script as root on the
agent machine. You will then see the following output on the verifier showing
the agent status change to failed::

  keylime.tpm - INFO - Checking IMA measurement list...
  keylime.ima - WARNING - File not found in allowlist: /root/evil_script.sh
  keylime.ima - ERROR - IMA ERRORS: template-hash 0 fnf 1 hash 0 good 781
  keylime.cloudverifier - WARNING - agent D432FBB3-D2F1-4A97-9EF7-75BD81C00000 failed, stopping polling


IMA File Signature Verification
-------------------------------

Keylime supports the verification of IMA file signatures, which also helps to
detect modifications on immutable files and can be used to complement or even
replace the allowlist of hashes in the runtime policy if all relevant
executables and libraries are signed. However, the set up of a system that
has *all* files signed is beyond the scope of this documentation.

In the following we will show how files can be signed and how a system with
signed files must be registered. We assume that the system has already been
set up for runtime-integrity monitoring following the above steps and that the
system would not show any errors on the Keylime Verifier side. It should not
be registered with the keylime verifier at this point. If it is, we now
deregister it::

   keylime_tenant -c delete -u <agent-uuid>

Our first step is to enable IMA Appraisal in Linux. Recent Fedora kernels for
example have IMA Appraisal support built-in but not activated. To enable it,
we need to add the following Linux kernel parameters to the Linux boot command
line::

  ima_appraise=fix ima_template=ima-sig ima_policy=tcb

For this we edit `/etc/default/grub` and append the above parameters to
the `GRUB_CMDLINE_LINUX` line and then recreate the system's grub configuration
file with the following command::

  sudo grub2-mkconfig -o /boot/grub2/grub.cfg

IMA will be in IMA Appraisal fix-mode when the system is started up the next
time. Fix-mode, unlike enforcement mode, does not require that all files be
signed but will give us the benefit that the verifier receives all
file signatures of signed executables.

For IMA Appraisal to append the file signatures to the IMA log, we need to
append the following line to the above IMA policy::

  appraise func=BPRM_CHECK fowner=0 appraise_type=imasig

We now create our IMA file signing key using the following commands::

  openssl genrsa -out ima-filesigning.pem 2048
  openssl rsa -in ima-filesigning.pem -pubout -out ima-pub.pem

Next, we determine the hash (sha1 or sha256) that IMA is using for file
measurements by looking at the IMA measurement log and then use evmctl to sign
a demo executable that we derive from the echo tool::

  sudo dnf -y install ima-evm-utils
  cp /bin/echo ./myecho
  sudo evmctl ima_sign --key ima-filesigning.pem -a <hash> myecho

.. note::
  It is important that we use the same hash for signing the file
  that IMA also uses for file measurements. In the case we use 'sha1'
  since the IMA measurement log further above shows sha1 filedata-hashes
  in the 4th column. On more recent systems we would likely use 'sha256'.

.. note::
  If the IMA measurement log contains invalid signatures, the system
  will have to be rebooted to start over with a clean log that the
  Keylime Verifier can successfully verify.

  Invalid signatures may for example be in the log if executables were
  accidentally signed with the wrong hash, such as sha1 instead of sha256.
  In this case they all need to be re-signed to match the hash that IMA is
  using for file signatures.

  Another reason for an invalid signature may be that a file was
  modified after it was signed. Any file modification will invalidate
  the signature. Similarly, a malformatted or altered *security.ima*
  extended attribute will lead to a signature verification failure.

  Yet another reason may be that an unknown key was used for signing
  files. In this case the system should be re-registered with that
  additional key using the Keylime tenant tool.

To verify that the file has been properly signed, we can use the
following command, which will show the security.ima extended attribute's
value::

  getfattr -m ^security.ima --dump myecho

We now reboot the machine::

  reboot

After the reboot the IMA measurement log should not have any measurement of the
`myecho` tool. The following command should not return anything::

   grep myecho /sys/kernel/security/ima/ascii_runtime_measurements

We now create a new policy that includes the signing key using the :code:`keylime_create_policy` tool::

  keylime_create_policy -B /path/to/runtime_policy.json -A /path/to/ima-pub.pem  -o /output/path/runtime_policy_with_key.json

After that we register the agent with the new policy::

  keylime_tenant -c add --uuid <agent-uuid> -f payload --runtime-policy /path/to/runtime_policy_with_key.json

We can now execute the :code:`myecho` tool as root::

   sudo ./myecho

At this point we should not see any errors on the verifier side and
there should be one entry of 'myecho' in the IMA measurement log that contains
a column after the file path containing the file signature::

   grep myecho /sys/kernel/security/ima/ascii_runtime_measurements

To test that signature verification works, we can now invalidate the
signature by *appending* a byte to the file and executing it again::

   echo >> ./myecho
   sudo ./myecho

We should now see two entries in the IMA measurement log. Each one should have
a different measurement::

  grep myecho /sys/kernel/security/ima/ascii_runtime_measurements

The verifier log should now indicating a bad file signature::

  keylime.tpm - INFO - Checking IMA measurement list on agent: D432FBB3-D2F1-4A97-9EF7-75BD81C00000
  keylime.ima - WARNING - signature for file /home/test/myecho is not valid
  keylime.ima - ERROR - IMA ERRORS: template-hash 0 fnf 0 hash 0 bad-sig 1 good 3042
  keylime.cloudverifier - WARNING - agent D432FBB3-D2F1-4A97-9EF7-75BD81C00000 failed, stopping polling


Using Key Learning to Verify Files
----------------------------------

Note: The following has been tested with RHEL 9.3 and keylime 7.3. It is
      work-in-progress on CentOS and Fedora.

Using key learning to verify files requires that files logged by IMA are
appropriately signed. If files are not signed or have a bad signature then
they must be either in the exclude list of the runtime policy or their hashes
must be part of the runtime policy. It should also be noted that IMA signature
verification provides lock-down of a system and ensures the provenance of
files from a trusted source but, unlike file hashes, does not provide
protection for file renaming or replacing files and signatures with other
versions (downgrading).

For the following setup we use RHEL 9.3 since this distribution carries file
signatures in its rpm packages and the Dracut scripts have been added to load
the IMA signature verification keys onto the :code:`.ima` keyring.

All below steps are run as `root`.

To ensure that file signatures are installed when packages are installed,
run the following command::

   dnf -y install rpm-plugin-ima

Since some packages did not carry file signatures until recently, update
all packages to ensure that the signatures are installed::

   dnf -y update

In case the system was previously not installed with file signatures, run
the following command to reinstall all packages with file signatures::

   dnf -y reinstall \*

To verify whether a particular file has its file signature installed use
the following command to display the contents of :code:`security.ima`. If
nothing is displayed then this file misses its file signature::

   getfattr -m ^security.ima -e hex --dump /usr/bin/bash

We must setup the system with the kernel command line option
:code:`ima_template=ima-sig` so that IMA signatures become part of the measurement
log. It is not necessary to enable signature enforcement on the system, measuring
executed applications is sufficient for the purpose of 'key learning'. For
this we edit :code:`/etc/default/grub` and adjust the following line::

   GRUB_CMDLINE_LINUX="rhgb quiet ima_template=ima-sig"

Then run the following command to update the kernel command line options::

   grub2-mkconfig -o /boot/grub2/grub.conf   # grub.cfg on CentOS/RHEL

Set the following IMA policy in :code:`/etc/ima/ima-policy` when systemd
will load the policy::

   # PROC_SUPER_MAGIC
   dont_measure fsmagic=0x9fa0
   # SYSFS_MAGIC
   dont_measure fsmagic=0x62656572
   # DEBUGFS_MAGIC
   dont_measure fsmagic=0x64626720
   # TMPFS_MAGIC
   dont_measure fsmagic=0x01021994
   # RAMFS_MAGIC
   dont_measure fsmagic=0x858458f6
   # SECURITYFS_MAGIC
   dont_measure fsmagic=0x73636673
   # SELINUX_MAGIC
   dont_measure fsmagic=0xf97cff8c
   # CGROUP_SUPER_MAGIC
   dont_measure fsmagic=0x27e0eb
   # OVERLAYFS_MAGIC
   # when containers are used we almost always want to ignore them
   dont_measure fsmagic=0x794c7630

   # Measure and log keys loaded onto the .ima keyring
   measure func=KEY_CHECK keyrings=.ima
   # Measure and log executables
   measure func=BPRM_CHECK
   # Measure and log shared libraries
   measure func=FILE_MMAP mask=MAY_EXEC

Copy IMA signature verification key(s) so that Dracut scripts can load
the keys onto the :code:`.ima` keyring early during system startup::

   mkdir -p /etc/keys/ima
   cp /usr/share/doc/kernel-keys/$(uname -r)/ima.cer /etc/keys/ima # RHEL/CentOS

Enable the IMA Dracut scripts in the initramfs::

   dracut --kver $(uname -r) --force --add integrity

Then reboot the system::

   reboot

Once the system has been rebooted it must show at least two entries in the IMA
log where keys were loaded onto the .ima keyring:

   grep -E " \.ima " /sys/kernel/security/ima/ascii_runtime_measurements

The first entry represents the Linux kernel signing key and the second entry
is the IMA file signing key.

We now create the policy::

   grep \
     -E "(boot_aggregate| ima-buf )" \
     /sys/kernel/security/ima/ascii_runtime_measurements > trimmed_ima_log

   keylime_create_policy -k -m ./trimmed_ima_log -o mypolicy.json

The 1st command creates a trimmed-down IMA measurement log that only
contains the boot_aggregate and ima-buf entries. The latter show the key(s)
that were loaded onto the :code:`.ima` keyring.

The 2nd command creates the runtime policy that holds the boot_aggregate
entry and a hash over keys that were loaded onto the .ima keyring. This
hash is used to verify that only trusted keys are learned.

We can now start to monitor this system::

   touch payload  # create empty payload for example purposes
   keylime_tenant -c update --uuid <agent-uuid> -f payload --runtime-policy ./mypolicy.json

In case the verification of the system fails we need to inspect the
verifier log and add those files to the :code:`trimmed_ima_log` that failed
verification. Assuming files with the filename pattern :code:`livesys` failed
verification we repeat the steps above as follows by adding files
with the file pattern :code:`livesys` to the trimmed log. These files will then
be verified using their hashes rather than signatures. Another possibility
would be to add these files to the list of excluded files.
We may need to repeat the following steps until the system passes
verification::


   grep \
     -E "(boot_aggregate| ima-buf |livesys)" \
     /sys/kernel/security/ima/ascii_runtime_measurements > trimmed_ima_log

   keylime_create_policy -k -m ./trimmed_ima_log -o mypolicy.json

   keylime_tenant -c update --uuid <agent-uuid> -f payload --runtime-policy ./mypolicy.json


To trigger a verification failure an unsigned application can be started::

   cat <<EOF > test.sh
   #!/usr/bin/env bash
   echo Test
   EOF

   chmod 0755 test.sh

   ./test.sh

To re-enable the verification of the system the policy needs to be updated
to contain :code:`test.sh` and possibly all other applications that are not
signed:

   grep \
     -E "(boot_aggregate| ima-buf |test\.sh)" \
     /sys/kernel/security/ima/ascii_runtime_measurements > trimmed_ima_log

   keylime_create_policy -k -m ./trimmed_ima_log -o mypolicy.json

   keylime_tenant -c update --uuid <agent-uuid> -f payload --runtime-policy ./mypolicy.json


Legacy allowlist and excludelist Format
---------------------------------------
Since Keylime 6.6.0 the old JSON and flat file formats for runtime policies are deprecated.
Keylime provides with :code:`keylime_convert_runtime_policy` a utility to convert those into the new format.
