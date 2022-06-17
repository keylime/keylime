Run-time Integrity Monitoring
=============================

Keylimes run-time integrity monitoring requires the set up of Linux IMA.

You should refer to your Linux Distributions documentation to enable IMA, but
as a general guide most recent versions already have `CONFIG_IMA` toggled to
`Y` as a value during Kernel compile.

It is then just a case of deploying an `ima-policy` file. On a Fedora or Debian
system, the file is situated in `/etc/ima/ima-policy`.

For configuration of your IMA policy, please refer to the `IMA Documentation <https://github.com/torvalds/linux/blob/6f0d349d922ba44e4348a17a78ea51b7135965b1/Documentation/ABI/testing/ima_policy>`_

Within Keylime we use the following for demonstration::

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
  # MEASUREMENTS
  measure func=BPRM_CHECK
  measure func=FILE_MMAP mask=MAY_EXEC
  measure func=MODULE_CHECK uid=0

This default policy measures all executables in `bprm_check`, all files `mmapped`
executable in `file_mmap` and module checks.

Once your `ima-policy` is in place, reboot your machine (or even better have it
present in your image for first boot).

You can then verify IMA is measuring your system::

  # head -5 /sys/kernel/security/ima/ascii_runtime_measurements
  PCR                                  template-hash filedata-hash                                 filename-hint
  10 3c93cea361cd6892bc8b9e3458e22ce60ef2e632 ima-ng sha1:ac7dd11bf0e3bec9a7eb2c01e495072962fb9dfa boot_aggregate
  10 3d1452eb1fcbe51ad137f3fc21d3cf4a7c2e625b ima-ng sha1:a212d835ca43d7deedd4ee806898e77eab53dafa /usr/lib/systemd/systemd
  10 e213099a2bf6d88333446c5da617e327696f9eb4 ima-ng sha1:6da34b1b7d2ca0d5ca19e68119c262556a15171d /usr/lib64/ld-2.28.so
  10 7efd8e2a3da367f2de74b26b84f20b37c692b9f9 ima-ng sha1:af78ea0b455f654e9237e2086971f367b6bebc5f /usr/lib/systemd/libsystemd-shared-239.so
  10 784fbf69b54c99d4ae82c0be5fca365a8272414e ima-ng sha1:b0c601bf82d32ff9afa34bccbb7e8f052c48d64e /etc/ld.so.cache

Keylime IMA allowlists
----------------------

An allowlist is a set of "golden" cryptographic hashes of a files un-tampered
state or of keys that may be loaded onto keyrings.

The structure of the allowlist is a hash followed by a full POSIX path to the
file::

  ffe3ad4c395985d143bd0e45a9a1dd09aac21b91 /path/to/file

For a key that is expected to be loaded on a keyring with the name .ima an entry
may look like this::

  b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c %keyring:.ima

Keylime will load the allowlist into the Keylime Verifier. Keylime will then
poll tpm quotes to `PCR 10` on the agents TPM and validate the agents file(s)
state against the allowlist. If the object has been tampered with or an
unexpected key was loaded onto a keyring, the hashes will not match and Keylime
will place the agent into a failed state. Likewise, if any files invoke the actions
stated in `ima-policy` that are not matched in the allowlist, keylime will place
the agent into a failed state.

Generate an allowlist
~~~~~~~~~~~~~~~~~~~~~

Keylime provides a script to generate allowlists from `initramfs`, but this is
only a guide. We encourage developers / users of Keylime to be creative and come
up with their own process for securely creating and maintaining an allowlist.

The `create_allowlist.sh` script is `available here <https://github.com/keylime/python-keylime/blob/master/keylime/create_allowlist.sh>`_

Run the script as follows::

  # create_allowlist.sh  allowlist.txt [hash-algo]

With `[hash-algo]` being `sha1sum`, `sha256sum` (note, you need the OpenSSL app
installed to have the shasum CLI applications available).

This will then result in `allowlist.txt` being available for Agent provisioning.

.. warning::
    It’s best practice to create the allowlist in a secure environment. Ideally,
    this should be on a fully encrypted, air gapped computer that is permanently
    isolated from the Internet. Disable all network cards and sign the allowlist
    hash to ensure no tampering occurs when transferring to other machines.

Alongside building an allowlist from `initramfs`, you could also generate good
hashes for your applications files or admin scripts that will run on the
remotely attested machine.

Excludes List
~~~~~~~~~~~~~

An excludes list can be utilised to exclude any file or path. The excludes list
uses the Python regular expression standard, where the syntax is similar to
those found in Perl. Note that this syntax is different from POSIX basic
regular expressions. For example the `tmp` directory can be ignored using::

  /tmp/.*

Allowlist entries for keys
~~~~~~~~~~~~~~~~~~~~~~~~~~

Allowlist entries for keys expected to be loaded onto keyrings can be generated
by hashing the files of keys like this::

   sha256sum /etc/keys/ima/rsakey-rsa.crt.der

As previously shown, the allowlist entry should be formed of the hash (sha256) and
the prefix '%keyring:' in front of the keyring the key will be loaded onto::

  b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c %keyring:.ima

The following rule should be added to the IMA policy so that IMA reports keys
loaded onto keyrings .ima and .evm (since Linux 5.6)::

   measure func=KEY_CHECK keyrings=.ima|.evm


IMA Keylime JSON format
~~~~~~~~~~~~~~~~~~~~~~~

The tenant parses the allow and exclude list into a JSON object that is then sent to the verifier.
Depending of the use case the object can also be constructed manually instead of using the tenant.

.. sourcecode:: json

    {
       "allowlist":{
          "meta":{
             "version":"ALLOWLIST_CURRENT_VERSION"
          },
          "release":"RELEASE_VERSION",
          "hashes":{
             "/file/path":[
                "VALID_HASH1",
                "VALID_HASH2"
             ]
          },
          "keyrings":{
             "LINUX_KEYRING":[
                "VALID_HASH3"
             ]
          },
          "ima":{
             "ignored_keyrings":[
                "IGNORED_KEYRING"
             ]
          }
       },
       "exclude":[
          "REGEX1, REGEX2"
       ]
    }


- `ALLOWLIST_CURRENT_VERSION` (integer): current version of the allow list format (latest is 2).
- `RELEASE_VERSION` (integer): release version of this allowlist.
- `hashes`: dictionary of the file path that should be validated as key and a list of valid hashes as entry.
- `VALID_HASHn`: valid hash of the file or keyring that is measured
- `keyrings`: dictionary of the keyring that should be used for signature validation and a list of valid hashes as entry.
- `LINUX_KEYRING`: kernel keyring like `.ima` or `.evm`
- `ignored_keyrings`: successful validated keyrings are used for signature validation. Add `*` to disable all or add them one by one.
- `exclude`: list of regexes of files to exclude
- `REGEXn`: regex for excluding certain files (e.g. `/tmp/.*`)


Remotely Provision Agents
~~~~~~~~~~~~~~~~~~~~~~~~~

Now that we have our allowlist available, we can send it to the verifier.

.. note::
  If you're using a TPM Emulator (for example with the ansible-keylime-tpm-emulator, you will also need
  to run the keylime ima emulator. To do this, open a terminal and run `keylime_ima_emulator`

Using the `keylime_tenant` we can send the allowlist and our excludes list as
follows::

  keylime_tenant -v <verifier-ip> -t <agent-ip> -f /path/excludes.txt --uuid D432FBB3-D2F1-4A97-9EF7-75BD81C00000 --allowlist /path/allowlist.txt --exclude /path/excludes.txt

.. note::
  If your agent is already registered, you can use `-c update`

Should you prefer, you can set the values `allowlist` & `ima_excludelist`
within `/etc/keylime.conf`, you can then use `default` as follows::

  `keylime_tenant -v 127.0.0.1 -t neptune -f /root/excludes.txt --uuid D432FBB3-D2F1-4A97-9EF7-75BD81C00000 --allowlist default --exclude default`


How can I test this?
--------------------

Create a script that does anything (for example `echo "hello world"`) that is not
present in your allowlist or the excludes list. Run the script as root on the
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
replace the allowlist of hashes if all relevant executables and libraries are
signed. However, the set up of a system that has *all* files signed is beyond
the scope of this documentation.

In the following we will show how files can be signed and how a system with
signed files must be registered. We assume that the system has already been
set up for runtime-integrity monitoring following the above steps and that the
system would not show any errors on the Keylime Verifier side. It should not
be registered with the keylime verifier at this point. If it is, we now
deregister it::

   keylime_tenant -c delete -u D432FBB3-D2F1-4A97-9EF7-75BD81C00000

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

We now register the system and pass along the file signing key::

  keylime_tenant -v 127.0.0.1 -t neptune -f /root/excludes.txt \
    --uuid D432FBB3-D2F1-4A97-9EF7-75BD81C00000 --allowlist default --exclude default \
    --sign_verification_key ima-pub.pem

We can now execute the myecho tool as root::

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
