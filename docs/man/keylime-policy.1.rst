==============
keylime-policy
==============

------------------------------------------
Keylime policy creation and signing tool
------------------------------------------

:Manual section: 1
:Author: Keylime Developers
:Date: September 2025

SYNOPSIS
========

**keylime-policy** {create,sign} [*OPTIONS*]

(Requires root privileges, use with sudo)

DESCRIPTION
===========

keylime-policy is a utility for creating and signing Keylime policies. It supports creating
runtime policies (for IMA/filesystem attestation) and measured boot policies (for boot-time
attestation), as well as signing runtime policies using DSSE (Dead Simple Signing Envelope).

COMMANDS
========

**keylime-policy create runtime** [*OPTIONS*]

   Create runtime policies from filesystem, allowlists, RPM repositories, or IMA measurement lists.

   Options:

   **-o, --output** *OUTPUT*
      Output file (defaults to stdout)

   **-p, --base-policy** *BASE_POLICY*
      Merge new data into existing JSON runtime policy

   **-k, --keyrings**
      Create keyrings policy entries

   **-b, --ima-buf**
      Process ima-buf entries other than keyrings

   **-a, --allowlist** *ALLOWLIST*
      Read checksums from plain-text allowlist

   **-e, --excludelist** *EXCLUDE_LIST_FILE*
      Add IMA exclude list to policy

   **-m, --ima-measurement-list** *[IMA_MEASUREMENT_LIST]*
      Use IMA measurement list for hash/keyring extraction

   **--ignored-keyrings** *IGNORED_KEYRINGS*
      Ignore specified keyring (repeatable)

   **--add-ima-signature-verification-key** *IMA_SIGNATURE_KEYS*
      Add x509/key to tenant_keyring (repeatable)

   **--show-legacy-allowlist**
      Display digests in legacy allowlist format

   **-v, --verbose**
      Set log level to DEBUG

   Filesystem scanning:

   **--algo** *{sha1,sha256,sha384,sha512,sm3_256}*
      Checksum algorithm

   **--ramdisk-dir** *RAMDISK_DIR*
      Path to initrds (e.g., /boot)

   **--rootfs** *ROOTFS*
      Path to root filesystem (e.g., /)

   **-s, --skip-path** *SKIP_PATH*
      Comma-separated directories to skip

   Repository scanning:

   **--local-rpm-repo** *LOCAL_RPM_REPO*
      Local RPM repository directory

   **--remote-rpm-repo** *REMOTE_RPM_REPO*
      Remote RPM repository URL

**keylime-policy create measured-boot** [*OPTIONS*]

   Create measured boot reference state policies from UEFI event logs.

   Options:

   **-e, --eventlog-file** *EVENTLOG_FILE*
      Binary UEFI eventlog (required)

   **--without-secureboot, -i**
      Create policy without SecureBoot (MeasuredBoot only)

   **-o, --output** *OUTPUT*
      Output path for generated measured boot policy

**keylime-policy sign runtime** [*OPTIONS*]

   Sign runtime policies using DSSE.

   Options:

   **-o, --output** *OUTPUT_FILE*
      Output file for DSSE-signed policy

   **-r, --runtime-policy** *POLICY*
      Runtime policy file to sign (required)

   **-k, --keyfile** *KEYFILE*
      EC private key for signing

   **-p, --keypath** *KEYPATH*
      Output filename for created private key

   **-b, --backend** *{ecdsa,x509}*
      DSSE backend (ecdsa or x509)

   **-c, --cert-outfile** *CERT_OUTFILE*
      Output file for x509 certificate (x509 backend)

EXAMPLES
========

**Create runtime policy from filesystem:**

.. code-block:: bash

   sudo keylime-policy create runtime --rootfs / --output my-policy.json

**Create runtime policy from allowlist:**

.. code-block:: bash

   sudo keylime-policy create runtime --allowlist my-allowlist.txt --output policy.json

**Create measured boot policy:**

.. code-block:: bash

   sudo keylime-policy create measured-boot -e /sys/kernel/security/tpm0/binary_bios_measurements -o mb-policy.json

**Sign runtime policy:**

.. code-block:: bash

   sudo keylime-policy sign runtime -r policy.json -k signing-key.pem -o signed-policy.json

ENVIRONMENT
===========

**KEYLIME_LOGGING_CONFIG**
   Path to logging.conf

NOTES
=====

- All operations require root privileges
- Runtime policies use JSON format
- Measured boot policies require binary UEFI event logs
- DSSE signing supports both ECDSA and x509 backends

SEE ALSO
========

**keylime_tenant**\(1), **keylime_verifier**\(8), **keylime_registrar**\(8)

BUGS
====

Report bugs at https://github.com/keylime/keylime/issues
