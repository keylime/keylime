User Selected PCR Monitoring
============================

.. warning::
    This page is still under development and not complete. It will be so until
    this warning is removed.

Using use the `tpm_policy` feature in Keylime, it is possible to monitor a
remote machine for any given PCR.

This can be used for Trusted Boot checks for both the `rhboot` shim loader and
Trusted Grub 2.

.. note::
    On larger deployments the PCR values might be insufficient. In this case use
    the UEFI event log for measured boot: :doc:`use_measured_boot`.

How to use
----------

Select which PCRs you would like Keylime to measure, by using the `tpm2_pcrread` from the `tpm2-tools <https://github.com/tpm2-software/tpm2-tools>`_
tool.

You can add a node to using `keylime_tenant`::

    # First create a payload to send to the agent (in our case this is empty)
    touch payload

    # Now actually add the node
    keylime_tenant -c add \
    --uuid d432fbb3-d2f1-4a97-9ef7-75bd81c00000 \
    -f payload \
    --tpm_policy '{"22":["0000000000000000000000000000000000000001","0000000000000000000000000000000000000000000000000000000000000001","000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001","ffffffffffffffffffffffffffffffffffffffff","ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"],"15":["0000000000000000000000000000000000000000","0000000000000000000000000000000000000000000000000000000000000000","000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"]}'

rhboot shim-loader
------------------

The following is sourced from the `rhboot shim repository <https://github.com/rhboot/shim/blob/master/README.tpm>`_
please visit the upstream README to ensure information is still accurate

The following PCRs are extended by shim:

PCR4:
    - the Authenticode hash of the binary being loaded will be extended into
      PCR4 before SB verification.
    - the hash of any binary for which Verify is called through the shim_lock
      protocol

PCR7:
    - Any certificate in one of our certificate databases that matches a binary
      we try to load will be extended into PCR7.  That includes:

          - DBX - the system denylist, logged as "dbx"
          - MokListX - the Mok denylist, logged as "MokListX"
          - vendor_dbx - shim's built-in vendor denylist, logged as "dbx"
          - DB - the system allowlist, logged as "db"
          - MokList the Mok allowlist, logged as "MokList"
          - vendor_cert - shim's built-in vendor allowlist, logged as "Shim"
          - shim_cert - shim's build-time generated allowlist, logged as "Shim"

    - MokSBState will be extended into PCR7 if it is set, logged as
      "MokSBState".

PCR8:
    - If you're using the grub2 TPM patchset we cary in Fedora, the kernel command
      line and all grub commands (including all of grub.cfg that gets run) are
      measured into PCR8.

PCR9:
    - If you're using the grub2 TPM patchset we cary in Fedora, the kernel,
      initramfs, and any multiboot modules loaded are measured into PCR9.

PCR14:
    - MokList, MokListX, and MokSBState will be extended into PCR14 if they are
      set.

