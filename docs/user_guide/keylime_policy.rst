===========================
The ``keylime-policy`` tool
===========================

``keylime-policy`` is a tool that is able to create both runtime and
measured boot policies, as well as sign runtime policies. It emerged by
consolidating this existing functionality that was available from a few
scripts scattered across the Keylime source tree.

Creating runtime policies
=========================

A runtime policy in its most basic form is a set of "golden" cryptographic
hashes of files' un-tampered state or of keys that may be loaded onto
keyrings for IMA verification (:ref:`see more on Keylime Runtime Policies<keylime-runtime-policies-label>`).

To create runtime policies, we use the ``keylime-policy create runtime`` subcommand. This subcommand supports multiple options, which can be seen by issuing the command ``keylime-policy create runtime --help``. The next table list some of the common options:


.. list-table:: Common options for creating runtime policies
    :header-rows: 1

    * - Option
      - Description

    * - ``-o`` or ``--output``
      - This option specifies where the tool will output the data.
        If not specified, it will print the data to the standard output

    * - ``-m`` or ``--ima-measurement-list``
      - This option specifies an IMA measurement list to use for obtaining
        data such as hashes and keyring. If not specified, it will attempt
        to use ``/sys/kernel/security/ima/ascii_runtime_measurements`` by
        default. If you want an empty list, you can use ``/dev/null`` instead

    * - ``-a`` or ``--alowlist``
      - Indicates a plain text allow list to read checksums from

    * - ``-e`` or ``--excludelist``
      - This option specifies an exclude list file whose contents will be added to the policy.
        Files and directories matching the entries in this list -- which also supports Python regular expressions with one regular expression per line -- will be *ignored* by Keylime in the sense that it will not fail validation if those files change

    * - ``--ramdisk-dir``
      - This option specifies a path where the initial ramdisks (e.g. initrds or initramfs') are located, e.g.: ``/boot``

    * - ``--rootfs``
      - This option specifies a path to a root file system, e.g.: ``/``

    * - ``--local-rpm-repo``
      - This option specifies a local RPM repository directory; ``keylime-policy`` will create a runtime policy based on the files that are part of the RPMs of this repo

    * - ``--remote-rpm-repo``
      - This option specifies a remote RPM repository; similar to ``--local-rpm-repo``, ``keylime-policy`` will create a runtime policy based on the files that are part of the RPMs of this repo

Let us look at some examples next:

Converting a legacy allow list into a runtime policy
---------------------------------------------------

Legacy allow lists are files in which each line is of the form ``<digest> <file>``. To convert such a file -- *allowlist.txt*, in this example -- into a runtime policy, you can do the following:

.. code-block:: sh

   keylime-policy create runtime --allowlist allowlist.txt

Converting an exclude list into a runtime policy
------------------------------------------------

An exclude list file contains a list of files or directories that are to be excluded from Keylime measurements. To convert an exclude list named **excludelist.txt** into a runtime policy, issue the following command:

.. code-block:: sh

   keylime-policy create runtime --excludelist excludelist.txt


Creating a runtime policy with files from a rootfs
--------------------------------------------------

To create a runtime policy including files from a given root file system, specify the ``--rootfs <directory>`` argument, as in the next example:

.. code-block:: sh

   keylime-policy create runtime --rootfs /mnt/rootfs

Creating a runtime policy with files from the initial ramdisks
--------------------------------------------------------------

To have a runtime policy including files from the initial ramdisks (initrd, initramfs), specify the direcory where they are located with ``--ramdisk-dir``:


.. code-block:: sh

   keylime-policy create runtime --ramdisk-dir /boot


Creating a runtime policy from RPM repositories
-----------------------------------------------

The ``keylime-policy`` tool is able to create runtime policies from RPM repositories, both local and remote:

Local repository
++++++++++++++++

To create a policy from a local RPM repository, we can use the ``--local-rpm-repo`` switch:

.. code-block:: sh

   keylime-policy create runtime --local-rpm-repo /tmp/local-rpm-repo

Note that, in this case, ``/tmp/local-rpm-repo`` should be a valid RPM repository, i.e., it should contain the ``repodata`` subdirectory with the relevant metadata files, such as ``repomd.xml``.

For reference, `createrepo_c <https://github.com/rpm-software-management/createrepo_c>`_ is a tool capable of creating such repositories.


Remote repository
^^^^^^^^^^^^^^^^^

We can also create policies from remote RPM repositories, and in this case, the relevant ``keylime-policy`` switch is ``--remote-rpm-repo``:

.. code-block:: sh

   keylime-policy create runtime --remote-rpm-repo https://composes.stream.centos.org/stream-10/production/latest-CentOS-Stream/compose/BaseOS/x86_64/os/


Similar to when we created a policy from a local repository, we need to make sure to give the address of a valid RPM repository to ``keylime-policy``.

Also note that *this operation may take a long time*, especially in the case the ``filelists-ext`` metadata is not available from the repository.


Creating a runtime policy from multiple sources
-----------------------------------------------

The previous examples show how to generate a runtime policy based on a *single source of data*, e.g., from a local or remote RPM repository, from a legacy allowlist, from a root file system, etc. The ``keylime-policy`` tool is able to combine multiple sources while generating the runtime policy, as we can see in the next example:


.. code-block:: sh

   keylime-policy create runtime --rootfs /mnt/rootfs --ramdisk-dir /boot --allowlist allowlist.txt --excludelist excludelist.txt --local-rpm-repo /tmp/local-rpm-repo --remote-rpm-repo https://composes.stream.centos.org/stream-10/production/latest-CentOS-Stream/compose/BaseOS/x86_64/os/

Have in mind that, depending on the options used, the operation may take a long time.


Creating measured boot policies
===============================

``keylime-policy`` supports consuming the UEFI event log file to generate a JSON file for a measured boot policy that can be later tweaked and customized to make it more generic, through the ``keylime-policy create measured-boot`` subcommand. The following table list the available options for it:

.. list-table:: Options for creating measured boot policies
    :header-rows: 1

    * - Option
      - Description

    * - ``-o`` or ``--output``
      - This option specifies where the tool will output the data.
        If not specified, it will print the data to the standard output

    * - ``-e`` or ``--eventlog-file``
      - This option specifies the binary UEFI event log file, which is normally
        ``/sys/kernel/security/tpm0/binary_bios_measurements``.
        This option is **required**

    * - ``-i`` or ``--without-secureboot``
      - This option indicates you want to create a measured boot reference policy without SecureBoot (only measured boot)

Create a measured boot policy
-----------------------------

To create a measured boot policy with ``keylime-tool`` using the ``/sys/kernel/security/tpm0/binary_bios_measurements`` event log file, you can issue the following command:

.. code-block:: sh

   keylime-policy create measured-boot -e /sys/kernel/security/tpm0/binary_bios_measurements

It may be required to add the ``-i`` switch to the above command, if the provided event log file has Secure Boot disabled; in this case, you should see a message like this, after running the previous command: *Provided eventlog has SecureBoot disabled, but -i flag was not set*.


Signing runtime policies
========================

``keylime-policy`` also supports signing Keylime runtime policies with `DSSE (Dead Simple Signing Envelope) <https://github.com/secure-systems-lab/dsse>`_ through the ``keylime-policy sign runtime`` subcommand. The available options for this subcommand are listed next:

.. list-table:: Options for signing runtime policies
    :header-rows: 1

    * - Option
      - Description

    * - ``-o`` or ``--output``
      - This option specifies where the tool will output the data.
        If not specified, it will print the data to the standard output

    * - ``-r`` or ``--runtime-policy``
      - This option specifies the location of the runtime policy file.
        This option is **required**

    * - ``-k`` or ``--keyfile``
      - This option specifies the Elliptic-curve private key to sign the policy with

    * - ``-p`` or ``keypath``
      - This option specifies where the private key will be written to, if one is not specified via the ``--keyfile`` argument

    * - ``-b`` or ``--backend``
      - This option specifies the DSSE backend to use, which can be either ``ecdsa`` or ``x509``.
        The default backend is `ecdsa`

    * - ``-c`` or ``--cert-outfile``
      - This option specifies the output file for the x509 certificate, when using the ``x509`` DSSE backend


When signing runtime policies, we need to select a DSSE backend, which can be either `ecdsa` or `x509`; if we don't explicitly select one of them, ``keylime-policy`` will use ``ecdsa`` as the default option.

The only strictly required option is the runtime policy to be signed, which can be provided via the ``-r`` switch. If you select the ``x509`` DSSE backend, you will also need to provide the output file for the x509 certificate with the ``-c`` option.

As for the private Elliptic-curve key to be used for the signing, you can either specify one with the ``-k`` switch, or ``keylime-policy`` will generate one for you. If it does generate one automatically, it will save this key with the name ``keylime-ecdsa-key.pem``, in the current directory; if you want the generated key to have a different file name, you can specify the desired file name with the ``-p`` switch.

For the next examples, we will sign the ``policy.json`` runtime policy file and will **not** specify an output file with ``-o``, so ``keylime-policy`` should output its result to *stdout*.


Signing a runtime policy with a provided private key
----------------------------------------------------

In this example, we have an EC private key ``ec-p521-private.pem`` and want to use it to sign our policy:

.. code-block:: sh

   keylime-policy sign runtime -r policy.json -k ec-p521-private.pem


Signing a runtime policy without providing a private key
--------------------------------------------------------

In this other example, we will not provida en EC private key, so ``keylime-policy`` will generate one for us and save it as ``keylime-ecdsa-key.pem``:


.. code-block:: sh

   keylime-policy sign runtime -r policy.json

You can verify that you now have a ``keylime-ecdsa-key.pem`` file with a content that looks like this:

.. code-block::

   -----BEGIN EC PRIVATE KEY-----
   <key content here>
   -----END EC PRIVATE KEY-----

Not providing a private key but specifying a custom name for the autogenerated key
----------------------------------------------------------------------------------

Here we will not specify a private EC key for the signing, but we want the autogenerated key to have the name ``autogen-ec-key.pem``:

.. code-block:: sh

   keylime-policy sign runtime -r policy.json -p autogen-ec-key.pem

You can verify that you now have a ``autogen-ec-key.pem`` private key file.


Signing a policy using the x509 DSSE backend
--------------------------------------------

In this example we will use the x509 DSSE backend. To do that, we need to specify the backend with `-b x509` and we also need to specify the output file for the x509 certificate with the `-c` switch:

.. code-block:: sh

   keylime-policy sign runtime -r policy.json -k ec-p521-private.pem -b x509 -c x509.pem

You can verify that you now have a ``x509.pem`` file with the contents that look like this:

.. code-block::

   -----BEGIN CERTIFICATE-----
   <certificate content here>
   -----END CERTIFICATE-----


