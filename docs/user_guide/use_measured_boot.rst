Use Measured Boot
=================

.. warning::
    This page is still under development and not complete. It will be so until
    this warning is removed.


Introduction
------------

In any real-world large-scale production environment, a large number of
different types of nodes will typically be found. The TPM 2.0 defines a
specific meaning - measurement of UEFI bios, measurement of boot device
firmware - for each of the lower-numbered PCRs (e.g., PCRs 0-9), as these are
extended during the multiple events of a measured boot log. However, simply
comparing the contents of these PCRs against a well-known "golden value"
becomes unfeasible. The reason for this is, in addition to the potentially
hundreds of variations due to node type, it can be experimentally demonstrated
that some PCRs (e.g, PCR 1) vary for each physical machine, if such machine is
netbooted (as it encodes the MAC address of the NIC used during boot.)

Fortunately, the UEFI firmware is now exposing the event log through an ACPI
table and a "recent enough" Linux kernel (e.g., 5.4 or later) is now consuming
this table and exposing this boot event log through the securityfs, typically
at the path `/sys/kernel/security/tpm0/binary_bios_measurements`. When combined
with `secure boot` and a "recent enough" version of grub (2.06 or later), the
aforementioned PCR set can be fully populated, including measurements of all
components, up to the `kernel` and `initrd`.

In addition to these sources of (boot log) data, a "recent enough" version of
`tpm2-tools` (5.0 or later) can be used to consume the contents of such logs
and thus rebuild the contents of PCRs [0-9] (and potentially PCRs [11-14]).

Implementation
--------------

Keylime can make use of this new capability in a very flexible manner. It can
allow the keylime operator (i.e. tenant) to provide a measured boot policy for
a keylime agent node and let the keylime verifier evaluate the policy against
the boot event log of that node. In theory, the measured boot policy could
contain both the reference state (i.e. reference data about the various boot events)
of the node and the rule/policy to evaluate the boot event log against that
reference state.

Keylime, at present, allows the operator to provide the reference state (a.k.a.
measured boot reference state) which is used by the policy engine 'elchecking'
(part of the verifier) to evaluate the boot event log according to the
rule/policy specified. The rule/policy to evaluate the boot event log against
the measured boot reference state is specified in `verifier.conf`, with
parameter named `measured_boot_policy_name`. The default value for it is
`accept-all`, meaning "just don't try to match the contents, just replay the log
and make sure the values of PCRs [0-9] and [11-14] match".

When the measured boot policy is provided by the operator while registering
an agent node, the following actions will be taken.

1. PCRs [0-9] and [11-14] will be included in the quote sent by `keylime_agent`
2. The `keylime_agent` will also send the contents of`/sys/kernel/security/tpm0/binary_bios_measurements`
3. The `keylime_verifier` will replay the boot log from step 2, ensuring the correct values for PCRs collected in step 1. Again, this is very similar to what it is done with "IMA logs" and PCR 10.
4. The very same `keylime_verifier` will take the boot log, now deemed "attested" and evaluate it against the measured boot policy, causing the attestation to fail if it does not conform.

How to use 
---------- 

The operator can provide the measured boot policy / measured boot reference state
by using the option '--mb-policy' with the command `keylime_tenant`.

The simplest way to test this functionality is by providing an empty
measured boot policy with the `accept-all` measured_boot_policy_name
specified in `verifier.conf`, which will cause the `keylime_verifier`
to simply skip the aforementioned step 4.

An example follows::

    echo "{}" > mb_policy.txt

    keylime_tenant -c add -t <AGENT IP> -v <VERIFIER IP> -u <AGENT UUID> --mb-policy ./mb_policy.txt

Note: please keep in mind that the IMA-specific options can be combined with
the above options in the example, resulting in a configuration where a
`keylime_agent` sent a quote with PCRs [0-15] and both logs (boot and IMA)

Evidently, to be fully used in a meaningful manner, keylime operators need to
provide their own measured boot policies and custom python module supporting
custom values of measured_boot_policy_name. The python module needs to be specified
with `measured_boot_imports` in the `verifier.conf`.

The most convenient way to create a measured boot policy is starting from the contents
of an UEFI boot log from a given node, and then tweak and customize it to make
more generic. Keylime includes a tool (under `scripts` directory) -
`create_mb_refstate` - which will consume a boot log and output a JSON file
for measured boot policy. An example follows::

   create_mb_refstate /sys/kernel/security/tpm0/binary_bios_measurements measured_boot_reference_state.json

   keylime_tenant -c add -t <AGENT IP> -v <VERIFIER IP> -u <AGENT UUID> --mb-policy ./measured_boot_reference_state.json

This measured boot reference state can be (as in the example above) consumed "as is", or it
can be tweaked to be made more generic (or even more strict, if the keylime
operator chooses so).

Keylime facilitates a framework (a.k.a. elchecking policy engine) specified
in `policies.py` under `keylime/mta/elchecking` directory, where some
"trivial" policies such as `accept-all` and `reject-all` are pre-defined.
The Domain-Specific Language (DSL) used by the framework are defined in
`tests.py` and an illustrative use of it can be seen in the policy
`example.py`, all under the same directory. This example policy was
crafted to be meaningful (i.e., with a relevant number of parameters tests) and
yet applicable to a large set of nodes. It consumes a measured boot policy such as
the one generated by the aforementioned tool or the
`example_reference_state.json`, located under the same directory.

Just to quickly exemplify what this policy does, it for instance tests if a
node has `SecureBoot` enabled (`tests.FieldTest("Enabled",
tests.StringEqual("Yes"))`) and if a node has a well-formed kernel command line
boot parameters (e.g., `tests.FieldTest("String",
tests.RegExp(r".*/grub.*"))`). The policy is well documented, and operators are
encouraged to just read through the comments in order to understand how the
tests are implemented.

While an operator can attempt to write its own policy from scratch, it is
recommended that one just copies `example.py` into `mypolicy.py`, change it as
required and then just points to this policy for `measured_boot_policy_name` in `verifier.conf`
for its own use.

Named Measured Boot Policy
----------------------------
Keylime allows the operator to store measured boot policies with names and use
the names to associate measured boot policies with various nodes. The policies are stored
in a database maintained by the keylime verifier. The operator can also list, view, update
and delete the policies stored.

Examples to add, update, show, delete and list named measuredboot policies::

   keylime_tenant -c addmbpolicy     -v <VERIFIER_IP>  --mb-policy-name <policy1_name> --mb-policy <policy1_file>

   keylime_tenant -c updatembpolicy  -v <VERIFIER_IP>  --mb-policy-name <policy1_name> --mb-policy <policy1_file2>

   keylime_tenant -c showmbpolicy    -v <VERIFIER_IP>  --mb-policy-name <policy1_name>

   keylime_tenant -c deletembpolicy  -v <VERIFIER_IP>  --mb-policy-name <policy1_name>

   keylime_tenant -c listmbpolicy    -v <VERIFIER_IP>

Operator can provide the name of an stored measured boot policy to use the policy
while registering a node as follows::

  keylime_tenant -c add -t <AGENT IP> -v <VERIFIER IP> -u <AGENT UUID> --mb-policy-name  <policy1_name>

If the poliy is not already stored, the following command to register the node will also
store the policy into the database::

  keylime_tenant -c add -t <AGENT IP> -v <VERIFIER IP> -u <AGENT UUID> --mb-policy-name <policy2_name> --mb-policy <policy2_file>

The following command to register the node will store the UUID of the node as the name
of the policy into the database::

  keylime_tenant -c add -t <AGENT IP> -v <VERIFIER IP> -u <AGENT UUID> --mb-policy <policy3_file>
