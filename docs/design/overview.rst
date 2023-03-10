===================
Overview of Keylime
===================

Keylime mainly consists of an agent, two server components (verifier and registrar) and a commandline tool the tenant.

Agent
-----

The agent is a service that runs on the operating system that should be attested.
It communicates with the TPM to enroll the AK and to generate quotes and
collects the necessary data like the UEFI and IMA event logs to make state attestation
possible.

The agent provides an interface to provision the device further once it was attested
successfully for the first time using the secure payload mechanism.
For more details see: :doc:`../user_guide/secure_payload`.

It is possible for the agent to listen to revocation events that are sent by the verifier
if an agent attestation failed. This is useful for environments where attested systems
directly communicate with each other and require that the other systems are trusted.
In this case a revocation message might change local policies so that the compromised
system cannot access any resources from other systems.

Registrar
---------
The agent registers itself in the registrar.
The registrar manages the agent enrollment process which includes
getting an UUID for the agent, collecting the `EK`:sub:`pub`, EK certificate and `AK`:sub:`pub` from an agent
and verifying that the `AK` belongs to the `EK` (using `MakeCredential` and `ActivateCredential`).


Once an agent has been registered in the registrar, it is ready to be enrolled for attestation.
The tenant can use the EK certificate to verify the trustworthiness of the TPM.

.. note::
    If `EK` or `AK` are mentioned outside of internal TPM signing operations, it usually
    references the `EK`:sub:`pub` or `AK`:sub:`pub` because it should not be possible
    extract the private keys out of the TPM.

.. note::
    The Keylime agent currently generates a `AK` on every startup and sends the EK and
    EK certificate. This is done to keep then design simple by not requiring a third
    party to verify the EK.
    The EK (and EK certificate) is required to verify the authenticity of the AK once
    and Keylime does not require a new AK but currently registration only with an AK
    is not enabled because the agent does not implement persisting the AK.

Verifier
--------
The verifier implements the actual attestation of an agent and sends revocation messages if an agent leaves the trusted
state.

Once an agent is registered for attestation (using the tenant or the API directly) the verifier continuously pulls
the required attestation data from the agent. This can include: a quote over the PCRs, the PCR values, NK public key,
IMA log and UEFI event log. After that the quote is validated additional validation of the data can be configured.

Static PCR values
"""""""""""""""""
The `tpm_policy` allows for simple checking of PCR values against a known good allowlist. In most cases this is only
useful when the boot chain does not change often, there is a way to retrieve the values beforehand
and the UEFI event log is unavailable.
More information can be found in :doc:`../user_guide/user_selected_pcr_monitoring`.

Measured Boot using the UEFI Event Log
""""""""""""""""""""""""""""""""""""""
On larger deployments it is not feasible to collect golden values for the PCR values used for measured boot. To make
attestation still possible Keylime includes a policy engine for validating the UEFI event log. This is the preferred
method because static PCR values are fragile because they change if something in the boot chain is updated (firmware,
Shim, GRUB, Linux kernel, initrd, ...). More information can be found in :doc:`../user_guide/use_measured_boot`.

IMA validation
""""""""""""""
Keylime allows to verify files measured by IMA against either a provided allowlist or a signature.
This makes it for example easy to attest all files that were executed by root.
More information can be found in :doc:`../user_guide/runtime_ima`.


Tenant
------
The tenant is a commandline management tool shipped by Keylime to manage agents.
This includes adding or removing the agent from attestation, validation of the EK certificate against a cert store and
getting the status of an agent. It also provides the necessary tools for the payload mechanism and revocation actions.

For all the features of the tenant see the output of ``keylime_tenant --help``.