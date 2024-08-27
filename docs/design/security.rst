====================
Attestation Security
====================

.. role:: raw-html(raw)
  :format: html

Keylime's core purpose is to verify the attested state of a system. The verification outcome (whether the attestation
is verified or not) may be used in various ways by the end user by integrating Keylime into their wider infrastructure,
for instance:

  * to produce alerts if an unauthorised change occurs somewhere in a user's fleet of machines (e.g., boot order is
    so configured that a server boots from an external drive);
    :raw-html:`<br>`

  * to authenticate a workload based on the state of the workload and the node on which it is running, in service of
    zero-trust principles; or
    :raw-html:`<br>`

  * to release keys from a key broker to unlock an encrypted data store once the data store system has been verified.
    :raw-html:`<br>`

As a result, a user must have faith that the verification outcome reported by Keylime is correct for the specific system
in question. It is crucial therefore to understand the security architecture and characteristics of Keylime and
attestation technologies broadly, especially as the security of an attestation service (whether Keylime or another
verification engine) depends heavily on the particular deployment.

.. note::
    At the time of this writing, Keylime only supports TPM-based attestation of `boot state`_ as recorded in UEFI logs,
    of `file system integrity`_ as recorded in Linux IMA logs, and of a TPM's `platform configuration registers (PCRs)`_
    directly. As Keylime may support other forms of attestation in the future, e.g., attestations produced by various
    trusted execution environments (TEEs), this page attempts to be agnostic as to the attestation technology being
    used, in so far as is possible, but does use such concrete examples to illustrate general concepts.

.. _boot state: ../user_guide/use_measured_boot.html
.. _file system integrity: ../user_guide/runtime_ima.html
.. _platform configuration registers (PCRs): ../user_guide/user_selected_pcr_monitoring.html


Attestation Terminology
-----------------------

At a high level, an attested node consists of a number of |attesting environments|_ which each consist of a stack of
software and the hardware it runs on. These collect *claims* about the state of the attested node (claims are also
called *measurements*) and produce *evidence* that these claims may be believable (a collection of evidence, including
claims, is what is usually referred to as an *attestation*). The evidence is authenticated cryptographically such that
it can be verified to have been produced, at least in part, by a specific component.

An attesting environment can be further split into a *measuring environment* and a *certifying environment* [1]_. The
measuring environment collects claims/measurements and the certifying environment acts as a witness, certifying that it
has seen the claims/measurements. For example, during boot with `UEFI`_, the firmware produces a log of events which are
measured into the TPM. Later, the TPM may be asked to certify the sequence of events which it received (this
certification is also known as a *quote*). In this situation, the measuring environment consists of UEFI and the
hardware platform it is running on, and the certifying environment is the TPM.

In some cases, the measuring environment and certifying environment could be the same. When attesting certain trusted
execution environments (TEEs), for example, the TEE hardware may perform both the measuring and certifying tasks.

It is important to note that attesting environments are not required to be entirely separate from one another and, in
fact, often share components. This is illustrated by the diagram below showing UEFI and `IMA`_ attestation being
performed on the same node:

.. image:: ../assets/attesting-environments-diagram.svg
  :width: 542
  :alt: Diagram showing two different attesting environments on a single system with a single underlying foundation. The
    UEFI firmware and bootloader are unique to the UEFI attesting environment while the Linux kernel is unique to the
    IMA attesting environment. But the same processor microcode, hardware platform (motherboard, CPU, memory, etc.) and TPM
    are shared by both.

The red shaded area shows the attesting environment which attests the boot state, whereas the blue shaded area shows the
attesting environment used to attest the integrity of files using IMA. The overlapping purple area contains the
components common to both. In both attesting environments, the certifying environment is the TPM.

.. _UEFI: https://en.wikipedia.org/wiki/UEFI
.. _IMA: https://www.redhat.com/en/blog/how-use-linux-kernels-integrity-measurement-architecture
.. _section 3.1: https://datatracker.ietf.org/doc/html/rfc9334#section-3.1
.. _attesting environments: https://datatracker.ietf.org/doc/html/rfc9334#section-3.1
.. |attesting environments| replace:: *attesting environments*


Trust Relationships
-------------------

The trust that a user chooses to place in the verification results produced by a deployment of Keylime should derive
from their trust in specific system components (*trust anchors*) and the cryptographic means by which this trust is
apportioned to other components and data. This is dependent on the secure design of the hardware, firmware and software
which produces the attestation evidence (collectively, the *attesting environment*), the secure design of Keylime and
any extensions or integrations, and the configuration of the system by the user.

As such, contributors to the Keylime project and users of Keylime alike need to consider the resulting *chain of trust*
when these units are composed together. To show this, a possible deployment is given in the below figure:

.. image:: ../assets/trust-chain-diagram.svg
  :width: 721
  :alt: Diagram showing the various components used to produce an attestation in a given Keylime deployment. The
    baseboard management controller (BMC) loads the processor microcode and UEFI firmware. The firmware measures the
    bootloader which in turn measures the kernel. As such, the trusted hardware is used to establish trust in the
    software components which produce the attestation.

In this example, the user has installed the Keylime agent on a node which identifies itself to an instance of the
Keylime registrar and delivers evidence to a separate Keylime verifier instance. As in the diagram from the previous 
section, the node is able to attest the contents of its UEFI boot log and the integrity of specific files using Linux
IMA. The user has configured the verifier with a certain *verification policy* [2]_ which it will use to evaluate the
evidence received in each periodic attestation.

When the attested node boots, the UEFI firmware and the bootloader each have their turn to execute in the boot sequence.
They both write entries to the boot log and, for each log entry, update registers in the TPM with a hash of that entry.
Nothing in the operation of the TPM ensures that the log entries accurately describe the events which took place at boot
time, so the firmware and bootloader must be trusted to be honest when writing to the log.

As any software component, the firmware and bootloader are subject to modification by legitimate users (e.g., when
performing an update) and malicious parties. But because the node in question has a Baseboard Management Controller
(BMC) which acts as an additional *hardware root of trust* in addition to the TPM, the user has a strong assurance that
only the correct, authenticated firmware is loaded into memory. Additionally, assuming Secure Boot is enabled, UEFI will
only launch the bootloader if it is correctly signed by an authorised OS vendor. 

.. note::
    The BMC may also perform authentication of certain hardware components, but this depends on the platform. We are
    therefore treating the entire hardware platform as a trust anchor in this example. As hardware manufacturers adopt
    `SPDM`_, authentication of hardware will become more commonplace.

.. _SPDM: https://www.dmtf.org/standards/spdm

The boot log which gets sent to the verifier is therefore trusted transitively: the log is trusted because the entries
are produced by an authorised firmware and bootloader. The bootloader is trusted because the firmware which
authenticates it is trusted. And the firmware is trusted because the BMC is trusted. We also have assurance that the
boot log has not been tampered with post boot because of how the TPM records log entry hashes in its registers.

File integrity verification is trusted in similar fashion: IMA (part of the Linux kernel) produces a log which can be
trusted because the kernel is authenticated by the bootloader before launching.

In both cases, trust in every component of the attesting environment can be established by tracing it to one or more
trust anchors. Therefore, the attesting environment as a whole can be trusted.


Verification as a Trust Anchor
------------------------------

In the previous example, a chain of trust is formed in large part by virtue of Secure Boot, a UEFI feature which
authenticates each component in the boot sequence. However, Secure Boot is imperfect. A motivated attacker can replace
the bootloader of a system with an old, vulnerable version which is accepted by the UEFI firmware as legitimate
because it has been signed by an authorised OS vendor. This type of attack has `previously succeeded`_ and has proved
difficult to remediate, as signing keys cannot be easily revoked without breaking many systems, preventing them from
booting.

.. _previously succeeded: https://www.microsoft.com/en-us/security/blog/2023/04/11/guidance-for-investigating-attacks-using-cve-2022-21894-the-blacklotus-campaign/

Instead of relying on Secure Boot, it is better to authenticate the boot chain as part of your verification policy. This
is possible because UEFI outputs the hash of the bootloader to the boot log when it loads it into memory. Your policy
can check this against a set of *reference values* of legitimate, up-to-date bootloaders.

.. note::
    The behaviour of UEFI when it loads the bootloader, including what logs are produced, is described in section 7 of
    the `TCG PC Client Platform Firmware Profile Specification`_. You should verify the hash of every EFI application
    launched as part of the boot process to establish a complete chain of trust.

.. _TCG PC Client Platform Firmware Profile Specification: https://trustedcomputinggroup.org/resource/pc-client-specific-platform-firmware-profile-specification/

The bootloader, in similar fashion, measures the kernel to the boot log before passing control to the OS. As a result,
it is possible to authenticate the kernel in your verification policy also.

From a security analysis perspective, it is important to grasp the following concept: the trust placed in an
attesting environment may be **conditional** on a verification outcome of an attestation produced by another attesting
environment. The attesting environment which produces a node's IMA log, for instance, may be trusted only if the
attesting environment which produces the UEFI log containing the hash of the kernel is trusted.


Virtual TPMs as Trust Anchors
-----------------------------

Keylime can perform TPM-based attestation using any device, physical or virtual, which implements the `TPM 2.0`_
standard. Ideally, the TPM should have a chain of trust which is rooted in hardware.

However, there are situations in which only a TPM implemented in, and secured by, software is available. Such a virtual
TPM (vTPM) needs to be located on a trusted system. For example, when attesting a VM running in a cloud environment, you
may choose to trust a vTPM provided by your cloud services provider (CSP) and running as part of the hypervisor.

.. note::
    Keylime was originally developed to attest VMs using the deep quotes provided by `vTPM support in Xen`_, for which
    the root of trust was a hardware TPM. However, support beyond `TPM 1.2`_ was never implemented. vTPMs provided by
    most hypervisors today no longer have a chain of trust rooted in hardware.

.. _vTPM support in Xen: https://xenbits.xenproject.org/docs/unstable/man/xen-vtpm.7.html
.. _TPM 1.2: https://trustedcomputinggroup.org/resource/tpm-main-specification/
.. _TPM 2.0: https://trustedcomputinggroup.org/resource/tpm-library-specification/

In a confidential computing scenario, a vTPM may be running in a trusted execution environment (TEE) which has been
attested and verified to be secure by virtue of the memory-protection guarantees granted by the CPU.


Node Identity
-------------

Fundamentally, the job of a verifier is to accept evidence from nodes on a network and apply the appropriate
verification policy to produce a verification outcome for each node. As different nodes may have different policies, it
is important that the verifier is able to reliably identify and authenticate each node. Otherwise, an attacker could
cause the wrong verification policy to be applied to a node.

Whatever key is used to sign an attestation therefore needs to be bound to the individual node in question. Further,
that binding needs to be performed by a trusted entity. The binding may be transitive so that the attestation signing
key is bound to another key which itself is bound to the attested node.

In Keylime, attestations can be bound to the attested node in a number of different ways:

Binding to a TPM Endorsement Key
""""""""""""""""""""""""""""""""

Attestations produced by a TPM are authenticated by an attestation key (AK) which is typically cryptographically bound
to the TPM's endorsement key (EK). The authenticity of the EK can be determined by an EK certificate which is usually
loaded into the TPM's non-volatile memory by the TPM manufacturer.

While the EK is required to be unique to the specific TPM, it is not linked to any identifying information about the
device in which the TPM is installed (the EK certificate does not contain any such information). This is an intentional
design choice by the Trusted Computing Group (TCG) which produces the TPM standard.

.. note::
    The TPM 2.0 spec says that a binding must be established between the TPM and the platform before you can trust a TPM
    quote, but does not provide a built-in way to do so. This is covered in `part 1, section 9.4.3.3`_ of the
    specification.

.. _part 1, section 9.4.3.3: https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-1-Architecture-01.07-2014-03-13.pdf#%5B%7B%22num%22%3A466%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22XYZ%22%7D%2C70%2C698%2C0%5D

When the Keylime agent first starts on the node to be attested, by default, it registers its EK, EK certificate and an
attestation key (AK), bound to the EK, with the registrar using an agent ID randomly generated by the agent or
provided by the user. The user can then use the Keylime tenant or REST API to retrieve these from the registrar, using
the agent ID, and enrol the AK with the verifier. Neither the registrar, the tenant, nor the verifier attempt to verify
the identity of the node by default.

.. note::
    Notice in the previous diagram that there is no chain of trust from a trust anchor to the Keylime agent. This means
    that the Keylime agent cannot be trusted to report the correct agent ID to the registrar.

If the user wishes to rely solely on the EK as identity for the attested node, they are expected to manually verify the
EK out of band themselves **before** enrolling the node for verification. This can be done `using tpm2-tools`_.

.. _using tpm2-tools: https://github.com/tpm2-software/tpm2-tools/blob/master/man/tpm2_getekcertificate.1.md

Other Identity Binding Options
""""""""""""""""""""""""""""""

There are other ways of binding attestations produced by Keylime to a specific node. These may be more involved but are
less fragile and therefore may be better from an operations perspective:

  * If the node in question has been issued a Device Identity (DevID) by its manufacturer, the AK can be bound directly
    to this identity which itself is bound to the EK by the device manufacturer. The user simply needs to provide its
    IDevID and IAK certificates, which contain the serial number of the device or other user-facing identifying
    information, and the manufacturer's CA certificates.

  * The user may construct an inventory database mapping node identifiers chosen by the user (e.g., hostnames) to an AK
    or EK. This database can be consulted before a node is added to the verifier by mechanisms available in Keylime.

  * The user may set up their own automatic process to verify possession of an AK or EK as well as the identity of the
    node through a protocol like ACME or other procedure and add the node to the verifier only if these checks pass.


Threat Model
------------

In the design of a secure system, it is prudent to define a threat model in terms of the capabilities of an idealised
attacker. This has a number of advantages, not limited to the following:

  * users are clear on the security properties they can expect from the system;

  * developers have agreement on which attacks are in scope and which are out of scope; and

  * the protocols utilised naturally lend themselves to analysis by outside parties.

In lieu of a full formal model, we give a plain English description, translatable to formal definitions, in the
subsections below.

Security Goals
""""""""""""""

We give the main security property for Keylime by stating what a successful adversary must achieve:

    A valid attack against Keylime is one in which an adversary can cause a mismatch between a verification outcome
    reported by a verifier and the correct, expected verification outcome for the verified node.

This includes attacks in which:

  * verification of a node is reported as having passed when the policy for the node should have resulted in a
    verification failure; or

  * verification of a node is reported as having failed when the policy for the node should have resulted in a
    successful verification.

The latter is important to consider because, depending on how Keylime is used (e.g., if Keylime results are consumed by
another system or used for authentication of non-person entities), this could be exploited to trigger cascading failures
throughout the network.

The Capabilities of the Adversary
"""""""""""""""""""""""""""""""""

For our adversary, we consider a typical network-based (Dolev-Yao) attacker [3]_ which exercises full control over the
network and can intercept, block and modify all messages but cannot break cryptographic primitives (all cryptography is
assumed perfect). Because we need to consider attacks in which the adversary is resident on a node to be verified, we
extend the "network" to include channels between the agent and any attesting environment (for TPM-based attestation,
this includes communication between the TPM and the agent).

The adversary cannot corrupt (i.e., take control of, or impersonate) the verifier, registrar, tenant or any attesting
environment, but has full control over the rest of the system, including the nodes' filesystem and memory.

Exclusions
""""""""""

Attacks which exploit poorly-defined verification policies or deficiencies in the information which can be obtained from
a node's attesting environments (including IMA and UEFI logs) are necessarily out of scope. Additionally, we exclude
attacks which are made possible by incorrect configuration by the user (this includes incorrectly specified verification
policies). Attacks which rely on modification of an attesting environment (such as by using a UEFI bootkit) are also
excluded.



----

**Footnotes:**

.. [1] *Attesting environments*, *claims*, and *evidence* are the terms preferred by the IETF's Remote Attestation
   Procedures (RATS) working group in their architecture specification, `RFC 9334`_. Although they do not explicitly 
   divide attesting environments into a *measuring environment* and *certifying environment* as we do here, separating
   claims collection and certification of claims into separate components is contemplated in section 3.1.

.. [2] It is common for a verification policy to perform verification of evidence against a separate set of *reference
   values* or *reference measurements*. For the purposes of this page, we consider that any reference values are part of
   the verification policy itself, as the distinction should not impact security analysis.

.. [3] This type of rule-based adversary is first described by Danny Dolev and Andrew Yao in their 1983 paper, `"On the
   security of public key protocols"`_.

.. _RFC 9334: https://datatracker.ietf.org/doc/html/rfc9334
.. _"On the security of public key protocols": http://www.cs.huji.ac.il/~dolev/pubs/dolev-yao-ieee-01056650.pdf