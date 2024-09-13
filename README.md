# Keylime

[![Slack CNCF chat](https://img.shields.io/badge/Chat-CNCF%20Slack-informational)](https://cloud-native.slack.com/archives/C01ARE2QUTZ)
[![Docs Status](https://readthedocs.org/projects/keylime/badge/?version=latest)](https://keylime.readthedocs.io/en/latest/?badge=latest)

![Keylime](docs/keylime.png?raw=true "Title")

Keylime is an open-source scalable trust system harnessing TPM Technology.

Keylime provides an end-to-end solution for bootstrapping hardware rooted
cryptographic trust for remote machines, the provisioning of encrypted payloads, 
and run-time system integrity monitoring. It also provides a flexible
framework for the remote attestation of any given `PCR` (Platform Configuration
Register). Users can create their own customized actions that will trigger when
a machine fails its attested measurements.

Keylime's mission is to make TPM Technology easily accessible to developers and
users alike, without the need for a deep understanding of the lower levels of a
TPM's operations. Amongst many scenarios, it well suited to tenants who need to
remotely attest machines not under their own full control (such as a consumer of
hybrid cloud or a remote Edge / IoT device in an insecure physical tamper prone
location.)

Keylime can be driven with a CLI application and a set of RESTful APIs.

Keylime consists of three main components; The Verifier, Registrar and the
Agent.

* The Verifier continuously verifies the integrity state of the machine that
the agent is running on.

* The Registrar is a database of all agents registered
with Keylime and hosts the public keys of the TPM vendors.

* The Agent is deployed to the remote machine that is to be measured or provisioned
with secrets stored within an encrypted payload released once trust is established.

### Rust based Keylime Agent

The verifier, registrar, and agent are all developed in Python and situated
in this repository `keylime`. The agent was ported to the
[Rust programming language](https://www.rust-lang.org). The code can be found 
in the [rust-keylime repository](https://github.com/keylime/rust-keylime).

The decision was made to port the agent to Rust, as rust is a low-level
performant systems language designed with security as a central tenet, by means
of the rust compiler's ownership model.

Starting with the 0.1.0 release of the Rust based Keylime agent, this agent is now the official agent.

| IMPORTANT: The Python version is deprecated and will be removed with the next major version (7.0.0)! |
|------------------------------------------------------------------------------------------------------|


### TPM Support

Keylime supports TPM version *2.0*.

Keylime can be used with a hardware TPM, or a software TPM emulator for
development, testing, or demonstration purposes.  However, DO NOT USE Keylime in
production with a TPM emulator!  A software TPM emulator does not provide a
hardware root of trust and dramatically lowers the security benefits of using
Keylime.

A hardware TPM should always be used when real secrets and trust is required.

## Table of Contents

* [Installation](#installation)
* [Usage](#usage)
  * [Configuring Keylime](#configuring-keylime)
  * [Running Keylime](#running-keylime)
  * [Provisioning](#provisioning)
* [Request a Feature](#request-a-feature)
* [Security Vulnerability Management Policy](#security-vulnerability-management-policy)
* [Meeting Information](#project-meetings)
* [Contributing: First Timers Support](#contributing--first-timers-support)
* [Testing](#testing)
* [Additional Reading](#additional-reading)
* [Disclaimer](#disclaimer)

## Installation

To install Keylime refer to [the instructions found in the documentation](https://keylime.readthedocs.io/en/latest/installation.html).


## Usage

### Configuring Keylime

Keylime puts its configuration in `/etc/keylime/*.conf` or `/usr/etc/keylime/*.conf`.
It will also take an alternate location for the config in the environment var 
`keylime_{VERIFIER,REGISTRAR,TENANT,CA,LOGGING}_CONFIG`.

Those files are documented with comments and should be self-explanatory in most cases.

### Running Keylime

Keylime has three major component services that run: the registrar, verifier, and the agent:

* The *registrar* is a simple HTTPS service that accepts TPM public keys.  It then
presents an interface to obtain these public keys for checking quotes.

* The *verifier* is the most important component in Keylime.  It does initial and
periodic checks of system integrity and supports bootstrapping a cryptographic key
securely with the agent.  The verifier uses mutual TLS for its control interface.

    By default, the verifier will create appropriate TLS certificates for itself
    in `/var/lib/keylime/cv_ca/`.  The registrar and tenant will use this as well.  If
    you use the generated TLS certificates then all the processes need to run as root
    to allow reading of private key files in `/var/lib/keylime/`.

* The *agent* is the target of bootstrapping and integrity measurements.  It puts
    its stuff into `/var/lib/keylime/`.


### Provisioning

To kick everything off you need to tell Keylime to provision a machine. This can be
done with the Keylime tenant.

#### Provisioning with keylime_tenant

The `keylime_tenant` utility can be used to provision your agent.

As an example, the following command tells Keylime to provision a new agent
at 127.0.0.1 with UUID d432fbb3-d2f1-4a97-9ef7-75bd81c00000 and talk to a
verifier at 127.0.0.1. Finally, it will encrypt a file called `filetosend`
and send it to the agent allowing it to decrypt it only if the configured TPM
policy is satisfied:

`keylime_tenant -c add -t 127.0.0.1 -v 127.0.0.1 -u D432fbb3-d2f1-4a97-9ef7-75bd81c00000 -f filetosend`

To stop Keylime from requesting attestations:

`keylime_tenant -c delete -t 127.0.0.1 -u d432fbb3-d2f1-4a97-9ef7-75bd81c00000`

For additional advanced options for the tenant utility run:

`keylime_tenant -h`

Documentation on how to create runtime and measured boot policies can be found in
the [Keylime User Guide](https://keylime.readthedocs.io/en/latest/user_guide.html).

## Systemd service support

The directory `services/` includes `systemd` service files for the verifier,
agent and registrar.

You can install the services with the following command:

`sudo ./services/installer.sh`

Once installed, you can run and inspect the services `keylime_verifier` and `keylime_registrar` via `systemctl`.
The Rust agent repository also contains a systemd service file for the agent.

## Request a feature

Keylime feature requests are tracked as enhancements in the [enhancements repository](https://github.com/keylime/enhancements)

The enhancement process has been implemented to provide a way to review and
assess the impact(s) of significant changes to Keylime.

## Security Vulnerability Management Policy

If you have found a security vulnerability in Keylime and would like to
report, first of all: thank you.

Please contact us directly at [security@keylime.groups.io](mailto:security@keylime.groups.io)
for any bug that might impact the security of this project. **Do not** use a
Github issue to report any potential security bugs.


## Project Meetings

We meet on the fourth Wednesday each month @ 16:00 UK time (GMT/BST) to 17:00. Anyone is welcome to join the meeting.

The meeting is normally announced on [CNCF chat (Slack)](https://cloud-native.slack.com/archives/C01ARE2QUTZ)

Meeting agenda are hosted and archived in the [meetings repo](https://github.com/keylime/meetings) as GitHub issues.

## Contributing: First Timers Support

We welcome new contributors to Keylime of any form, including those of you who maybe new to working in an open source project.

So if you are new to open source development, don't worry, there are a myriad of ways you can get involved in our open source project. As a start, try exploring issues with [`good first issue`](https://github.com/keylime/keylime/labels/good%20first%20issue) label.
We understand that the process of creating a Pull Request (PR) can be a barrier for new contributors. These issues are reserved for new contributors like you. If you need any help or advice in making the PR, feel free to jump into our [chat room](https://cloud-native.slack.com/archives/C01ARE2QUTZ) and ask for help there.

Your contribution is our gift to make our project even more robust. Check out [CONTRIBUTING.md](https://github.com/keylime/keylime/blob/master/CONTRIBUTING.md) to find out more about how to contribute to our project.

Keylime uses [Semantic Versioning](https://semver.org/). It is recommended you also read the [RELEASE.md](RELEASE.md)
file to learn more about it and familiarise yourself with simple of examples of using it.

## Testing

Please, see [TESTING.md](TESTING.md) for details.

## Additional Reading

* Executive summary Keylime slides: [docs/old/keylime-elevator-slides.pptx](https://github.com/keylime/keylime/raw/master/docs/old/keylime-elevator-slides.pptx)
* Detailed Keylime Architecture slides: [docs/old/keylime-detailed-architecture-v7.pptx](https://github.com/keylime/keylime/raw/master/docs/old/keylime-detailed-architecture-v7.pptx)
* See ACSAC 2016 paper in doc directory: [docs/old/tci-acm.pdf](https://github.com/keylime/keylime/blob/master/docs/old/tci-acm.pdf)
  * and the ACSAC presentation on Keylime: [docs/old/llsrc-keylime-acsac-v6.pptx](https://github.com/keylime/keylime/raw/master/docs/old/llsrc-keylime-acsac-v6.pptx)
* See the HotCloud 2018 paper: [docs/old/hotcloud18.pdf](https://github.com/keylime/keylime/blob/master/docs/old/hotcloud18.pdf)
* Details about Keylime REST API: [docs/old/keylime RESTful API.docx](https://github.com/keylime/keylime/raw/master/docs/old/keylime%20RESTful%20API.docx)
* [Demo files](demo/) - Some pre-packaged demos to show off what Keylime can do.
* [IMA stub service](https://github.com/keylime/rust-keylime/tree/master/keylime-ima-emulator) - Allows you to test IMA and Keylime on a machine without a TPM.  Service keeps emulated TPM synchronized with IMA.

#### Errata from the ACSAC Paper

We discovered a typo in Figure 5 of the published ACSAC paper. The final interaction
between the Tenant and Cloud Verifier showed an HMAC of the node's ID using the key
K_e.  This should be using K_b. The paper in this repository and the ACSAC presentation
have been updated to correct this typo.

The software that runs on the system with the TPM is now called the Keylime *agent* rather
than the *node*.  We have made this change in the documentation and code.  The ACSAC paper
will remain as it was published using *node*.

## Disclaimer

DISTRIBUTION STATEMENT A. Approved for public release: distribution unlimited.

This material is based upon work supported by the Assistant Secretary of Defense for
Research and Engineering under Air Force Contract No. FA8721-05-C-0002 and/or
FA8702-15-D-0001. Any opinions, findings, conclusions or recommendations expressed in this
material are those of the author(s) and do not necessarily reflect the views of the
Assistant Secretary of Defense for Research and Engineering.

Keylime's license was changed from BSD Clause-2 to Apache 2.0. The original BSD
Clause-2 licensed code can be found on the [MIT GitHub
organization](https://github.com/mit-ll/MIT-keylime).
