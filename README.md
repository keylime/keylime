# Keylime

[![Slack CNCF chat](https://img.shields.io/badge/Chat-CNCF%20Slack-informational)](https://cloud-native.slack.com/archives/C01ARE2QUTZ)

![keylime](doc/keylime.png?raw=true "Title")

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

Keylime can be driven with a CLI application, web front end, and a set of
RESTful APIs.

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
in this repository `keylime`. The agent is currently undergoing a port to the
[Rust programming language](https://www.rust-lang.org), with this work taking
place in the [rust-keylime repository](https://github.com/keylime/rust-keylime).

The decision was made to port the agent to Rust, as rust is a low level
performant systems language designed with security as a central tenet, by means
of the rust compilers ownership model.

When the rust agent work is complete, the rust-keylime agent will become the
recommended ongoing agent within Keylime. Until then the Python agent is
fully functioning and available to use as a remote monitoring system to interact
with the keylime verifier and registrar.

### TPM Support

Keylime supports TPM version *2.0*.

Keylime can be used with a hardware TPM, or a software TPM emulator for
development, testing, or demonstration purposes.  However, DO NOT USE keylime in
production with a TPM emulator!  A software TPM emulator does not provide a
hardware root of trust and dramatically lowers the security benefits of using
keylime.

A hardware TPM should always be used when real secrets and trust is required.

## Table of Contents

* [Installation](#installation)
  * [Automated](#automated)
  * [Manual](#manual)
* [Making sure your TPM is ready for keylime](#making-sure-your-tpm-is-ready-for-keylime)
* [Usage](#usage)
  * [Configuring keylime](#configuring-keylime)
  * [Running keylime](#running-keylime)
  * [Provisioning](#provisioning)
  * [Using keylime CA](#using-keylime-ca)
* [Request a Feature](#request-a-feature)
* [Security Vulnerability Management Policy](#security-vulnerability-management-policy)
* [Meeting Information](#project-meetings)
* [Contributing: First Timers Support](#contributing--first-timers-support)
* [Testing](#testing)
* [Additional Reading](#additional-reading)
* [Disclaimer](#disclaimer)

## Installation

### Installer script

Keylimes installer requires Python 3.6 or greater.

The following command line options are available using `installer.sh` script:

```
Usage: ./installer.sh [option...]
Options:
-k              Download Keylime (stub installer mode)
-o              Use OpenSSL instead of CFSSL
-t              Create tarball with keylime_agent
-m              Use modern TPM 2.0 libraries (vs. TPM 1.2)
-s              Install & use a Software TPM emulator (development only)
-p PATH         Use PATH as Keylime path
-h              This help info
```

Should you not have the Keylime repository on your local machine, you can
use the `-k` flag which will download the software. In this case, all you need
is the `installer.sh` script locally.

Note that CFSSL is required if you want to support revocation. As noted above, do not use the TPM emulator option `-s` in production systems.

#### Installer Distribution coverage

| Distribution  | Versions      | TPM2-Software   |
| ------------- |:-------------:| -----:          |
| CentOS        | 7 / 8         | Compiled        |
| RHEL          | 7 / 8         | Compiled        |
| Fedora        | 32 / 33 / 34  | Package Install |
| Ubuntu        | 19 LTS / 20   | Compiled        |

### Ansible

Ansible roles are available to deploy keylime for use with a hardware TPM or a software TPM emulator. 
Please proceed to the [Keylime Ansible
Repository](https://github.com/keylime/ansible-keylime).
Or, alternatively the [Keylime Ansible TPM Emulator
Repository](https://github.com/keylime/ansible-keylime-tpm-emulator).

| WARNING: The "Keylime Ansible TPM Emulator" role uses a software TPM, which is considered cryptographically insecure. It should only be used for development or testing and **NOT** in production!|
| --- |

### Docker (Development Only)

keylime and related emulators can also be deployed using Docker.
Since this docker configuration currently uses a TPM emulator,
it should only be used for development or testing and NOT in production.

Please see either the 
[Dockerfiles](https://github.com/keylime/keylime/tree/master/docker) or our
[local CI script](https://github.com/keylime/keylime/blob/master/.ci/run_local.sh)
which will automate the build and pull of keylime.

### Manual

Keylimes installer requires Python 3.6 or greater.

#### Python-based prerequisites

The list of Python packages needed to install keylime can be found in
 [requirements.txt](https://github.com/keylime/keylime/tree/master/requirements.txt).

Some of them are usually available as distro packages.
See [installer.sh](https://github.com/keylime/keylime/blob/master/installer.sh)
 for more information, if you want to install them this way.

You can also install them using pip:

```bash
python3 -m pip install -r requirements.txt
```

#### TPM utility prerequisites

Keylime uses the Intel TPM2 software set to provide TPM 2.0 support.

These can be installed using your package manager.

* On Fedora 32 (and greater):

`sudo dnf install tpm2-tss tpm2-tools tpm2-abrmd`

* On Ubuntu 20 LTS:

`sudo apt-get install tpm2-tss tpm2-tools tpm2-abrmd`

You can also build the [tpm2-tss](https://github.com/tpm2-software/tpm2-tss) software stack as well as
[tpm2-tools](https://github.com/tpm2-software/tpm2-tools) instead . See the
README.md in these projects for detailed instructions on how to build and install.

The brief synopsis of a quick build/install (after installing dependencies) is:

```bash
git clone https://github.com/tpm2-software/tpm2-tss.git tpm2-tss
pushd tpm2-tss
./bootstrap
./configure --prefix=/usr
make
sudo make install
popd

git clone https://github.com/tpm2-software/tpm2-tools.git tpm2-tools
pushd tpm2-tools
./bootstrap
./configure --prefix=/usr/local
make
sudo make install
```

To ensure that you have the patched version installed ensure that you have
the `tpm2_checkquote` utility in your path.

###### TPM 2.0 Access

The Linux kernel provides a resource manager since version 5.4 which is 
configured as the default in Keylime. On older kernel versions it is 
recommended to use the [tpm2-abrmd](https://github.com/tpm2-software/tpm2-abrmd) 
resource manager.

Alternatively, it is also possible, though not recommended, to communicate
directly with the TPM (and not use a resource manager).  This can be done by
setting the environment var `TPM2TOOLS_TCTI` to the appropriate value:

To talk directly to the swtpm2 emulator: 

`export TPM2TOOLS_TCTI="mssim:port=2321"`

To talk directly to a real TPM: 

`export TPM2TOOLS_TCTI="device:/dev/tpm0"`

#### Install Keylime

You're finally ready to install keylime!

```bash
sudo python3 -m pip install . -r requirements.txt
```

#### Optional Requirements

If you want to support revocation, you also need to have cfssl installed and in your
path on the tenant agent. It can be obtained from https://github.com/cloudflare/cfssl. 
You will also need to set ca_implementation to "cfssl" instead of "openssl" in `/etc/keylime.conf`.

## Making sure your TPM is ready for keylime

The above instructions for installing the TPM libraries will be configured
to talk to `/dev/tpm0`.  If this device is not on your system, then you may need
to build/install TPM support for your kernel.  You can use following command
to see if the kernel is initializing the TPM driver during boot:

`dmesg | grep -i tpm`

If you have the `/dev/tpm0` device, you next need to get it into the right state. The kernel
driver reports status on the TPM in `/sys`.  You can locate the folder with relevant
info from the driver using:

`sudo find /sys -name tpm0`

Several results may be returned, but the duplicates are just symlinks to one
location.  Go to one of the returned paths, for example, /sys/class/misc/tpm0.  Now
change to the device directory.  Here you can find some information from the TPM like
the current pcr values and sometimes the public EK is available.  It will also report
two important state values: active and enabled.  To use keylime, both of these must
be 1.  If they are not, you may need to reboot into the BIOS to enable and activate
the TPM.  If you need to both enable and activate, then you must enable first, reboot,
then activate and finally reboot again.  It is also possible that you may need to
assert physical presence (see manual for your system on how to do this) in order to
accomplish these actions in your BIOS.

If your system shows enabled and activated, you can next check the "owned"
status in the /sys directory.  Keylime can take a system that is not owned (i.e., owned = 0)
and take control of it.  Keylime can also take a system that is already owned,
provided that you know the owner password and that keylime or another trusted
computing system that relies upon tpm4720 previously took ownership.  If you know
the owner password, you can set the option tpm_ownerpassword in keylime.conf to this known value.

## Usage

### Configuring keylime

keylime puts its configuration in `/etc/keylime.conf`.  It will also take an alternate
location for the config in the environment var `KEYLIME_CONFIG`.

This file is documented with comments and should be self-explanatory.

### Running keylime

Keylime has three major component services that run: the registrar, verifier, and the agent:

* The *registrar* is a simple HTTPS service that accepts TPM public keys.  It then
presents an interface to obtain these public keys for checking quotes.

* The *verifier* is the most important component in keylime.  It does initial and
periodic checks of system integrity and supports bootstrapping a cryptographic key
securely with the agent.  The verifier uses mutual TLS for its control interface.

    By default, the verifier will create appropriate TLS certificates for itself
    in `/var/lib/keylime/cv_ca/`.  The registrar and tenant will use this as well.  If
    you use the generated TLS certificates then all the processes need to run as root
    to allow reading of private key files in `/var/lib/keylime/`.

* The *agent* is the target of bootstrapping and integrity measurements.  It puts
    its stuff into `/var/lib/keylime/`.

To run a basic test, run `keylime_verifier`, `keylime_registrar`, and `keylime_agent`.  If
the agent starts up properly, then you can proceed.

### Provisioning

To kick everything off you need to tell keylime to provision a machine. This can be
done either with the keylime tenant or webapp.

#### Provisioning with keylime_tenant

The `keylime_tenant` utility can be used to provision your agent.

As an example, the following command tells keylime to provision a new agent
at 127.0.0.1 with UUID d432fbb3-d2f1-4a97-9ef7-75bd81c00000 and talk to a
verifier at 127.0.0.1.  Finally it will encrypt a file called `filetosend`
and send it to the agent allowing it to decrypt it only if the configured TPM
policy (in `/etc/keylime.conf`) is satisfied:

`keylime_tenant -c add -t 127.0.0.1 -v 127.0.0.1 -u D432fbb3-d2f1-4a97-9ef7-75bd81c00000 -f filetosend`

To stop keylime from requesting attestations:

`keylime_tenant -c delete -t 127.0.0.1 -u d432fbb3-d2f1-4a97-9ef7-75bd81c00000`

For additional advanced options for the tenant utility run:

`keylime_tenant -h`

#### Provisioning with keylime_webapp

There is also a WebApp GUI interface for the tenant, available by
running `keylime_webapp`.  Next, simply navigate to the WebApp in
your web browser (https://localhost/webapp/ by default, as specified in `/etc/keylime.conf`).

Note that the webapp must be run on the same machine as the tenant, since it
uses its keys for TLS authentication in `/var/lib/keylime/`.

### Using keylime CA

A simple certificate authority is available to use with keylime. You can interact
with it using `keylime_ca` or `keylime_tenant`.  Options for configuring the
certificates that `keylime_ca` creates are in `/etc/keylime.conf`.

NOTE: This CA functionality is different than the TLS support for talking to
the verifier or registrar (though it uses some of the same config options
in `/etc/keylime.conf`).  This CA is for the Keylime Agents you provision and
you can use keylime to bootstrap the private keys into agents.

To initialize a new certificate authority run:

`keylime_ca --command init`

This will create a certificate authority in `/var/lib/keylime/ca` and requires
root access to write to the directory.  Use `-d` to point it to another directory
not necessarily requiring root.

You can create certificates under this ca using:

`keylime_ca --command create --name certname.host.com`

This will create a certificate signed by the CA in `/var/lib/keylime/ca` (`-d` also
works here to have it use a different CA directory).

To obtain a zip file of the certificate, public key, and private key for a cert use:

`keylime_ca --command pkg --name certname.host.com`

This will zip the above files and place them in /var/lib/keylime/ca/certname.host.com-pkg.zip.  The
private key will be protected by the key that you were prompted with.

You may wonder why this is in keylime at all?  Well, you can tell `keylime_tenant` to
automatically create a key and then provision an agent with it.  Use the --cert
option in `keylime_tenant` to do this.  This takes in the directory of the CA:

`keylime_tenant -c add -t 127.0.0.1 -u d432fbb3-d2f1-4a97-9ef7-75bd81c00000 --cert /var/lib/keylime/ca`

If you also have the option extract_payload_zip in `/etc/keylime.conf` set to `True` on
the keylime agent, then it will automatically extract the zip containing an unprotected
private key, public key, certificate and CA certificate to `/var/lib/keylime/secure/unzipped`.

If the keylime verifier option `revocation_notifier` is set to `True`, then
the CV will sign a revocation message and send it over 0mq to any subscribers.  The
keylime CA supports listening to these notifications and will generate an updated
CRL.  To enable this feature, run:

`keylime_ca -c listen`

The revocation key will be automatically created by the tenant the first time
you use the CA with keylime.  Currently the CRL is only written back to the CA
directory, unless IPsec configuration is being used (see [Additional Reading](#additional-reading)).

## Systemd service support

The directory `services/` includes `systemd` service files for the verifier,
agent and registrar.

You can install the services with the following command:

`sudo ./services/install.sh`

Once installed, you can run and inspect the services `keylime_verifier`,
`keylime_agent` and `keylime_registrar` via `systemctl`.

### Request a feature

Keylime feature requests are tracked as enhancements in the [enhancements repository](https://github.com/keylime/enhancements)

The enhancement process has been implemented to provide a way to review and
assess the impact(s) of significant changes to Keylime.

## Security Vulnerability Management Policy

If you would have found a security vulnerability in Keylime and would like to
report, first of all: thank you.

Please contact us directly at [security@keylime.groups.io](mailto:security@keylime.groups.io)
for any bug that might impact the security of this project. **Do not** use a
Github issue to report any potential security bugs.


## Project Meetings

We meet every Wednesday @ 15:00 UTC to 15:30. Anyone is welcome to join the meeting.

The meeting is hosted in [CNCF chat (Slack)](https://cloud-native.slack.com/archives/C01ARE2QUTZ)

Meeting agenda are hosted and archived in the [meetings repo](https://github.com/keylime/meetings) as Github issues.

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

* Executive summary Keylime slides: [doc/keylime-elevator-slides.pptx](https://github.com/keylime/keylime/raw/master/doc/keylime-elevator-slides.pptx)
* Detailed Keylime Architecture slides: [doc/keylime-detailed-architecture-v7.pptx](https://github.com/keylime/keylime/raw/master/doc/keylime-detailed-architecture-v7.pptx)
* See ACSAC 2016 paper in doc directory: [doc/tci-acm.pdf](https://github.com/keylime/keylime/blob/master/doc/tci-acm.pdf)
  * and the ACSAC presentation on keylime: [doc/llsrc-keylime-acsac-v6.pptx](https://github.com/keylime/keylime/raw/master/doc/llsrc-keylime-acsac-v6.pptx)
* See the HotCloud 2018 paper: [doc/hotcloud18.pdf](https://github.com/keylime/keylime/blob/master/doc/hotcloud18.pdf)
* Details about Keylime REST API: [doc/keylime RESTful API.docx](https://github.com/keylime/keylime/raw/master/doc/keylime%20RESTful%20API.docx)
* [Bundling a portable Cloud Agent](doc/cloud-agent-tarball-notes.md) - Create portable tarball of Cloud Agent, for usage on systems without python and other dependencies.
* [Xen vTPM setup notes](doc/xen-vtpm-notes.md) - Guidance on getting Xen set up with vTPM support for Keylime.
* IPsec Configurations
  * [IPsec with Libreswan](auto-ipsec/libreswan) - Configuring Keylime with a Libreswan backend for IPsec functionality.
  * [IPsec with Racoon](auto-ipsec/racoon) - Configuring Keylime with a Racoon backend for IPsec functionality.
* [Demo files](demo/) - Some pre-packaged demos to show off what Keylime can do.
* [Stubbed TPM/vTPM notes](doc/stub-tpm-notes.md) - Explains how to use Keylime with canned/simulated TPM behavior (useful for testing).
* [IMA stub service](ima_stub_service/) - Allows you to test IMA and keylime on a machine without a TPM.  Service keeps emulated TPM synchronized with IMA.

#### Errata from the ACSAC Paper

We discovered a typo in Figure 5 of the published ACSAC paper. The final interaction
between the Tenant and Cloud Verifier showed an HMAC of the node's ID using the key
K_e.  This should be using K_b. The paper in this repository and the ACSAC presentation
have been updated to correct this typo.

The software that runs on the system with the TPM is now called the keylime *agent* rather
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
Clause-2 licensed code can be found on the [MIT github
organization](https://github.com/mit-ll/MIT-keylime).
