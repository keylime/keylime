# python-keylime

[![Build
Status](https://travis-ci.org/keylime/python-keylime.svg?branch=master)](https://travis-ci.org/keylime/python-keylime) [![Gitter chat](https://badges.gitter.im/gitterHQ/gitter.png)](https://gitter.im/keylime-project/community)

![keylime](doc/keylime.png?raw=true "Title")

keylime is a scalable trusted cloud key management system. keylime provides an
end-to-end solution for both bootstrapping hardware rooted cryptographic
identities for IaaS nodes and for system integrity monitoring of those nodes via
periodic attestation.

keylime supports both TPM versions 1.2 and 2.0.  

keylime can be used with a software TPM emulator
for development, testing, or demonstration purposes.  However, DO NOT USE keylime in 
production with a TPM emulator!  A software TPM emulator does not provide a hardware root
of trust and dramatically lowers the security benefits of using keylime.

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
* [Report a Security Vulnerability](#report-a-security-vulnerability)
* [Meeting Information](#project-meetings)
* [Additional Reading](#additional-reading)
* [License](#license)

## Installation

### Automated

keylime requires Python 2.7.10 or newer for proper TLS support.

Installation can be performed via an automated shell script, `installer.sh`.  The
following command line options are available:
```
Usage: ./installer.sh [option...]
Options:
-k              Download Keylime (stub installer mode)
-o              Use OpenSSL instead of CFSSL
-t              Create tarball with keylime_node
-m              Use modern TPM 2.0 libraries (vs. TPM 1.2)
-s              Install TPM in socket/simulator mode (vs. chardev)
-p PATH         Use PATH as Keylime path
-h              This help info
```

Note that CFSSL is required if you want to support revocation. As noted above, do not use
the TPM emulator option `-s` in production systems.

### Ansible (Development Only)

Ansible roles are available to deploy keylime in either TPM 1.2 or 2.0 mode
(with the relevant TPM 1.2 or 2.0 Emulator).  Since this role currently uses a TPM emulator,
it should only be used for development or testing and NOT in production.

Please proceed to the [Keylime Ansible
Repository](https://github.com/keylime/ansible-keylime).

### Docker (Development Only)

Python keylime and related emulators can also be deployed using Docker. 
Since this docker configuration currently uses a TPM emulator,
it should only be used for development or testing and NOT in production.

Please see either the Dockerfiles
[here](https://github.com/keylime/python-keylime/tree/master/docker) or our
local CI script
[here](https://github.com/keylime/python-keylime/blob/master/.ci/run_local.sh)
which will automate the build and pull of keylime on TPM 1.2 or 2.0.

### Manual

Keylime requires Python 2.7.10 or newer for proper TLS support.  This is newer than
some LTS distributions like Ubuntu 14.04 or CentOS 7.  See google for instructions
on how to get a newer Python onto those platforms.

#### Python-based prerequisites

The following python packages are required:

* pycryptodomex>=3.4.1
* tornado>=4.3
* m2crypto>=0.21.1
* pyzmq>=14.4
* setuptools>=0.7
* python-dev
* pyyaml

The latter of these are usually available as distro packages. See [installer.sh](https://github.com/keylime/python-keylime/blob/master/installer.sh) for more information if you want to install them this way.
You can also let keylime's `setup.py` install them via PyPI.

#### TPM utility prerequisites

##### TPM 1.2 Support

You also need a patched version of tpm4720 the IBM software TPM emulator and
utilities.  This is available at https://github.com/keylime/tpm4720-keylime.  
Even if you are using keylime with a real TPM, you must install the IBM emulator
because keylime uses the command line utilities that come with it.  
See README.md in that project for detailed instructions on how to build and install it.

The brief synopsis of a quick build/install (after installing dependencies) is:

```bash
git clone https://github.com/keylime/tpm4720-keylime.git
cd tpm4720-keylime/libtpm
./comp-chardev.sh
sudo make install
```

To build tpm4720 to use the TPM emulator replace `./comp-chardev.sh` with `./comp-sockets.sh`.

To ensure that you have the patched version installed ensure that you have
the `encaik` utility in your path.

##### TPM 2.0 Support

Keylime uses the Intel TPM2 software set to provide TPM 2.0 support.  You will
need to install the tpm2-tss software stack (available at
https://github.com/tpm2-software/tpm2-tss) as well as a patched version of the
tpm2-tools utilities available at https://github.com/keylime/tpm2-tools. See
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

git clone https://github.com/keylime/tpm2-tools.git tpm2-tools
pushd tpm2-tools
./bootstrap
./configure --prefix=/usr/local
make
sudo make install
```

To ensure that you have the patched version installed ensure that you have
the `tpm2_checkquote` utility in your path.

###### TPM 2.0 Resource Manager

Note that it is recommended that you use the tpm2-abrmd resource manager
(available at https://github.com/tpm2-software/tpm2-abrmd) as well instead of
communicating directly with the TPM.  See README.md at that project for
detailed instructions on how to build and install.

A brief, workable example for Ubuntu 18 LTS systems is:

```bash
sudo useradd --system --user-group tss
git clone https://github.com/tpm2-software/tpm2-abrmd.git tpm2-abrmd
pushd tpm2-abrmd
./bootstrap
./configure --with-dbuspolicydir=/etc/dbus-1/system.d \
            --with-systemdsystemunitdir=/lib/systemd/system \
            --with-systemdpresetdir=/lib/systemd/system-preset \
            --datarootdir=/usr/share
make
sudo make install
sudo ldconfig
sudo pkill -HUP dbus-daemon
sudo systemctl daemon-reload
sudo service tpm2-abrmd start
export TPM2TOOLS_TCTI="tabrmd:bus_name=com.intel.tss2.Tabrmd"

# NOTE: if using swtpm2 emulator, you need to run the tpm2-abrmd service as:
sudo -u tss /usr/local/sbin/tpm2-abrmd --tcti=mssim &
```

Alternatively, it is also possible, though not recommended, to communicate
directly with the TPM (and not use a resource manager).  This can be done by
setting the environment var `TPM2TOOLS_TCTI` to the appropriate value:

To talk directly to the swtpm2 emulator: `export TPM2TOOLS_TCTI="mssim:port=2321"`

To talk directly to a real TPM: `export TPM2TOOLS_TCTI="device:/dev/tpm0"`

#### Install Keylime

You're finally ready to install keylime!
```bash
sudo python setup.py install
```

#### To run on OSX 10.11+

You need to build m2crypto from source with

```bash
brew install openssl
git clone https://gitlab.com/m2crypto/m2crypto.git
python setup.py build build_ext --openssl=/usr/local/opt/openssl/
sudo -E python setup.py install build_ext --openssl=/usr/local/opt/openssl/
```

#### Optional Requirements

If you want to support revocation, you also need to have cfssl installed and in your
path on the tenant node.  It can be obtained from https://github.com/cloudflare/cfssl.  You
will also need to set ca_implementation to "cfssl" instead of "openssl" in `/etc/keylime.conf`.

## Making sure your TPM is ready for keylime

The above instructions for installing the TPM libraries will be configured
to talk to /dev/tpm0.  If this device is not on your system, then you may need
to build/install TPM support for your kernel.  You can use:

`dmesg | grep -i tpm`

to see if the kernel is initializing the TPM driver during boot.  If you have
the /dev/tpm0 device, you next need to get it into the right state.  The kernel
driver reports status on the TPM in /sys.  You can locate the folder with relevant
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

Keylime has three major component services that run: the registrar, verifier, and the node:

* The *registrar* is a simple HTTPS service that accepts TPM public keys.  It then
presents an interface to obtain these public keys for checking quotes.

* The *verifier* is the most important component in keylime.  It does initial and
periodic checks of system integrity and supports bootstrapping a cryptographic key
securely with the node.  The verifier uses mutual TLS for its control interface.

    By default, the verifier will create appropriate TLS certificates for itself
    in `/var/lib/keylime/cv_ca/`.  The registrar and tenant will use this as well.  If
    you use the generated TLS certificates then all the processes need to run as root
    to allow reading of private key files in `/var/lib/keylime/`.

* The *node* is the target of bootstrapping and integrity measurements.  It puts
    its stuff into `/var/lib/keylime/`.

To run a basic test, run `keylime_verifier`, `keylime_registrar`, and `keylime_node`.  If
the node starts up properly, then you can proceed.

### Provisioning

To kick everything off you need to tell keylime to provision a machine. This can be
done either with the keylime tenant or webapp.

#### Provisioning with keylime_tenant

The `keylime_tenant` utility can be used to provision your node.

As an example, the following command tells keylime to provision a new node
at 127.0.0.1 with UUID D432FBB3-D2F1-4A97-9EF7-75BD81C00000 and talk to a
cloud verifier at 127.0.0.1.  Finally it will encrypt a file called filetosend
and send it to the node allowing it to decrypt it only if the configured TPM
policy (in `/etc/keylime.conf`) is satisfied:

`keylime_tenant -c add -t 127.0.0.1 -v 127.0.0.1 -u D432FBB3-D2F1-4A97-9EF7-75BD81C00000 -f filetosend`

To stop keylime from requesting attestations:

`keylime_tenant -c delete -t 127.0.0.1 -u D432FBB3-D2F1-4A97-9EF7-75BD81C00000`

For additional advanced options for the tenant utility run:

`keylime_tenant -h`

#### Provisioning with keylime_webapp

There is also a WebApp GUI interface for the tenant, available by
running `keylime_webapp`.  Next, simply navigate to the WebApp in
your web browser (https://localhost/webapp/ by default, as specified in `/etc/keylime.conf`).

Note that the webapp must be run on the same machine as the tenant, since it
uses its keys for TLS authentication (in `/var/lib/keylime/`).

### Using keylime CA

A simple certificate authority is available to use with keylime. You can interact
with it using `keylime_ca` or `keylime_tenant`.  Options for configuring the
certificates that `keylime_ca` creates are in `/etc/keylime.conf`.

NOTE: This CA functionality is different than the TLS support for talking to
the verifier or registrar (though it uses some of the same config options
in `/etc/keylime.conf`).  This CA is for the cloud nodes you provision and
you can use keylime to bootstrap the private keys into nodes.

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
automatically create a key and then provision a node with it.  Use the --cert
option in `keylime_tenant` to do this.  This takes in the directory of the CA:

`keylime_tenant -c add -t 127.0.0.1 -u D432FBB3-D2F1-4A97-9EF7-75BD81C00000 --cert /var/lib/keylime/ca`

If you also have the option extract_payload_zip in `/etc/keylime.conf` set to `True` on
the cloud node, then it will automatically extract the zip containing an unprotected
private key, public key, certificate and CA certificate to `/var/lib/keylime/secure/unzipped`.

If the cloud verifier option `revocation_notifier` is set to `True`, then
the CV will sign a revocation message and send it over 0mq to any subscribers.  The
keylime CA supports listening to these notifications and will generate an updated
CRL.  To enable this feature, run:

`keylime_ca -c listen`

The revocation key will be automatically created by the tenant the first time
you use the CA with keylime.  Currently the CRL is only written back to the CA
directory, unless IPsec configuration is being used (see [Additional Reading](#additional-reading)).

## Report a Security Vulnerability

Please contact us directly at [security@keylime.groups.io](mailto:security@keylime.groups.io)
for any bug that might impact the security of this project. **Do not** use a
github issue to report any potential security bugs.


## Project Meetings

We meet every Wednesday @ 15:00 UTC to 15:30. Anyone is welcome to join the meeting.

The meeting is hosted in [gitter chat](https://gitter.im/keylime-project/community)

Meeting agenda are hosted and archived in the [meetings repo](https://github.com/keylime/meetings) as github issues.

## Additional Reading

* Executive summary Keylime slides: [doc/keylime-elevator-slides.pptx](https://github.com/keylime/python-keylime/raw/master/doc/keylime-elevator-slides.pptx)
* See ACSAC 2016 paper in doc directory: [doc/tci-acm.pdf](https://github.com/keylime/python-keylime/blob/master/doc/tci-acm.pdf)
  * and the ACSAC presentation on keylime: [doc/llsrc-keylime-acsac-v6.pptx](https://github.com/keylime/python-keylime/raw/master/doc/llsrc-keylime-acsac-v6.pptx)
* See the HotCloud 2018 paper: [doc/hotcloud18.pdf](https://github.com/keylime/python-keylime/blob/master/doc/hotcloud18.pdf)
* Details about Keylime REST API: [doc/keylime RESTful API.docx](https://github.com/keylime/python-keylime/raw/master/doc/keylime%20RESTful%20API.docx)
* [Bundling a portable Cloud Node](doc/cloud-node-tarball-notes.md) - Create portable tarball of Cloud Node, for usage on systems without python and other dependencies.
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

## License

Copyright (c) 2019 Massachusetts Institute of Technology.

All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
    list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this
    list of conditions and the following disclaimer in the documentation and/or
    other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN
NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
THE POSSIBILITY OF SUCH DAMAGE.


DISTRIBUTION STATEMENT A. Approved for public release: distribution unlimited.

This material is based upon work supported by the Assistant Secretary of Defense for
Research and Engineering under Air Force Contract No. FA8721-05-C-0002 and/or
FA8702-15-D-0001. Any opinions, findings, conclusions or recommendations expressed in this
material are those of the author(s) and do not necessarily reflect the views of the
Assistant Secretary of Defense for Research and Engineering.

Delivered to the US Government with Unlimited Rights, as defined in DFARS Part
252.227-7013 or 7014 (Feb 2014). Notwithstanding any copyright notice, U.S. Government
rights in this work are defined by DFARS 252.227-7013 or DFARS 252.227-7014 as detailed
above. Use of this work other than as specifically authorized by the U.S. Government may
violate any copyrights that exist in this work.
