# python-keylime

A python library to make friends of TPMs and Clouds.  See ACSAC 2016 paper in doc directory: https://github.com/mit-ll/python-keylime/blob/master/doc/tci-acm.pdf  A presentation on keylime is also available in the doc directory: https://github.com/mit-ll/python-keylime/raw/master/doc/llsrc-keylime-acsac-v6.pptx 

## Errata from the ACSAC Paper

We discovered a typo in Figure 5 of the published ACSAC paper. The final interaction between the Tenant and Cloud Verifier showed an HMAC of the node's ID using the key K_e.  This should be using K_b.  The paper in this repository and the ACSAC presentation have been updated to correct this typo.  

## Installation

### Automated

keylime requires Python 2.7.10 or newer for proper TLS support.  

keylime supports installation via an automated shell script, `installer.sh`.  The following command line options are available: 
```
Usage: ./installer.sh [option...]
Options:
-k              Download Keylime (stub installer mode)
-o              Use OpenSSL instead of CFSSL
-t              Create tarball with keylime_node
-s              Install TPM 4720 in socket mode (vs. chardev)
-p PATH         Use PATH as Keylime path
-h              This help info
```

### Manual 

keylime requires Python 2.7.10 or newer for proper TLS support.  This is newer than some LTS distributions like Ubuntu 14.04 or centos 7.  See google for instructions on how to get a newer Python onto those platforms.

It also requires the following python packages:

* pycryptodomex>=3.4.1
* tornado>=4.3
* m2crypto>=0.21.1
* pyzmq>=14.4
* setuptools>=0.7
* python-dev

The latter of these are usually available as distro packages.

On Centos: `yum install -y python-devel python-setuptools python-tornado python-m2crypto python-zmq`

On Ubuntu: `apt-get install -y python-dev python-setuptools python-tornado python-m2crypto python-zmq`

You also need a patched version of tpm4720 the IBM software TPM emulator and utilities.  This is available at https://github.com/mit-ll/tpm4720-keylime
See README.md in that project for detailed instructions on how to build and install it.  
The brief synopsis of a quick build/install is:
On Ubuntu: `apt-get -y install build-essential libssl-dev libtool automake`

On Centos: `yum install -y openssl-devel libtool gcc automake`

then clone, build. and install with:
```
git clone https://github.com/mit-ll/tpm4720-keylime.git
cd tpm4720-keylime/libtpm
./comp-chardev.sh
sudo make install
```

To ensure that you have the patched version installed ensure that you have the `encaik` utility in your path.

You're finally ready to install keylime!

`sudo python setup.py install`

## Optional Requirements

If you want to support revocation and the keylime CA (see below), you also need to have cfssl installed and in your path on the tenant node.  It can be obtained from https://github.com/cloudflare/cfssl  You will also need to set ca_implementation to "cfssl" instead of "openssl".

## Configuring keylime

keylime puts its configuration in /etc/keylime.conf.  It will also take an alternate location for the config
in the environment var KEYLIME_CONFIG.

This file is documented with comments and should be self explanatory.

## Making sure your TPM is ready for keylime

The above instructions for installing tpm4720 will be configured to talk to /dev/tpm0.  If this device is not on your system, then you may need to build/install TPM support for your kernel.  You can use 

`dmesg | grep -i tpm`

to see if the kernel is initializing the TPM driver during boot.  If you have the /dev/tpm0 device, you next need to get it into the right state.  The kernel driver reports status on the TPM in /sys.  You can locate the folder with relevant info from the driver using

`sudo find /sys -name tpm0`

Several results may be returned, but the duplicates are just symlinks to one location.  Go to one of the returned paths, for example, /sys/class/misc/tpm0.  Now change to the device directory.  Here you can find some information from the TPM like the current pcr values and sometimes the public EK is available.  It will also report two important state values: active and enabled.  To use keylime, both of these must be 1.  If they are not, you may need to reboot into the BIOS to enable and activate the TPM.  If you need to both enable and activate, then you must enable first, reboot, then activate and finally reboot again.  It is also possible that you may need to assert physical presence (see manual for your system on how to do this) in order to accomplish these actions in your BIOS.  

If your system shows enabled and activated, you can next check the "owned" status in the /sys directory.  Keylime can take a system that is not owned (i.e., owned = 0) and take control of it.  Keylime can also take a system that is already owned, provided that you know the owner password and that keylime or another trusted computing system that relies upon tpm4720 previously took ownership.  If you know the owner password, you can set the option tpm_ownerpassword in keylime.conf to this known value.

## Running keylime

Keylime has 3 major component services that run: the registrar, verifier, and the node.

The registrar is a simple HTTPS service that accepts TPM public keys and verifies them.  It then presents an interface
to obtain these public keys for checking quotes.

The verifier is the most important component in keylime.  It does initial and periodic checks of system integrity and supports bootstrapping a cryptographic key securely with the node.  The keylime_verifier uses mutual TLS for its control interface.  By default, the verifier will create appropriate TLS certificates for itself in /var/lib/keylime/cv_ca/.  The registrar and tenant will use this as well.
If you use the generated TLS certificates then all the processes need to run as root to allow reading of private key files in /var/lib/keylime/

To run a basic test, run keylime_verifier, keylime_registrar, and keylime_node.  If the node starts up properly, then you can proceed.

The node puts its stuff into /var/lib/keylime/

### Provisioning

To kick everything off you need to tell keylime to provision a machine. This can be done either with the keylime tenant or webapp.

#### Provisioning with keylime_tenant

The keylime_tenant utility can be used to provision your node.

As an example, the following command tells keylime to provision a new node at 127.0.0.1 with UUID D432FBB3-D2F1-4A97-9EF7-75BD81C00000
and talk to a cloud verifier at 127.0.0.1.  Finally it will encrypt a file called filetosend and send it
to the node allowing it to decrypt it only if the configured TPM policy (in /etc/keylime.conf) is satisfied

`keylime_tenant -c add -t 127.0.0.1 -v 127.0.0.1 -u D432FBB3-D2F1-4A97-9EF7-75BD81C00000 -f filetosend`

To stop keylime from requesting attestations:

`keylime_tenant -c delete -t 127.0.0.1 -u D432FBB3-D2F1-4A97-9EF7-75BD81C00000`

For additional advanced options for the tenant utility run:

`keylime_tenant -h`

#### Provisioning with keylime_webapp

There is also a WebApp GUI interface for the tenant, available by running keylime_webapp.  Next, simply navigate to the WebApp in 
your web browser (https://localhost/webapp/ by default, as specified in /etc/keylime.conf). 

Note that the webapp must be run on the same machine as the tenant, since it uses its keys for TLS authentication (in /var/lib/keylime/).

## Using keylime CA

we've built a simple certificate authority to use with keylime. You can interact with it using keylime_ca or keylime_tenant.
Options for configuring the certificates that keylime_ca creates are in /etc/keylime.conf.  

NOTE: This CA functionality is different than the TLS support for talking to the verifier or registrar (though it uses some of the same config options in /etc/keylime.conf.  This CA is for the cloud node's you provision and you can use keylime to bootstrap the private keys into nodes.

To initialize a new certificate authority run:

`keylime_ca --command init`

This will create a certificate authority in /var/lib/keylime/ca and requires root access to write the directory.  Use -d to point it to another directory not necessarily require root.

You can create certificates under this ca using

`keylime_ca --command create --name certname.host.com`

This will create certificate signed by the CA in /var/lib/keylime/ca (-d also works here to have it use a different CA directory).

To obtain the a zip file of the certificate, public key, and private key for a cert use

`keylime_ca --command pkg --name certname.host.com`

This will zip the above files and place them in /var/lib/keylime/ca/certname.host.com-pkg.zip.  The private key will be protected by
the key that you were prompted with.

You may wonder why this is in keylime at all?  Well, you can tell keylime_tenant to automatically create a key and then provision
a node with it.  Use the --cert option to keylime_tenant to do this.  This takes in the directory of the CA.

`keylime_tenant -c add -t 127.0.0.1 -u D432FBB3-D2F1-4A97-9EF7-75BD81C00000 --cert /var/lib/keylime/ca`

If you also have the option extract_payload_zip in /etc/keylime.conf set to True on the cloud_node, then it will
automatically extract the zip containing an unprotected private key, public key, certificate and CA certificate to /var/lib/keylime/secure/unzipped

If the option cloud verifier option revocation_notifier is set to True, then the CV will sign a revocation message and send it over 0mq to any subscribers.  The keylime CA supports listening to these notifications and will generate an updated CRL.  To enable this feature, run

`keylime_ca -c listen -n ca/RevocationNotifier-public.pem`

The revocation key will be automatically created by the tenant the first time you use the CA with keylime.  Currently the CRL is written back to the CA directory, but that's it.

## Bundling Keylime Cloud Node into a portable tarball

### Automated

Particularly if your Keylime cloud node will be running on a bare-bones system (e.g., without libc installed), it can be useful to create a tarball of the Cloud Node service which includes all needed dependencies.  

This tarball can be generated as part of the automated installer process by using the `-t` option *(Create tarball with keylime_node)* during installation.  This builds a semi-portable node binary (keylime_node) and tarballs it along with all needed dependencies. 

You can also choose to do this directly with the `make_node_bundle_tarball.sh` script in the keylime directory, which automatically installs all needed tools, builds the semi-portable binary and tarballs it with all of its library dependencies.  This tarball will appear in the dist folder.

If only the semi-portable binary is needed (without library dependencies), then it can be found alongside the tarball in the dist folder (keylime_node). 

### Manual (semi-portable binary only)

You can build a single binary for the keylime_node service.  It uses http://www.pyinstaller.org/  Install with `pip install pyinstaller`

Make sure that you have UPX for binary compression.  On ubuntu: `apt-get install upx-ucl`.

Ensure that you have the tools needed to install keylime normally (see section above). On Ubuntu:
`apt-get install -y python-dev python-setuptools python-tornado python-m2crypto python-zmq`.  Now pull in the rest of the python dependencies with `sudo python setup.py install`

Now you can run `make_node_bundle.sh` in the keylime directory.  The single binary will appear inside the dist folder.  You can distribute this file along with keylime.conf and run the node service without any other Keylime dependencies.  It will look for the conf file in /etc/ first and then in the same directory as the keylime_node binary.

### Notes

1. *Due to a bug in pyinstaller 3.2.1 and prior, you may receive errors when running keylime_node (e.g., cannot load Cryptodome).  For more information, refer to their patch for this bug (https://github.com/pyinstaller/pyinstaller/pull/2453).*
    
    *For this reason, it is recommended to use at least pyinstaller 3.3.  If your system does not have pyinstaller 3.3+, you can mitigate this issue by copying their hook file [PyInstaller/hooks/hook-Cryptodome.py](https://raw.githubusercontent.com/pyinstaller/pyinstaller/dacc07f49e2c22bba5473f4cb5b2a5194cdae5e1/PyInstaller/hooks/hook-Cryptodome.py) into your ``PyInstaller/hooks/`` directory (e.g.,/usr/local/lib/python2.7/dist-packages/PyInstaller/hooks/ or /usr/lib/python2.7/site-packages/PyInstaller/hooks/).*
    
2. *In some cases (e.g., if your target machine already has Python installed), it may be necessary to compile Python (on the build machine) with rpath defined for pyinstaller to work properly:*
    
    ```
    ./configure --enable-shared --prefix=<path_to_python> LDFLAGS=-Wl,-rpath=<path_to_python_libs>
    ```
    
    *See https://bugs.python.org/issue27685 for more information.*


## To run on OSX 10.11

You need to build m2crypto from source with 

```
brew install openssl
git clone https://gitlab.com/m2crypto/m2crypto.git
python setup.py build build_ext --openssl=/usr/local/opt/openssl/
sudo -E python setup.py install build_ext --openssl=/usr/local/opt/openssl/
```

## License

Copyright (c) 2015 Massachusetts Institute of Technology.

All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


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
