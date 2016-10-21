# License

DISTRIBUTION STATEMENT A. Approved for public release: distribution unlimited.

This material is based upon work supported by the Assistant Secretary of Defense for 
Research and Engineering under Air Force Contract No. FA8721-05-C-0002 and/or 
FA8702-15-D-0001. Any opinions, findings, conclusions or recommendations expressed in this
material are those of the author(s) and do not necessarily reflect the views of the 
Assistant Secretary of Defense for Research and Engineering.

Copyright 2015 Massachusetts Institute of Technology.

The software/firmware is provided to you on an As-Is basis

Delivered to the US Government with Unlimited Rights, as defined in DFARS Part 
252.227-7013 or 7014 (Feb 2014). Notwithstanding any copyright notice, U.S. Government 
rights in this work are defined by DFARS 252.227-7013 or DFARS 252.227-7014 as detailed 
above. Use of this work other than as specifically authorized by the U.S. Government may 
violate any copyrights that exist in this work.


# python-keylime

A python library to make friends of TPMs and Clouds.  See ACSAC 2016 paper in doc directory

# Installation

keylime requires Python 2.7.9 or newer for proper TLS support.  This is newer than some LTS distributions like Ubuntu 14.04 or centos 7.  See google for instructions on how to get a newer Python onto those platforms.

It also requires the following python packages:

* pycryptodomex>=3.4.1
* tornado>=4.3
* m2crypto>=0.21.1
* setuptools
* python-dev

The latter of these are usually available as distro packages.

On Centos: `yum install -y python-devel python-setuptools python-tornado python-m2crypto`

On Ubuntu: `apt-get install -y python-dev python-setuptools python-tornado python-m2crypto`

You also need a patched version of tpm4720 the IBM software TPM emulator and utilities.

Obtain version 4720 of the IBM TPM emulator to patch at: https://sourceforge.net/projects/ibmswtpm/files/tpm4720.tar.gz/download


extract this version then apply patches/tpm4720-patch.txt with 
```
mkdir -p tpm4720
tar -xzf tpm4720.tar.gz -C tpm4720
cd tpm4720
patch -p1 < tpm4720-patch.txt
```

See README.md in the tpm emulator directory for detailed instructions on how to build and install it.  There are also scripts for building distro packages in the patched version.
The brief synopsis of a quick build/install is:

`apt-get -y install build-essential libssl-dev libtool automake`
or
`yum install -y openssl-devel libtool gcc automake`

then build and install with:
```
cd tpm4720/libtpm
./comp-chardev.sh
sudo make install
```

To ensure that you have the patched version installed ensure that you have the `encaik` utility in your path.

You're finally ready to install keylime!

`sudo python setup.py install`


# configuring keylime

keylime puts its configuration in /etc/keylime.conf.  It will also take an alternate location for the config
in the environment var KEYLIME_CONFIG.

This file is documented with comments and should be self explanatory.

# Running keylime

Keylime has 3 major component services that run: the registrar, verifier, and the node.

The registrar is a simple HTTPS service that accepts TPM public keys and verifies them.  It then presents an interface
to obtain these public keys for checking quotes.

The verifier is the most important component in keylime.  It does initial and periodic checks of system integrity and supports bootstrapping a cryptographic key securely with the node.  The keylime_verifier uses mutual TLS for its control interface.  By default, the verifier will create appropriate TLS certificates for itself in /var/lib/keylime/cv_ca/.  The registrar and tenant will use this as well.
If you use the generated TLS certificates then all the processes need to run as root to allow reading of private key files in /var/lib/keylime/

to run a basic test, run keylime_verifier, keylime_registrar, and keylime_node.  If the node starts up properly, then you can proceed.

The node puts its stuff into /var/lib/keylime/

To kick everything off you need to tell keylime to provision a machine.  THe keylime_tenant utility does this.

As an example, the following command tells keylime to provision a new node at 127.0.0.1 with UUID D432FBB3-D2F1-4A97-9EF7-75BD81C00000
and  talk to a cloud verifier at 127.0.0.1.  finally it will encrypt a file called filetosend and send it
to the node allowing it to decrypt it only if the configured TPM policy (in /etc/keylime.conf) is satisfied

`keylime_tenant -c add -t 127.0.0.1 -v 127.0.0.1 -u D432FBB3-D2F1-4A97-9EF7-75BD81C00000 -f filetosend `

to stop keylime from requesting attestations:

`keylime_tenant -c delete -t 127.0.0.1 -u D432FBB3-D2F1-4A97-9EF7-75BD81C00000`

For additional advanced options for the tenant utility run

`keylime_tenant -h`

# Using keylime CA

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

# to run on OSX 10.11

you need to build m2crypto from source with 

```
brew install openssl
git clone https://gitlab.com/m2crypto/m2crypto.git
python setup.py build build_ext --openssl=/usr/local/opt/openssl/
sudo -E python setup.py install build_ext --openssl=/usr/local/opt/openssl/
```
