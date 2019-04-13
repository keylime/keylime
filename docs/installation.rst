Installation
============

There are three current methods for installing Keylime, the ansible role, the
keylime installer or a manual installation.

Ansible Keylime Roles
---------------------

An Ansible role to deploy `Python Keylime <https://github.com/keylime/python-keylime>`_
, alongside the `Keylime rust cloud node <https://github.com/keylime/rust-keylime>`_

Please note that the rust cloud node is still under early stages of Development.
Those wishing to test drive keylimes functionality should use the existing
python based cloud node `keylime_node` until later notice.

This role deploys keylime for use with a Hardware TPM Emulator

Should you wish tto deploy Keylime with a software TPM emulator for development
or getting your feet wet, use the `Ansible Keylime Soft TPM <https://github.com/keylime/ansible-keylime-soft-tpm>`_
role instead.

Download or clone `Ansible Keylime <https://github.com/keylime/ansible-keylime>`_
from its repository and follow the usage section.

Usage
~~~~~

Run the example playbook against your target remote node(s)::

    ansible-playbook -i your_hosts playbook.yml

TPM Version Control (Software TPM)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Ansible Keylime Soft TPM provides two role types for both 1.2 and 2.0 TPM versions.

Either TPM version 1.2 or TPM 2.0 support can be configured by simply changing
the role in the `playbook.yml` file `here <https://github.com/keylime/ansible-keylime/blob/master/playbook.yml#L11>`_

For TPM 2.0 use::

    - ansible-keylime-tpm20

For TPM 1.20 use::

    - ansible-keylime-tpm12

Both roles will deploy the relevant TPM 1.2 Emulator (tpm4720) or 2.0 Emulator
(IBM software TPM).

Vagrant
~~~~~~~

If you prefer, a Vagrantfile is available for provisioning.

Clone the repository and then simply run `vagrant up --provider <provider> --provision`

For example, using libvirt::

    vagrant up --provider libvirt --provision


For example, using VirtualBox::

    vagrant up --provider virtualbox --provision

Once the VM is started, vagrant ssh into the VM and run `sudo su` - to
become root.

You can then start the various components using commands::

    keylime_verifier
    keylime_registrar
    keylime_node

WebApp
~~~~~~

The web application can be started with the command `keylime_webapp`. If using
Vagrant, port 443 will be forwarded from the guest to port 8443 on the host.

This will result in the web application being available on url:

https://localhost:8443/webapp/

Rust Cloud node
~~~~~~~~~~~~~~~

To start the rust cloud node, navigate to it's repository directory and use
cargo to run::

    [root@localhost rust-keylime]# RUST_LOG=keylime_node=trace cargo run
        Finished dev [unoptimized + debuginfo] target(s) in 0.28s
        Running `target/debug/keylime_node`
        INFO  keylime_node > Starting server...
        INFO  keylime_node > Listening on http://127.0.0.1:1337

Keylime Bash installer
----------------------

Keylime requires Python 2.7.10 or newer for proper TLS support.

Installation can be performed via an automated shell script, `installer.sh`. The
following command line options are available::

    Usage: ./installer.sh [option...]
    Options:
    -k              Download Keylime (stub installer mode)
    -o              Use OpenSSL instead of CFSSL
    -t              Create tarball with keylime_node
    -m              Use modern TPM 2.0 libraries (vs. TPM 1.2)
    -s              Install TPM in socket/simulator mode (vs. chardev)
    -p PATH         Use PATH as Keylime path
    -h              This help info

Note that CFSSL is required if you want to support revocation. As noted above, do not use
the TPM emulator option `-s` in production systems.

Docker (Development Only)
-------------------------

Python keylime and related emulators can also be deployed using Docker.
Since this docker configuration currently uses a TPM emulator,
it should only be used for development or testing and NOT in production.

Please see either the Dockerfiles
`here <https://github.com/keylime/python-keylime/tree/master/docker>`_ or our
local CI script
`here <https://github.com/keylime/python-keylime/blob/master/.ci/run_local.sh>`_
which will automate the build and pull of keylime on TPM 1.2 or 2.0.

Manual
------

Keylime requires Python 2.7.10 or newer for proper TLS support.  This is newer than
some LTS distributions like Ubuntu 14.04 or CentOS 7.  See google for instructions
on how to get a newer Python onto those platforms.

Python-based prerequisites
~~~~~~~~~~~~~~~~~~~~~~~~~~

The following python packages are required:

* pycryptodomex>=3.4.1
* tornado>=4.3
* m2crypto>=0.21.1
* pyzmq>=14.4
* setuptools>=0.7
* python-dev
* pyyaml

The latter of these are usually available as distro packages. See `installer.sh <https://github.com/keylime/python-keylime/blob/master/installer.sh>`_
for more information if you want to install them this way. You can also let keylime's `setup.py`
install them via PyPI.

TPM 1.2 Support
~~~~~~~~~~~~~~~

You also need a patched version of tpm4720 the IBM software TPM emulator and
utilities.  This is available `here <https://github.com/keylime/tpm4720-keylime>`_
Even if you are using keylime with a real TPM, you must install the IBM emulator
because keylime uses the command line utilities that come with it.
See README.md in that project for detailed instructions on how to build and install it.

The brief synopsis of a quick build/install (after installing dependencies) is::

    git clone https://github.com/keylime/tpm4720-keylime.git
    cd tpm4720-keylime/libtpm
    ./comp-chardev.sh
    sudo make install

To build tpm4720 to use the TPM emulator replace `./comp-chardev.sh` with `./comp-sockets.sh`.

To ensure that you have the patched version installed ensure that you have
the `encaik` utility in your path.

TPM 2.0 Support
~~~~~~~~~~~~~~~

Keylime uses the Intel TPM2 software set to provide TPM 2.0 support.  You will
need to install the tpm2-tss software stack (available `here <https://github.com/tpm2-software/tpm2-tss>`_) as well as a patched version of the
tpm2-tools utilities available `here<https://github.com/keylime/tpm2-tools>`_. 
See README.md in these projects for detailed instructions on how to build and install.

The brief synopsis of a quick build/install (after installing dependencies) is::
    
    # tpm2-tss
    git clone https://github.com/tpm2-software/tpm2-tss.git tpm2-tss
    pushd tpm2-tss
    ./bootstrap
    ./configure --prefix=/usr
    make
    sudo make install
    popd
    # tpm2-tools
    git clone https://github.com/keylime/tpm2-tools.git tpm2-tools
    pushd tpm2-tools
    ./bootstrap
    ./configure --prefix=/usr/local
    make
    sudo make install


To ensure that you have the patched version installed ensure that you have
the `tpm2_checkquote` utility in your path.

TPM 2.0 Resource Manager
~~~~~~~~~~~~~~~~~~~~~~~~

Note that it is recommended that you use the tpm2-abrmd resource manager
(available at https://github.com/tpm2-software/tpm2-abrmd) as well instead of
communicating directly with the TPM.  See README.md at that project for
detailed instructions on how to build and install.

A brief, workable example for Ubuntu 18 LTS systems is::

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

# NOTE: if using swtpm2 emulator, you need to run the tpm2-abrmd service as::

    sudo -u tss /usr/local/sbin/tpm2-abrmd --tcti=mssim &

Alternatively, it is also possible, though not recommended, to communicate
directly with the TPM (and not use a resource manager).  This can be done by
setting the environment var `TPM2TOOLS_TCTI` to the appropriate value:

To talk directly to the swtpm2 emulator: `export TPM2TOOLS_TCTI="mssim:port=2321"`

To talk directly to a real TPM: `export TPM2TOOLS_TCTI="device:/dev/tpm0"`

Install Keylime
~~~~~~~~~~~~~~~

You're finally ready to install keylime::

    sudo python setup.py install

To run on OSX 10.11+
~~~~~~~~~~~~~~~~~~~~

You need to build m2crypto from source with::

    brew install openssl
    git clone https://gitlab.com/m2crypto/m2crypto.git
    python setup.py build build_ext --openssl=/usr/local/opt/openssl/
    sudo -E python setup.py install build_ext --openssl=/usr/local/opt/openssl/


Optional Requirements
~~~~~~~~~~~~~~~~~~~~~

If you want to support revocation, you also need to have cfssl installed and in your
path on the tenant node.  It can be obtained from `here <https://github.com/cloudflare/cfssl>`_.  You
will also need to set ca_implementation to "cfssl" instead of "openssl" in `/etc/keylime.conf`.
