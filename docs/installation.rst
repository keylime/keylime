Installation
============

There are three current methods for installing Keylime: the Ansible role, the
Keylime installer or a manual installation.

Ansible Keylime Roles
---------------------

An Ansible role to deploy `Keylime <https://github.com/keylime/keylime>`_
, alongside the `Keylime Rust cloud agent <https://github.com/keylime/rust-keylime>`_

.. warning::
    Please note that the Rust cloud agent is still under early stages of development.
    Those wishing to test drive Keylimes functionality should use the existing
    Python based cloud agent `keylime_agent` until later notice.

This role deploys Keylime for use with a Hardware TPM.

Should you wish to deploy Keylime with a software TPM emulator for development
or getting your feet wet, use the `Ansible Keylime Soft TPM <https://github.com/keylime/ansible-keylime-soft-tpm>`_
role instead.

Usage
~~~~~

Download or clone `Ansible Keylime <https://github.com/keylime/ansible-keylime>`_
from its repository and follow the usage section.

Run the example playbook against your target remote host(s)::

    ansible-playbook -i your_hosts playbook.yml

TPM Version Control (Software TPM)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Ansible Keylime Soft TPM** provides a role type for 2.0 TPM
versions.

TPM 2.0 support can be configured by simply adding
the role in the `playbook.yml` file `here <https://github.com/keylime/ansible-keylime/blob/master/playbook.yml#L11>`_

For TPM 2.0 use::

    - ansible-keylime-tpm20


This rule uses the TPM 2.0 Emulator (IBM software TPM).

Vagrant
~~~~~~~

If you prefer, a `Vagrantfile` is available for provisioning.

Clone the repository and then simply run::

    vagrant up --provider <provider> --provision

For example, using libvirt::

    vagrant up --provider libvirt --provision


For example, using VirtualBox::

    vagrant up --provider virtualbox --provision

Once the VM is started, vagrant ssh into the VM and run `sudo su` - to
become root.

You can then start the various components using commands::

    keylime_verifier
    keylime_registrar
    keylime_agent

WebApp
~~~~~~

The web application can be started with the command `keylime_webapp`. If using
Vagrant, port 443 will be forwarded from the guest to port 8443 on the host.

This will result in the web application being available on url:

https://localhost:8443/webapp/

Rust Cloud agent
~~~~~~~~~~~~~~~

To start the rust cloud agent, navigate to it's repository directory and use
cargo to run::

    [root@localhost rust-keylime]# RUST_LOG=keylime_agent=trace cargo run
        Finished dev [unoptimized + debuginfo] target(s) in 0.28s
        Running `target/debug/keylime_agent`
        INFO  keylime_agent > Starting server...
        INFO  keylime_agent > Listening on http://127.0.0.1:1337

Keylime Bash installer
----------------------

Keylime requires Python 3.7 for dataclasses support.

Installation can be performed via an automated shell script, `installer.sh`. The
following command line options are available::

    Usage: ./installer.sh [option...]
    Options:
    -k              Download Keylime (stub installer mode)
    -o              Use OpenSSL instead of CFSSL
    -t              Create tarball with keylime_agent
    -m              Use modern TPM 2.0 libraries (vs. TPM 1.2)
    -s              Install TPM in socket/simulator mode (vs. chardev)
    -p PATH         Use PATH as Keylime path
    -h              This help info

Note that CFSSL is required if you want to support revocation. As noted above, do not use
the TPM emulator option `-s` in production systems.

Docker - Deployment
--------------------

The verifier, registrar and tenant can also be deployed using Docker images.
Keylime's offical images can be found `here <https://github.com/orgs/keylime/packages>`_.
Those are automatically generated for every commit and release.

For building those images locally see
`here <https://github.com/keylime/keylime/blob/master/docker/release/build_locally.sh>`_.


Docker - Development
--------------------

Python Keylime and with a TPM emulator can also be deployed using Docker.
Since this docker configuration uses a TPM emulator, it should only be
used for development or testing and NOT in production.

Please see either the Dockerfiles
`here <https://github.com/keylime/keylime/tree/master/docker/ci>`_ or our
local CI script
`here <https://github.com/keylime/keylime/blob/master/.ci/run_local.sh>`_
which will automate the build and pull of Keylime.

Manual
------

Keylime requires Python 3.7 or newer to work properly out of the box because older versions do not support dataclasses.

Python-based prerequisites
~~~~~~~~~~~~~~~~~~~~~~~~~~

The following Python packages are required:


* cryptography>=3.3.2
* tornado>=5.0.2
* m2crypto>=0.21.1
* pyzmq>=14.4
* pyyaml>=3.11
* simplejson>=3.8
* requests>=2.6
* sqlalchemy>=1.3
* alembic>=1.1.0
* python-gnupg>=0.4.6
* packaging>=16.0
* psutil>=5.4.2


The current list of required packages can be found `here <https://github.com/keylime/keylime/blob/master/requirements.txt>`_.

All of them should be available as distro packages. See `installer.sh <https://github.com/keylime/keylime/blob/master/installer.sh>`_
for more information if you want to install them this way. You can also let Keylime's `setup.py`
install them via PyPI.


TPM 2.0 Support
~~~~~~~~~~~~~~~

Keylime uses the Intel TPM2 software set to provide TPM 2.0 support.  You will
need to install the tpm2-tss software stack (available `here <https://github.com/tpm2-software/tpm2-tss>`_) and
tpm2-tools utilities available `here <https://github.com/tpm2-software/tpm2-tools>`_.
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
    git clone https://github.com/tpm2-software/tpm2-tools.git tpm2-tools
    pushd tpm2-tools
    ./bootstrap
    ./configure --prefix=/usr/local
    make
    sudo make install


To ensure that you have the recent version installed ensure that you have
the `tpm2_checkquote` utility in your path.

.. note::
    Keylime by default (all versions after 6.2.0) uses the kernel TPM resource
    manager. For kernel versions older than 4.12 we recommend to use the tpm2-abrmd
    resource manager (available `here <https://github.com/tpm2-software/tpm2-abrmd>`_).

How the TPM is accessed by tpm2-tools can be set using the `TPM2TOOLS_TCTI` environment
variable. More information about that can be found
`here <https://github.com/tpm2-software/tpm2-tools/blob/master/man/common/tcti.md>`_.

Talk to the swtpm emulator directly::

    export TPM2TOOLS_TCTI="mssim:port=2321"


To talk to the TPM directly (not recommended)::

    export TPM2TOOLS_TCTI="device:/dev/tpm0"


Install Keylime
~~~~~~~~~~~~~~~

You're finally ready to install Keylime::

    sudo python setup.py install


Optional Requirements
~~~~~~~~~~~~~~~~~~~~~

If you want to support revocation, you also need to have cfssl installed and in your
path on the tenant agent.  It can be obtained from `here <https://github.com/cloudflare/cfssl>`_.  You
will also need to set ca_implementation to "cfssl" instead of "openssl" in `/etc/keylime.conf`.

Database support
---------------------

Keylime supports the following databases::

* SQLite
* PostgreSQL
* MySQL
* Oracle
* Microsoft SQL Server

SQLite is supported as default.

Each database is configured within `/etc/keylime.conf` for both the keylime_verifier
and keylime_registrar databases.

SQLite
~~~~~~

The following illustrates examples for SQLite and PostgreSQL::

    database_drivername = sqlite
    database_username = ''
    database_password = ''
    database_host = ''
    database_port = ''
    database_name = cv_data.sqlite
    database_query = ''

PostgreSQL
~~~~~~~~~~

For PostgreSQL you will need to install the database first and set up a user
account::

    database_drivername = postgresql
    database_username = keylime
    database_password = allyourbase
    database_host = localhost
    database_port = 5432
    database_name = keylime_db
    database_query = ''

For details on other platforms, please refer to the SQLAlchemy documentation
on `engine configuration <https://docs.sqlalchemy.org/en/13/core/engines.html>`_.
