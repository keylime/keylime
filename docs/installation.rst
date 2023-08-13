Installation
============

There are three current methods for installing Keylime: the Ansible role, the
Keylime installer or a manual installation.

Ansible Keylime Roles
---------------------

An Ansible role to deploy `Keylime <https://github.com/keylime/keylime>`_
, alongside the `Keylime Rust agent <https://github.com/keylime/rust-keylime>`_

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
the role in the :code:`playbook.yml` file `here <https://github.com/keylime/ansible-keylime/blob/master/playbook.yml#L11>`_

For TPM 2.0 use::

    - ansible-keylime-tpm20


This rule uses the TPM 2.0 Emulator (IBM software TPM).

Rust agent
~~~~~~~~~~~~~~~
.. note::
    The Rust agent is the official agent for Keylime and replaces the Python implementation.
    For the rust agent a different configuration file is used (by default :code:`/etc/keylime/agent.conf`)
    which is **not** interchangeable with the old Python configuration.

Installation instructions can be found in the `README.md <https://github.com/keylime/rust-keylime>`_ for the Rust agent.

Keylime Bash installer
----------------------

Keylime requires Python 3.6 or greater.

Installation can be performed via an automated shell script, :code:`installer.sh`. The
following command line options are available::

    Usage: ./installer.sh [option...]
    Options:
    -k              Download Keylime (stub installer mode)
    -m              Use modern TPM 2.0 libraries; this is the default
    -s              Install & use a Software TPM emulator (development only)
    -p PATH         Use PATH as Keylime path
    -h              This help info


Docker - Deployment
--------------------

The verifier, registrar and tenant can also be deployed using Docker images.
Keylime's official images can be found `here <https://quay.io/organization/keylime>`_.
Those are automatically generated for every commit and release.

For building those images locally see
`here <https://github.com/keylime/keylime/blob/master/docker/release/build_locally.sh>`_.

Manual
------

Keylime requires Python 3.6 or greater.

Python-based prerequisites
~~~~~~~~~~~~~~~~~~~~~~~~~~

The following Python packages are required:


* cryptography>=3.3.2
* tornado>=5.0.2
* pyzmq>=14.4
* pyyaml>=3.11
* requests>=2.6
* sqlalchemy>=1.3.12
* alembic>=1.1.0
* packaging>=20.0
* psutil>=5.4.2
* lark>=1.0.0
* pyasn1>=0.4.2
* pyasn1-modules>=0.2.1
* jinja2>=3.0.0
* gpg (Note: the GPG bindings must match the local GPG version and therefore this package should not be installed via PyPI)
* typing-extensions>=3.7.4 (only for Python versions < 3.8)

The current list of required packages can be found `here <https://github.com/keylime/keylime/blob/master/requirements.txt>`_.

All of them should be available as distro packages. See `installer.sh <https://github.com/keylime/keylime/blob/master/installer.sh>`_
for more information if you want to install them this way. You can also let Keylime's :code:`setup.py`
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
    popd


To ensure that you have the recent version installed ensure that you have
the :code:`tpm2_checkquote` utility in your path.

.. note::
    Keylime by default (all versions after 6.2.0) uses the kernel TPM resource
    manager. For kernel versions older than 4.12 we recommend to use the tpm2-abrmd
    resource manager (available `here <https://github.com/tpm2-software/tpm2-abrmd>`_).

How the TPM is accessed by tpm2-tools can be set using the :code:`TPM2TOOLS_TCTI` environment
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


Configuring basic (m)TLS setup
------------------------------
Keylime uses mTLS authentication between the different components.
By default the verifier creates a CA for this under :code:`/var/lib/keylime/cv_ca/` on first startup.
The directory contains files for three different components:

* *Root CA*: :code:`cacert.crt` contains the root CA certificate.
  **Important:** this certificate needs to be also be deployed on the agent, otherwise the tenant and verifier cannot
  connect to the agent!
* *Server certificate and key*: :code:`server-cert.crt` and :code:`server-{private,public}.pem` are used by the registrar
  and verifier for their HTTPS interface.
* *Client certificate and key*: :code:`client-cert.crt` and :code:`client-{private,public}.pem` are used
  by the tenant to authenticate against the verifier, registrar and agent. The verifier uses this key and certificate
  to authenticate against the agent.

Keylime allows each component to use their own server and client keys and
also a list of trusted certificates for mTLS connections.
Please refer to options the the respective configuration files for more details.

Database support
---------------------

Keylime supports the following databases:

* SQLite
* PostgreSQL
* MySQL
* MariaDB

SQLite is configured as default (:code:`database_url = sqlite`) where the databases are stored under :code:`/var/lib/keylime`.

Starting with Keylime version 6.4.0 only supports SQLAlchemy's URL format to allow a more flexible configuration.
The format for the supported databases can be found in the SQLAlchemy
`engine configuration documentation <https://docs.sqlalchemy.org/en/14/core/engines.html#database-urls>`_.
