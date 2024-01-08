=============
Configuration
=============

Keylime is configured by files installed by default in ``/etc/keylime``.
The files are loaded following a hierarchical order in which the values set for
the options can be overridden by the next level.

For each component, a base configuration file (e.g.
``/etc/keylime/verifier.conf``) is loaded, setting the base values.
Then, the configuration snippets placed in the respective directory (e.g.
``/etc/keylime/verifier.conf.d``) are loaded, overriding the previously set
values.
Finally, options can be overridden via environment variables.

The following components can be configured:

.. list-table:: Components and configuration
    :header-rows: 1

    * - Component
      - Default base config file
      - Default snippets directory
    * - agent
      - ``/etc/keylime/agent.conf``
      - ``/etc/keylime/agent.conf.d``
    * - verifier
      - ``/etc/keylime/verifier.conf``
      - ``/etc/keylime/verifier.conf.d``
    * - registrar
      - ``/etc/keylime/registrar.conf``
      - ``/etc/keylime/registrar.conf.d``
    * - tenant
      - ``/etc/keylime/tenant.conf``
      - ``/etc/keylime/tenant.conf.d``
    * - ca
      - ``/etc/keylime/ca.conf``
      - ``/etc/keylime/ca.conf.d``
    * - logging
      - ``/etc/keylime/logging.conf``
      - ``/etc/keylime/logging.conf.d``

The next sections contain details of the configuration files

Configuration file processing order
-----------------------------------

The configurations are loaded in the following order:

1. Default (hardcoded) option values
2. Base configuration options, overriding previously set values

  * By default, located in ``/etc/keylime/<component>.conf`` for each component

3. Configuration snippets, overriding previously set values

 * By default, located in ``/etc/keylime/<component>.conf.d`` for each component
 * The configuration snippets are loaded in lexicographic order

4. Environment variables, overriding previously set values

 * The environment variables are in the form
   ``KEYLIME_{COMPONENT}_[SECTION_]{OPTION}``, for example
   ``KEYLIME_VERIFIER_SERVER_KEY``.

Configuration file format
-------------------------

The configuration files for all components are written in INI format, except for
the agent which is written in TOML format.

Each component contains a main section named after the component name (for
historical reasons).  For example, the main section of ``verifier.conf`` is
``[verifier]``.

Override configurations via configuration snippets
--------------------------------------------------

To override a configuration option using a configuration snippet, simply create
a file in the component's configuration snippets directory (e.g.
``/etc/keylime/verifier.conf.d`` to override options from
``/etc/keylime/verifier.conf``).

Note that the configuration snippets are loaded and processed in
lexicographic order, keeping the last value set for each option.
It is recommended to use a numeric prefix for the files to control the order in
which they should be processed (e.g. ``001-custom.conf``).

The configuration snippets need the section to be explicitly provided, meaning
that the snippets are required to be valid INI (or TOML in the case of the
agent) files.

For example, the following snippet placed in
``/etc/keylime/verifier.conf.d/0001-ip.conf`` can override the default verifier ip
address:

.. code-block:: ini

    [verifier]
    ip = 172.30.1.10

Override configurations via environment variables
-------------------------------------------------

It is possible to override configuration options by setting the desired value
through environment variables.
The environment variables are defined as
``KEYLIME_{COMPONENT}_[SECTION_]{OPTION}``

The section can be omitted if the option to set is located in the main section
(the section named after the component). Otherwise the section is required.

For example, to set the ``webhook_url` option from the `[revocations]`` section in
the ``verifier.conf`` file, the environment variable to set is
``KEYLIME_VERIFIER_REVOCATIONS_WEBHOOK_URL``.

To set an option located in the main section, for example the ``server_key``
option from the ``[verifier]`` section in the ``verifier.conf``, the environment
variable to set is ``KEYLIME_VERIFIER_SERVER_KEY`` (note that the section can be
omitted).

Configuraton upgrades
---------------------

When updating keylime, it is also recommended to upgrade the configuration to
make sure that the used configuration is compatible with the keylime version.

The ``keylime_upgrade_config`` script is installed by default with the keylime
components, and is the script that performs the configuration upgrade following
the upgrade mappings and templates.

By default, the configuration templates are installed in
``/usr/share/keylime/templates``. For each configuration version a respective
directory is installed in the templates directory.

The ``keylime_upgrade_config`` will take the current configuration files as input
(by default from ``/etc/keylime/``). For each component, the version of the
configuration file is checked against the available upgrade template versions to
decide if an upgrade is necessary or not. In case an upgrade is not necessary,
meaning all the components configuration files are up-to-date, the script does
not modify the configuration files.

For each component that needs upgrade, the script will process all the
transformations needed by each configuration version. For example, suppose the
installed configuration file is in version ``1.0`` and there are upgrade templates
available for the versions ``2.0`` and ``3.0``. The upgrade script will process the
transformations defined from the version ``1.0`` to the version ``2.0`` and then
from the version ``2.0`` to the version ``3.0``.

For each configuration upgrade template version, there are the following files:

* ``mapping.json``: This file defines the transformations that should be
  performed, mapping the configuration option from the older version to the
  configuration options in the new version.  If the mapping has the ``update``
  type, then it describes operations to transform the previous version to the
  next (adding, removing, or replacing options)
* ``<component>.j2``: These are templates for the configuration files. It defines
  the output format for the configuration file for each component.
* ``adjust.py``: This is an optional script that defines special adjustments that
  cannot be specified through the ``mapping.json`` file. It is executed after the
  mapping transformations are applied.

The main goal of the upgrade script is to keep the configuration changes made by
the user and keep the configuration files up-to-date.  For new options, the
default values are used.

The configuration upgrade script ``keylime_upgrade_script``
-----------------------------------------------------------

Run ``keylime_upgrade_config --help`` for the description of the supported
options.

When executed by the ``root`` user, the default output directory for the
``keylime_upgrade_config`` script is the ``/etc/keylime`` directory. The existing
configuration files are kept intact as backup and renamed with the ``.bkp`` extension
appended to the file names.

In case the ``--output`` option is provided to the ``keylime_upgrade_config``
script, the configuration files are written even when they were alredy
up-to-date using the available templates.  It can be seen as a way to force the
creation of the configuration fiels, fitting the options read into the new
templates.

Passing the ``--debug`` option to the ``keylime_upgrade_config``, the logging level
is set to ``DEBUG``, making the script more verbose.

The templates directory to be processed can be passed via the ``--templates``
option. If provided, the script will try to find the configuration upgrade
templates in the provided path instead of the default location
(``/usr/share/keylime/templates``)

To output files only for a subset of the components, the ``--component`` can be
provided multiple times.

To override input files (by default the ``/etc/keylime/<component>.conf`` for each
component), the ``--input`` option can be passed multiple times. Unknown
components are ignored.

To stop the processing in a target version, set the target version with the
``--version`` option.

To ignore the input files and use the default value for all options, the
``--defaults`` option can be provided

Finally, to process a single mapping file, the mapping file path can be passed
via the ``--mapping`` option
