Updating Configurations
=======================

When configuration changes are introduced, a new mapping and configuration
templates should be created (at least once per release where configuration
changes were introduced).

When only adding new configuration options, the configuration file is still
compatible with the previous version since all the options that existed before
are still present. In this case, the configuration minor version number should
be bumped.

When an option is removed or renamed, the configuration file is no longer
compatible with the previous version. In this case, the major version number
should be bumped.

Adding upgrade template files
-----------------------------

For each configuration version, it should exist a corresponding directory under
the ``templates``. For example, for the configuration version ``2.0``, the
directory ``templates/2.0`` was added.

For each new version, the following files should be created:

* A directory for the new version number should be created in the ``templates``
  directory
* The ``mapping.json`` file that specify the transformations from the previous
  configuration version to the new version should be added. See the format in
  :ref:`Mapping file format`
* For each existing component, the corresponding configuration file jinja2
  template should be added. For example, for the ``verifier``, the
  ``verifier.j2`` should be created in the directory for the new version
* If special transformations that cannot be expressed through the simple
  operations in the ``mapping.json`` file, the ``adjust.py`` script can be
  added. See below the requirements for the ``adjust.py`` in :ref:`Adjust script
  requirements`

For example, when adding templates for a new version ``X.Y``, the following
directory tree should be added::

   templates
   └── X.Y
       ├── adjust.py (optional)
       ├── agent.j2
       ├── ca.j2
       ├── logging.j2
       ├── mapping.json
       ├── registrar.j2
       ├── tenant.j2
       ├── test.md
       └── verifier.j2

Mapping file format
-------------------

For each configuration version, a mapping from the previous version to the new
version is required. The mapping is provided as a JSON file, with the following
fields:

* ``version``: The mapping version, in the ``MAJOR.MINOR`` format. The value
  assigned to this field should match the template directory name. For example,
  for the mapping in the ``templates/2.0`` directory, the ``version`` field
  should be set as ``2.0``.
* ``type``: The mapping type. The supported values are ``update`` and ``full``.
  See the requirements for each type below in :ref:`Update mapping` and
  :ref:`Full mapping`, respectively.
* ``components``: The components to be modified by the mapping. Depending on the
  mapping type, the contents of the ``components`` field are different.
  See the requirements for each type below in :ref:`Update mapping` and
  :ref:`Full mapping`.
* ``subcomponents``: Only present in the ``full`` mapping type, this field is
  required to associate sections to their parent components.

* Full mapping: The ``type`` field in the ``mapping.json`` file should be set as
  ``full`` for the mapping to be processed as a full mapping.
  In this type of mapping, all the options for all the components are treated as
  replacements of options.
  If an option is omitted, it means the option is removed in the new configuration
  version.


Update mapping
--------------

For the update mapping, the ``type`` field in the ``mapping.json`` file should
be set as ``update``. The update mapping is used to create a new configuration
version by applying changes to the existing options through operations and
preserve all the other options.  This mapping type is the recommended way to
introduce small changes to the configuration files.

In the update mapping, the ``components`` field list the components that are
modified from the previous version, and the operations applied to them. See the
format of the components dictionary below in the :ref:`Update mapping
components format`

The update mapping does not use or need the ``subcomponents`` field.

Update mapping components format
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

For the update mapping, the ``components`` field should be set as a dictionary
which maps the sections to be modified to the operations to be applied to them.
Only the sections that are modified need to be present in the dictionary, all
the omitted components are preserved as they were in the previous version.

The supported operations to modify the sections are:

* ``add``: This operation adds a new option to the section. It should be
  assigned as a dictionary mapping the new option name to its default value.

  For example, the following mapping file adds 2 new options to the ``[comp_a]``
  section:

  .. code-block:: json

    {
        "version": "3.1",
        "type": "update",
        "components": {
            "comp_a": {
                "add": {
                    "new_option": "value",
                    "new_option2": "value2"
                }
            }
        }
    }

* ``remove``: This operation removes options that exists in the previous
  configuration version. An array of options to be removed should be assigned to
  the ``remove`` field for the section/component to be modified.

  For example, the following mapping file removes 2 options from the
  ``[comp_a]`` section:

  .. code-block:: json

    {
        "version": "3.1",
        "type": "update",
        "components": {
            "comp_a": {
                "remove": ["unused_option", "another_unused_option"]
            }
        }
    }


* ``replace``: This operation replaces an option that exists in the previous
  configuration version with another in the new version. During the processing
  of the mapping file, the value found in the replaced option will be preserved,
  and assigned to the new option in the output. If the option is not found in
  the input configuration file, the default value is used instead.

  The ``replace`` field should be set as a dictionary mapping the option to be
  replaced to the parameters for the new option. The dictionary should have the
  following fields:

  * ``section``: The section to which the new option should be added
  * ``option``: The new option name
  * ``default``: The default value to be used in case the old option is not
    found in the input configuration.

  For example, the following mapping file replaces two options from the
  ``[comp_a]`` section:

  .. code-block:: json

    {
        "version": "3.1",
        "type": "update",
        "components": {
            "comp_a": {
                "replace": {
                    "old_option_to_replace": {
                        "section": "new_section",
                        "option": "new_option",
                        "default": "value"
                    },
                    "old_value": {
                        "section": "other_section",
                        "option": "other_new_option",
                        "default": "value"
                    }
                }
            }
        }
    }


Full mapping
------------

In the full mapping, al the options of the new configuration version should be
declared.  If an option is omitted, it means the option is removed.

The format of the fields in the full mapping file are:

* ``version``: Should be in the ``MAJOR.MINOR`` format. The version should match
  the directory name
* ``type``: Should be set as ``full``. If omitted, the mapping will be treated
  as as full mapping
* ``components``: Should be set as a dictionary which maps each component to a
  dictionary of options. See the option dictionary format below in
  :ref:`Full mapping components format` section.
* ``subcomponents``: Should be set as a dictionary mapping subcomponents to its
  main component. This is necessary to create a relationship between the
  sections of the files that are not components (e.g. The ``[revocations]``
  section in the ``verifier.conf`` file should be declared in the
  ``subcomponents`` dictionary as ``"revocations": "verifier"``). See the format
  below in :ref:`Subcomponents format`

Full mapping components format
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

For each component, the options transformations should be declared through
dictionaries that map the **new option** name to the **option it is replacing**.

The upgrade script will search the options to be replaced in the old
configuration, in the section provided in the ``section`` field.  If the option
is found, the value is preserved in the news configuration, otherwise the value
provided in the ``default`` field is used instead.

As an example, follows an excerpt of the ``templates/2.0/mapping.json`` file:

.. code-block:: json

    "components": {
        "agent": {
            "version": {
                "section": "agent",
                "option": "version",
                "default": "2.0"
            },
            "revocation_notification_ip": {
                "section": "general",
                "option": "receive_revocation_ip",
                "default": "127.0.0.1"
            },
    }

In the excerpt above, in the ``agent`` component two options are declared,
``version`` and ``revocation_notification_ip``.

The new option ``revocation_notification_ip`` will receive the value from the
``receive_revocation_ip`` from the ``general`` section in the old configuration
file.  If the option is not found, the value ``127.0.0.1`` provided in the
``default`` field is used instead.

Subcomponents format
^^^^^^^^^^^^^^^^^^^^

The configuration file for some of the components (e.g. the ``verifier.conf``)
have more than one section.  The main section is named after the component (e.g.
``[verifier]`` section of the ``verifier.conf`` file).  The other sections are
considered subsections, or subcomponents,  by the configuration upgrade script.
The subsections are associated with their main section in the ``Subcomponents``
dictionary, which maps a subsection to the associated main section.

For example, the following excerpt from the ``templates/2.0/mapping.json``
file:

.. code-block:: json

    "subcomponents": {
        "revocations": "verifier",
        "loggers": "logging",
        "handlers": "logging",
        "formatters": "logging",
        "formatter_formatter": "logging",
        "logger_root": "logging",
        "handler_consoleHandler": "logging",
        "logger_keylime": "logging"
    }

In the excerpt, the ``[revocations]`` section is declared as a subsection (or
subcomponent) of the ``[verifier]`` section.

Adjust script requirements
--------------------------

The optional ``adjust.py`` script can perform complex operations that cannot be
expressed using the ``mapping.json`` file.  For example, deciding the value of
an option depending on the presence of another option in the configuration file.

The ``adjust.py`` script is processed after the ``mapping.json`` is applied.
For this reason, when writing the ``adjust.py`` script, the author should
consider the input to be the output of the processing of the associated
``mapping.json`` file.

The only requirement for the ``adjust.py`` script is to implement the
``adjust()`` function, defined as the following:

.. code-block:: python

  def adjust(
      config: RawConfigParser, mapping: Dict, logger: Logger = logging.getLogger(__name__)
  ) -> None:

The ``config`` parameter is the result after applying the transformations
defined by the ``mapping.json`` file.

The ``mapping`` parameter is the dictionary read from the ``mapping.json`` JSON file.

The optional ``logger`` parameter will receive the logger from the
``keylime_upgrade_config`` script, so that all the log messages are in a single
place. It is recommended to keep the default assigned as
``logging.getLogger(__name__)`` so that the ``keylime_upgrade_config`` can set
the log level accordingly.

The ``adjust()`` function should make the changes to the parser received through
the ``config`` parameter directly.
