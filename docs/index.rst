=====================
Keylime Documentation
=====================

.. warning::
    This documentation is still under development and not complete. It will be
    so until this warning is removed.

Welcome to the Keylime Documentation site!

Keylime is a TPM-based highly scalable remote boot attestation and runtime
integrity measurement solution. Keylime enables cloud users to monitor remote
nodes using a hardware based cryptographic root of trust.

Keylime was originally born out of the security research team in MIT's Lincoln
Laboratory and is now developed and maintained by the Keylime community.

This Documentation site contains guides to install, use and administer keylime
as well as guides to enable developers to make contributions to keylime
or develop services against Keylime's Rest API(s).

We recommend newcomers to read the :doc:`design section <design>` to get an understanding
what the goals of Keylime are and how they are implemented.


.. toctree::
   :maxdepth: 2
   :caption: Contents:

   installation
   user_guide
   design
   publications
   rest_apis
   developers
   security

.. toctree::
   :maxdepth: 1
   :caption: Manpages:

   man/keylime_tenant.1
   man/keylime_verifier.8
   man/keylime_registrar.8
   man/keylime_agent.8
   man/keylime_policy.1

Indices and tables
==================

* :ref:`genindex`
* :ref:`search`
