.. This work is licensed under a Creative Commons Attribution 4.0 International License.
.. http://creativecommons.org/licenses/by/4.0
.. (c) Manuel Buil (SuSe Linux) and others

Abstract
========

This document compiles the release notes for the Gambia release of
OPNFV SFC

Important notes
===============

These notes provide release information for the use of SFC with the
Apex installer, xci tool and Compass4NFV for the Gambia release of OPNFV.

Summary
=======

The goal of the SFC release is to integrate the OpenDaylight SFC project
into an OPNFV environment, with either the Apex installer, xci tool or
Compass4NFV.

More information about OpenDaylight and SFC can be found here.

- `OpenDaylight <http://www.opendaylight.org>`_ version "Fluorine SR1"

- `Service function chaining <https://wiki.opnfv.org/display/sfc/Service+Function+Chaining+Home>`_


- Documentation built by Jenkins

  - Overall OPNFV documentation

  - :ref:`Design document <sfc-design>`
  - :ref:`User Guide <sfc-userguide>`
  - :ref:`Installation Instructions <sfc-configguide>`

  - Release Notes (this document)


Release Data
============

+--------------------------------------+--------------------------------------+
| **Project**                          | sfc                                  |
|                                      |                                      |
+--------------------------------------+--------------------------------------+
| **Repo/tag**                         | opnfv-7.2.0                          |
|                                      |                                      |
+--------------------------------------+--------------------------------------+
| **Release designation**              | Gambia 7.2                           |
|                                      |                                      |
+--------------------------------------+--------------------------------------+
| **Release date**                     | January 25th, 2019                   |
|                                      |                                      |
+--------------------------------------+--------------------------------------+
| **Purpose of the delivery**          | Move to OpenStack Rocky, ODL FLuorine|
|                                      | and OVS 2.9.2 (NSH native support)   |
|                                      | Move to odl_v2 driver in n-sfc       |
+--------------------------------------+--------------------------------------+

Version change
--------------

Module version changes
~~~~~~~~~~~~~~~~~~~~~~
This release of OPNFV sfc is based on following upstream versions:

- OpenStack Rocky release

- OpenDaylight Fluorine SR1 release

- Open vSwitch 2.9.2

Document changes
~~~~~~~~~~~~~~~~
This is the first tracked version of OPNFV SFC Gambia. It comes with
the following documentation:

- :ref:`Design document <sfc-design>`
- :ref:`User Guide <sfc-userguide:>`
- :ref:`Installation Instructions <sfc-configguide:>`

- Release notes (This document)

Reason for version
------------------

Feature additions
~~~~~~~~~~~~~~~~~

- `Use odl_v2 driver for n-sfc`
- `Unit test creation`
- `Code refactored`
- `Tests can be run without tacker and with n-sfc directly`

Bug corrections
~~~~~~~~~~~~~~~

Deliverables
------------

Software deliverables
~~~~~~~~~~~~~~~~~~~~~

No specific deliverables are created, as SFC is included with Apex and Compass4NFV.

Documentation deliverables
~~~~~~~~~~~~~~~~~~~~~~~~~~

- :ref:`Design document <sfc-design>`
- :ref:`User Guide <sfc-userguide:>`
- :ref:`Installation Instructions <sfc-configguide:>`
- Release notes (This document)

Known Limitations, Issues and Workarounds
=========================================

System Limitations
------------------

The Gambia 2.0 release has a few limitations:

1 - The testcase sfc_two_chains_SSH_and_HTTP is disabled in this release due to
a missing feature in ODL. We are unable to currently update a chain config

Known issues
------------

1 - When tacker is deployed without Mistral, there is an ERROR in the logs and
the VIM is always in 'PENDING' state because tacker cannot monitor its health.
However, everything works and SFs can be created.

2 - When tacker is deployed without barbican, it cannot be in HA mode because
barbican is the only way to fetch the fernet keys.

Workarounds
-----------

Test results
============
The Gambia release of SFC has undergone QA test runs with Functest tests on the
Apex and Compass installers and xci utility

References
==========
For more information on the OPNFV Gambia release, please see:

OPNFV
-----

1) `OPNFV Home Page <https://www.opnfv.org>`_

2) `OPNFV documentation- and software downloads <https://www.opnfv.org/software/download>`_

3) `OPNFV Gambia release <https://docs.opnfv.org/en/stable-gambia/index.html>`_

OpenStack
---------

4) `OpenStack Rocky Release artifacts <http://www.openstack.org/software/rocky>`_

5) `OpenStack documentation <http://docs.openstack.org>`_

OpenDaylight
------------

6) `OpenDaylight artifacts <http://www.opendaylight.org/software/downloads>`_
