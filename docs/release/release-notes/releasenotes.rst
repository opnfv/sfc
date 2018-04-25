.. This work is licensed under a Creative Commons Attribution 4.0 International License.
.. http://creativecommons.org/licenses/by/4.0
.. (c) Manuel Buil (SuSe Linux) and others

Abstract
========

This document compiles the release notes for the Fraser release of
OPNFV SFC

Important notes
===============

These notes provide release information for the use of SFC with the
Apex installer, xci tool and Compass4NFV for the Fraser release of OPNFV.

Summary
=======

The goal of the SFC Fraser release is to integrate the OpenDaylight
SFC project into an OPNFV environment, with either the Apex installer,
xci tools or Compass4NFV.

More information about OpenDaylight and SFC can be found here.

- `OpenDaylight <http://www.opendaylight.org/software>`_ version "Oxygen SR1"

- `Service function chaining <https://wiki.opnfv.org/display/sfc/Service+Function+Chaining+Home>`_


- Documentation built by Jenkins

  - Overall OPNFV documentation

  - `Design document <http://docs.opnfv.org/en/stable-fraser/submodules/sfc/docs/development/design/index.html>`_

  - `User Guide <http://docs.opnfv.org/en/stable-fraser/submodules/sfc/docs/release/userguide/index.html>`_

  - `Installation Instructions <http://docs.opnfv.org/en/stable-fraser/submodules/sfc/docs/release/configguide/index.html>`_

  - Release Notes (this document)


Release Data
============

+--------------------------------------+--------------------------------------+
| **Project**                          | sfc                                  |
|                                      |                                      |
+--------------------------------------+--------------------------------------+
| **Repo/tag**                         | opnfv-6.0.0                          |
|                                      |                                      |
+--------------------------------------+--------------------------------------+
| **Release designation**              | Fraser base release                  |
|                                      |                                      |
+--------------------------------------+--------------------------------------+
| **Release date**                     |  27th April 2018                     |
|                                      |                                      |
+--------------------------------------+--------------------------------------+
| **Purpose of the delivery**          | Move to OpenStack Pike and ODL Oxygen|
|                                      | Support symmetric testcases          |
|                                      | Support master branch of OpenStack   |
+--------------------------------------+--------------------------------------+

Version change
--------------

Module version changes
~~~~~~~~~~~~~~~~~~~~~~
This release of OPNFV sfc is based on following upstream versions:

- OpenStack Pike release

- OpenDaylight Oxygen SR1 release

- Open vSwitch 2.6.1 with Yi Yang NSH patch

Document changes
~~~~~~~~~~~~~~~~
This is the first tracked version of OPNFV SFC Fraser. It comes with
the following documentation:

- `Design document <http://docs.opnfv.org/en/stable-fraser/submodules/sfc/docs/development/design/index.html>`_

- `User Guide <http://docs.opnfv.org/en/stable-fraser/submodules/sfc/docs/release/userguide/index.html>`_

- `Installation Instructions <http://docs.opnfv.org/en/stable-fraser/submodules/sfc/docs/release/configguide/index.html>`_

- Release notes (This document)

Reason for version
------------------

Feature additions
~~~~~~~~~~~~~~~~~

- `Using SNAPS as base for our tests`
- `Increase test coverage with two extra test cases: symmetric and deletion`
- `Reduced the footprint of the image we use for testing to reduce testing time`

Bug corrections
~~~~~~~~~~~~~~~

Deliverables
------------

Software deliverables
~~~~~~~~~~~~~~~~~~~~~

No specific deliverables are created, as SFC is included with Apex and Compass4NFV.

Documentation deliverables
~~~~~~~~~~~~~~~~~~~~~~~~~~

- `Design document <http://docs.opnfv.org/en/stable-fraser/submodules/sfc/docs/development/design/index.html>`_

- `User Guide <http://docs.opnfv.org/en/stable-fraser/submodules/sfc/docs/release/userguide/index.html>`_

- `Installation Instructions <http://docs.opnfv.org/en/stable-fraser/submodules/sfc/docs/release/configguide/index.html>`_

- Release notes (This document)

Known Limitations, Issues and Workarounds
=========================================

System Limitations
------------------

The Fraser 1.0 release has a few limitations:

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
The Fraser release of SFC has undergone QA test runs with Functest tests on the
Apex and Compass installers and xci utility

References
==========
For more information on the OPNFV Fraser release, please see:

OPNFV
-----

1) `OPNFV Home Page <https://www.opnfv.org>`_

2) `OPNFV documentation- and software downloads <https://www.opnfv.org/software/download>`_

3) `OPNFV Fraser release <http://wiki.opnfv.org/releases/fraser>`_

OpenStack
---------

4) `OpenStack Pike Release artifacts <http://www.openstack.org/software/pike>`_

5) `OpenStack documentation <http://docs.openstack.org>`_

OpenDaylight
------------

6) `OpenDaylight artifacts <http://www.opendaylight.org/software/downloads>`_

Open vSwitch with NSH
---------------------

7) https://github.com/yyang13/ovs_nsh_patches

