===========================================================
OPNFV Release Note for the Brahmaputra release of OPNFV SFC
===========================================================

License
=======

This work is licensed under a Creative Commons Attribution 4.0 International
License. .. http://creativecommons.org/licenses/by/4.0 ..
(c) Brady Johnson (Ericsson Inc.) and others

Abstract
========

This document compiles the release notes for the Brahmaputra release of
OPNFV SFC.

Important notes
===============

These notes provide release information for the use of SFC with the Fuel
and Apex installer tools for the Brahmaputra release of OPNFV.

Summary
=======

The goal of the SFC Brahmaputra release is to integrate the OpenDaylight
SFC project into an OPNFV environment, with either the Fuel or Apex
installer. In subsequent releases, other OPNFV installers will be
considered.

More information about OpenDaylight and SFC can be found here.

- `OpenDaylight <http://www.opendaylight.org/software>`_ version "Berylium"

- `Service function chaining <https://wiki.opnfv.org/service_function_chaining>`_


- Documentation built by Jenkins

  - overall OPNFV documentation

  - Design document

  - this document (release notes)


Release Data
============

+--------------------------------------+--------------------------------------+
| **Project**                          | sfc                                  |
|                                      |                                      |
+--------------------------------------+--------------------------------------+
| **Repo/tag**                         | brahmaputra.1.0                      |
|                                      |                                      |
+--------------------------------------+--------------------------------------+
| **Release designation**              | Brahmaputra base release             |
|                                      |                                      |
+--------------------------------------+--------------------------------------+
| **Release date**                     | February 25 2016                     |
|                                      |                                      |
+--------------------------------------+--------------------------------------+
| **Purpose of the delivery**          | Brahmaputra base release             |
|                                      |                                      |
+--------------------------------------+--------------------------------------+

Version change
--------------

Module version changes
~~~~~~~~~~~~~~~~~~~~~~
This is the first tracked release of OPNFV sfc. It is based on
following upstream versions:

- OpenStack Liberty release

- OpenDaylight Beryllium release

- Open vSwitch

Document changes
~~~~~~~~~~~~~~~~
This is the first tracked version of OPNFV SFC. It comes with
the following documentation:

- Design document

- Release notes (This document)

Reason for version
------------------

Feature additions
~~~~~~~~~~~~~~~~~

**JIRA TICKETS:**

`New features <https://jira.opnfv.org/issues/?filter=11002>`_ 'https://jira.opnfv.org/issues/?filter=11002'

Bug corrections
~~~~~~~~~~~~~~~

**JIRA TICKETS:**

`Bug-fixes <https://jira.opnfv.org/browse/FUEL-99?filter=11001>`_ 'https://jira.opnfv.org/browse/FUEL-99?filter=11001'

Deliverables
------------

Software deliverables
~~~~~~~~~~~~~~~~~~~~~

No specific deliverables are created, as SFC is included with Apex and Fuel.

Documentation deliverables
~~~~~~~~~~~~~~~~~~~~~~~~~~

- Design document

- Release notes (This document)

Known Limitations, Issues and Workarounds
=========================================

OpenDaylight SFC relies on a version of Open vSwitch (OVS) with
Network Service Headers (NSH). A version of OVS with NSH currently
exists, but it is in a private branch. Extensive upstream work has
been done to merge the NSH patches into mainstream OVS, but the work
is still not complete. More information about this can be found in
the OPNFV SFC design document.

System Limitations
------------------

No limitations beyond those in Fuel and Apex have been identified.

Known issues
------------

**JIRA TICKETS:**

`Known issues <https://jira.opnfv.org/browse/SFC-27>`_ 'https://jira.opnfv.org/browse/SFC-27'

Workarounds
-----------



Test results
============
The Brahmaputra release of SFC has only undergone QA test runs with
the Fuel installer and basic Yardstick tests, nothing SFC specific.

References
==========
For more information on the OPNFV Brahmaputra release, please see:

OPNFV
-----

1) `OPNFV Home Page <www.opnfv.org>`_

2) `OPNFV documentation- and software downloads <https://www.opnfv.org/software/download>`_

3) `OPNFV Brahmaputra release <http://wiki.opnfv.org/releases/brahmaputra>`_

OpenStack
---------

4) `OpenStack Liberty Release artifacts <http://www.openstack.org/software/liberty>`_

5) `OpenStack documentation <http://docs.openstack.org>`_

OpenDaylight
------------

6) `OpenDaylight artifacts <http://www.opendaylight.org/software/downloads>`_


:Authors: Brady Johnson (brady.allen.johnson@ericsson.com)
:Version: 1.0.0

