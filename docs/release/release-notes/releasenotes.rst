.. This work is licensed under a Creative Commons Attribution 4.0 International License.
.. http://creativecommons.org/licenses/by/4.0
.. (c) Brady Johnson (Ericsson Inc.) and others

Abstract
========

This document compiles the release notes for the Danube release of
OPNFV SFC.

Important notes
===============

These notes provide release information for the use of SFC with the Fuel
and Apex installer tools for the Danube release of OPNFV.

Summary
=======

The goal of the SFC Danube release is to integrate the OpenDaylight
SFC project into an OPNFV environment, with either the Fuel or Apex
installer. In subsequent releases, other OPNFV installers will be
considered.

More information about OpenDaylight and SFC can be found here.

- `OpenDaylight <http://www.opendaylight.org/software>`_ version "Boron"

- `Service function chaining <https://wiki.opnfv.org/display/sfc/Service+Function+Chaining+Home>`_


- Documentation built by Jenkins

  - Overall OPNFV documentation

  - `Design document <http://artifacts.opnfv.org/sfc/colorado/docs/design/index.html>`_

  - `User Guide <http://artifacts.opnfv.org/sfc/colorado/docs/userguide/index.html>`_

  - `Installation Instructions <http://artifacts.opnfv.org/sfc/colorado/docs/installationprocedure/index.html>`_

  - Release Notes (this document)


Release Data
============

+--------------------------------------+--------------------------------------+
| **Project**                          | sfc                                  |
|                                      |                                      |
+--------------------------------------+--------------------------------------+
| **Repo/tag**                         | danube 1.0                           |
|                                      |                                      |
+--------------------------------------+--------------------------------------+
| **Release designation**              | Danube base release                  |
|                                      |                                      |
+--------------------------------------+--------------------------------------+
| **Release date**                     | March 27 2017                        |
|                                      |                                      |
+--------------------------------------+--------------------------------------+
| **Purpose of the delivery**          | Add two new test cases and improve   |
|                                      | the old test case by using the new   |
|                                      | functions coming in functest         |
+--------------------------------------+--------------------------------------+

Version change
--------------

Module version changes
~~~~~~~~~~~~~~~~~~~~~~
This is the first tracked release of OPNFV sfc. It is based on
following upstream versions:

- OpenStack Newton release

- OpenDaylight Boron SR2 release

- Open vSwitch 2.6 with Yi Yang NSH patch

Document changes
~~~~~~~~~~~~~~~~
This is the second tracked version of OPNFV SFC. It comes with
the following documentation:

- `Design document <http://artifacts.opnfv.org/sfc/colorado/docs/design/index.html>`_

- `User Guide <http://artifacts.opnfv.org/sfc/colorado/docs/userguide/index.html>`_

- `Installation Instructions <http://artifacts.opnfv.org/sfc/colorado/docs/installationprocedure/index.html>`_

- Release notes (This document)

Reason for version
------------------

Feature additions
~~~~~~~~~~~~~~~~~

**JIRA TICKETS:**

`JIRA EPIC with the new features in SFC Colorado <https://jira.opnfv.org/browse/SFC-33>`_

Bug corrections
~~~~~~~~~~~~~~~

**JIRA TICKETS:**

`Bug-fixes <https://jira.opnfv.org/browse/SFC-34>`_

Deliverables
------------

Software deliverables
~~~~~~~~~~~~~~~~~~~~~

No specific deliverables are created, as SFC is included with Apex and Fuel.

Documentation deliverables
~~~~~~~~~~~~~~~~~~~~~~~~~~

- `Design document <http://artifacts.opnfv.org/sfc/colorado/docs/design/index.html>`_

- `User Guide <http://artifacts.opnfv.org/sfc/colorado/docs/userguide/index.html>`_

- `Installation Instructions <http://artifacts.opnfv.org/sfc/colorado/docs/installationprocedure/index.html>`_

- Release notes (This document)

Known Limitations, Issues and Workarounds
=========================================

System Limitations
------------------

The Danube 1.0 release has several limitations:

1 - The symmetric test case only works when client, server and
SFs are running in the same compute host. This is due to a missing
functionality in Tacker

2 - The test cases don't work if client and server are in different
computes because netvirt classifier and netvirt security groups are
not compatible in Boron. The reason is that packets never reach table
41 or table 91 in the client compute (they are hijacked by SFC in table
11) and thus the sec. group functionality does not know about that
traffic. Consequently, there are no rules created to allow the traffic
in the opposite direction (tcp_port_src = tcp_port_dst) and when server
replies to the client, that traffic is dropped.

3 - The test cases don't work if the client and the server are
in one compute and the SFs are in other compute. The reason is that ODL
Boron only creates a classification rule in the computes with SFs.
Therefore, the traffic from the client goes to the server as it would
be done without SFC (SFC classifier is implemented only in the other
compute)

Known issues
------------

OpenDaylight SFC relies on a version of Open vSwitch (OVS) with
Network Service Headers (NSH). A version of OVS with NSH currently
exists, but it is in a branched version of OVS. Extensive upstream
work has been done to merge the NSH patches into mainstream OVS,
but the work is still not complete. More information about this
can be found in the OPNFV SFC design document (link provided above).

Workarounds
-----------

The way OpenStack handles VXLAN-GPE tunnels doesnt work well with
SFC, since OpenStack terminates the VXLAN tunnels in the br-int
bridge instead of the SF VM. Ideally, the tunnel should be terminated
in the VM so the SF has access to the NSH header carried in the tunnel.
A workaround was created to send the packets to the SF VM with the
VXLAN-GPE headers intact and can be found in the OPNFV SFC design
document (link provided above).

Test results
============
The Danube release of SFC has undergone QA test runs
with Functest tests on the Fuel and Apex installers.

References
==========
For more information on the OPNFV Danube release, please see:

OPNFV
-----

1) `OPNFV Home Page <https://www.opnfv.org>`_

2) `OPNFV documentation- and software downloads <https://www.opnfv.org/software/download>`_

3) `OPNFV Colorado release <http://wiki.opnfv.org/releases/colorado>`_

OpenStack
---------

4) `OpenStack Mitaka Release artifacts <http://www.openstack.org/software/mitaka>`_

5) `OpenStack documentation <http://docs.openstack.org>`_

OpenDaylight
------------

6) `OpenDaylight artifacts <http://www.opendaylight.org/software/downloads>`_

Open vSwitch with NSH
---------------------

7) https://github.com/yyang13/ovs_nsh_patches

