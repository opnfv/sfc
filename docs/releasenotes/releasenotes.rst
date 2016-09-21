.. This work is licensed under a Creative Commons Attribution 4.0 International License.
.. http://creativecommons.org/licenses/by/4.0
.. (c) Brady Johnson (Ericsson Inc.) and others

Abstract
========

This document compiles the release notes for the Colorado release of
OPNFV SFC.

Important notes
===============

These notes provide release information for the use of SFC with the Fuel
and Apex installer tools for the Colorado release of OPNFV.

Summary
=======

The goal of the SFC Colorado release is to integrate the OpenDaylight
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
| **Repo/tag**                         | colorado.1.0                         |
|                                      |                                      |
+--------------------------------------+--------------------------------------+
| **Release designation**              | Colorado base release                |
|                                      |                                      |
+--------------------------------------+--------------------------------------+
| **Release date**                     | September 22 2016                    |
|                                      |                                      |
+--------------------------------------+--------------------------------------+
| **Purpose of the delivery**          | Improve functionality provided in    |
|                                      | Brahmaputra release. Increased test  |
|                                      | coverage with new Funtest cases.     |
|                                      | Make SFC/Tacker work on multiple     |
|                                      | compute nodes                        |
|                                      |                                      |
+--------------------------------------+--------------------------------------+

Version change
--------------

Module version changes
~~~~~~~~~~~~~~~~~~~~~~
This is the second tracked release of OPNFV sfc. It is based on
following upstream versions:

- OpenStack Mitaka release

- OpenDaylight Boron release

- Open vSwitch 2.5.90 with Yi Yang NSH patch

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

The release in Colorado 1.0 has several limitations:

1 - It only works in non-HA environments. Tacker is currently not
available in HA environments and so the calls to it fail.

2 - It only works in one-compute deployments. Tacker fixed the
multicompute support in the last weeks but we did not have
time to test it

3 - The first time a classification rule is created, it does not
work. This is a known issue in Netvirt-ODL. Create the classification
once again and it should work

4 - Any VM (e.g. SFs) must have only one security group.
There is a bug in ODL Boron which only one security group is read.
The rest are silently ignored.

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
The Colorado release of SFC has undergone QA test runs
with Functest tests on the Fuel and Apex installers.

References
==========
For more information on the OPNFV Colorado release, please see:

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

