.. This work is licensed under a Creative Commons Attribution 4.0 International License.
.. http://creativecommons.org/licenses/by/4.0
.. (c) Manuel Buil (SuSe Linux) and others

Abstract
========

This document compiles the release notes for the Euphrates release of
OPNFV SFC

Important notes
===============

These notes provide release information for the use of SFC with the
Apex installer and xci tools for the Euphrates release of OPNFV.

Summary
=======

The goal of the SFC Euphrates release is to integrate the OpenDaylight
SFC project into an OPNFV environment, with either the Apex installer or
xci tools. In subsequent releases, we expect Compass4NFV to integrate
the SFC scenarios too.

More information about OpenDaylight and SFC can be found here.

- `OpenDaylight <http://www.opendaylight.org/software>`_ version "Nitrogen SR1"

- `Service function chaining <https://wiki.opnfv.org/display/sfc/Service+Function+Chaining+Home>`_


- Documentation built by Jenkins

  - Overall OPNFV documentation

  - `Design document <http://docs.opnfv.org/en/stable-euphrates/submodules/sfc/docs/development/design/index.html>`_

  - `User Guide <http://docs.opnfv.org/en/stable-euphrates/submodules/sfc/docs/release/userguide/index.html>`_

  - `Installation Instructions <http://docs.opnfv.org/en/stable-euphrates/submodules/sfc/docs/release/configguide/index.html>`_

  - Release Notes (this document)


Release Data
============

+--------------------------------------+--------------------------------------+
| **Project**                          | sfc                                  |
|                                      |                                      |
+--------------------------------------+--------------------------------------+
| **Repo/tag**                         | euphrates 2.0                        |
|                                      |                                      |
+--------------------------------------+--------------------------------------+
| **Release designation**              | Euphrates base release               |
|                                      |                                      |
+--------------------------------------+--------------------------------------+
| **Release date**                     | 15th December 2017                   |
|                                      |                                      |
+--------------------------------------+--------------------------------------+
| **Purpose of the delivery**          | Integrate neutron networking-sfc     |
|                                      | and use the latest tacker code. Move |
|                                      | to OpenStack ocata and ODL Nitrogen  |
+--------------------------------------+--------------------------------------+

Version change
--------------

Module version changes
~~~~~~~~~~~~~~~~~~~~~~
This release of OPNFV sfc is based on following upstream versions:

- OpenStack Ocata release

- OpenDaylight Nitrogen SR1 release

- Open vSwitch 2.6.1 with Yi Yang NSH patch

Document changes
~~~~~~~~~~~~~~~~
This is the first tracked version of OPNFV SFC Euphrates. It comes with
the following documentation:

- `Design document <http://docs.opnfv.org/en/stable-euphrates/submodules/sfc/docs/development/design/index.html>`_

- `User Guide <http://docs.opnfv.org/en/stable-euphrates/submodules/sfc/docs/release/userguide/index.html>`_

- `Installation Instructions <http://docs.opnfv.org/en/stable-euphrates/submodules/sfc/docs/release/configguide/index.html>`_

- Release notes (This document)

Reason for version
------------------

Feature additions
~~~~~~~~~~~~~~~~~

- `Integration with neutron networking-sfc`
- `Moved to latest tacker code`
- `Started using forwarding graphs as a way to configure SFC`
- `Created compatibility with latest functest (based on Alpine containers)`

Bug corrections
~~~~~~~~~~~~~~~

**JIRA TICKETS:**

`Bug-fixes <https://jira.opnfv.org/browse/SFC-103>`_
`Bug-fixes <https://jira.opnfv.org/browse/SFC-104>`_
`Bug-fixes <https://jira.opnfv.org/browse/SFC-105>`_
`Bug-fixes <https://jira.opnfv.org/browse/SFC-106>`_
`Bug-fixes <https://jira.opnfv.org/browse/SFC-107>`_
`Bug-fixes <https://jira.opnfv.org/browse/SFC-108>`_
`Bug-fixes <https://jira.opnfv.org/browse/SFC-109>`_
`Bug-fixes <https://jira.opnfv.org/browse/SFC-110>`_
`Bug-fixes <https://jira.opnfv.org/browse/SFC-111>`_
`Bug-fixes <https://jira.opnfv.org/browse/SFC-112>`_
`Bug-fixes <https://jira.opnfv.org/browse/SFC-113>`_
`Bug-fixes <https://jira.opnfv.org/browse/SFC-114>`_
`Bug-fixes <https://jira.opnfv.org/browse/SFC-116>`_
`Bug-fixes <https://jira.opnfv.org/browse/SFC-117>`_

Apart from the OPNFV bug fixes, there were some bugs in ODL and Tacker which
were fixed as well.

Deliverables
------------

Software deliverables
~~~~~~~~~~~~~~~~~~~~~

No specific deliverables are created, as SFC is included with Apex.

Documentation deliverables
~~~~~~~~~~~~~~~~~~~~~~~~~~

- `Design document <http://docs.opnfv.org/en/stable-euphrates/submodules/sfc/docs/development/design/index.html>`_

- `User Guide <http://docs.opnfv.org/en/stable-euphrates/submodules/sfc/docs/release/userguide/index.html>`_

- `Installation Instructions <http://docs.opnfv.org/en/stable-euphrates/submodules/sfc/docs/release/configguide/index.html>`_

- Release notes (This document)

Known Limitations, Issues and Workarounds
=========================================

System Limitations
------------------

The Euphrates 2.0 release has a few limitations:

1 - The testcase sfc_two_chains_SSH_and_HTTP is disabled in this release due to
bugs in ODL, Tacker and networking-sfc:

https://bugs.opendaylight.org/show_bug.cgi?id=9221
https://bugs.launchpad.net/tacker/+bug/1719839
https://bugs.launchpad.net/tacker/+bug/1719876
https://bugs.launchpad.net/networking-sfc/+bug/1719835
https://bugs.launchpad.net/networking-sfc/+bug/1719883

2 - The topology CLIENT_SERVER_SAME_HOST does not work due to a bug in the
vxlan_tool. This tool is part of the ODL-SFC repo and provides support for
non-NSH-aware SFs:

https://bugs.opendaylight.org/show_bug.cgi?id=9219

3 - The topologies CLIENT_SERVER_DIFFERENT_HOST_SPLIT_VNF and
CLIENT_SERVER_SAME_HOST_SPLIT_VNF do not work because of a ODL bug:

https://bugs.opendaylight.org/show_bug.cgi?id=9220


Known issues
------------

1 - OpenDaylight SFC relies on a version of Open vSwitch (OVS) with
Network Service Headers (NSH). A version of OVS with NSH currently
exists, but it is in a branched version of OVS. Extensive upstream
work has been done to merge the NSH patches into mainstream OVS,
but the work is still not complete. More information about this
can be found in the OPNFV SFC design document (link provided above).

2 - Due to a bug in tacker:

https://bugs.launchpad.net/tacker/+bug/1719841

it is not possible to run the SFC scenarios in openstack environments
which require SSL connections to public endpoints and use self-signed
certificates

Workarounds
-----------

There is a way to avoid the known issue number 2  when using xci. Once
the deployment is successfully done, go to tacker server and modify
line 242 of the file:

/openstack/venvs/tacker-15.1.7/lib/python2.7/site-packages/keystoneauth1/session.py

So that instead of having:

self.verify = verify

It has:

self.verify = False

Forcing tacker to not check the certificates


Test results
============
The Euphrates release of SFC has undergone QA test runs
with Functest tests on the Apex installer and xci utility

References
==========
For more information on the OPNFV Euphrates release, please see:

OPNFV
-----

1) `OPNFV Home Page <https://www.opnfv.org>`_

2) `OPNFV documentation- and software downloads <https://www.opnfv.org/software/download>`_

3) `OPNFV Danube release <http://wiki.opnfv.org/releases/euphrates>`_

OpenStack
---------

4) `OpenStack Newton Release artifacts <http://www.openstack.org/software/ocata>`_

5) `OpenStack documentation <http://docs.openstack.org>`_

OpenDaylight
------------

6) `OpenDaylight artifacts <http://www.opendaylight.org/software/downloads>`_

Open vSwitch with NSH
---------------------

7) https://github.com/yyang13/ovs_nsh_patches

