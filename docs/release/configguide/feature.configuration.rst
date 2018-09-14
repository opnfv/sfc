.. This work is licensed under a Creative Commons Attribution 4.0 International License.
.. SPDX-License-Identifier: CC-BY-4.0
.. (c) Ferenc Cserepkei, Brady Allen Johnson, Manuel Buil and others

Abstract
========
This document provides information on how to install the OpenDaylight SFC
features in OPNFV with the use of os_odl-sfc-(no)ha scenario.

SFC feature desciription
========================
For details of the scenarios and their provided capabilities refer to
the scenario description documents:

- :ref:`<os-odl-sfc-ha>`
- :ref:`<os-odl-sfc-noha>`

The SFC feature enables creation of Service Fuction Chains - an ordered list
of chained network funcions (e.g. firewalls, NAT, QoS)

The SFC feature in OPNFV is implemented by 3 major components:

- OpenDaylight SDN controller

- Tacker: Generic VNF Manager (VNFM) and a NFV Orchestrator (NFVO)

- OpenvSwitch: The Service Function Forwarder(s)

Hardware requirements
=====================

The SFC scenarios can be deployed on a bare-metal OPNFV cluster or on a
virtual environment on a single host.

Bare metal deployment on (OPNFV) Pharos lab
-------------------------------------------
Hardware requirements for bare-metal deployments of the OPNFV infrastructure
are given by the Pharos project. The Pharos project provides an OPNFV
hardware specification for configuring your hardware:
http://artifacts.opnfv.org/pharos/docs/pharos-spec.html


Virtual deployment
------------------
SFC scenarios can be deployed using APEX installer and xci utility. Check the
requirements from those in order to be able to deploy the OPNFV-SFC:

Apex: https://wiki.opnfv.org/display/apex/Apex
XCI: https://wiki.opnfv.org/display/INF/XCI+Developer+Sandbox
