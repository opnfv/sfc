.. This work is licensed under a Creative Commons Attribution 4.0 International License.
.. http://creativecommons.org/licenses/by/4.0
.. (c) <optionally add copywriters name>

Introduction
============
.. In this section explain the purpose of the scenario and the types of capabilities provided

The os-odl-sfc_fdio-ha is intended to be used to install the OPNFV SFC project in a standard
OPNFV High Availability mode. The OPNFV SFC project integrates the OpenDaylight SFC project
into the OPNFV environment. The OPNFV SFC Euphrates release uses the OpenDaylight Nitrogen SR1 release.

Scenario components and composition
===================================
.. In this section describe the unique components that make up the scenario,
.. what each component provides and why it has been included in order
.. to communicate to the user the capabilities available in this scenario.

This scenario installs everything needed to use the SFC OpenDaylight project in an OPNFV
environment. The classifier used in this scenario is implemented by the Netvirt OpenDaylight
project.

Following is a detailed list of what is included with this scenario:

OpenDaylight features installed
-------------------------------

The OpenDaylight SDN controller is installed in the controller node.

The following are the SFC features that get installed:

- odl-sfc-model
- odl-sfc-provider
- odl-sfc-provider-rest
- odl-sfc-ovs
- odl-sfc-openflow-renderer

The following are the Netvirt features that get installed:

- odl-netvirt-openstack
- odl-sfc-genius
- odl-neutron-service
- odl-neutron-northbound-api
- odl-neutron-spi
- odl-neutron-transcriber
- odl-ovsdb-southbound-impl-api
- odl-ovsdb-southbound-impl-impl
- odl-ovsdb-library

By simply installing the odl-netvirt-sfc feature, all the dependant features
will automatically be installed.

The VNF Manager
---------------

In order to create a VM for each Service Function, a VNF Manager is needed. The OPNFV
SFC project currently uses the Tacker OpenStack project as a VNF Manager. Tacker is
installed on the controller node and manages VNF life cycle, and coordinates VM creation
and SFC configuration with OpenStack and OpenDaylight SFC project.

Scenario usage overview
=======================
.. Provide a brief overview on how to use the scenario and the features available to the
.. user.  This should be an "introduction" to the userguide document, and explicitly link to it,
.. where the specifics of the features are covered including examples and API's

Once this scenario is installed, it will be possible to create Service Chains and
classification entries to map tenant traffic to individual, pre-defined Service Chains.
All configuration can be performed using the Tacker CLI.

Limitations, Issues and Workarounds
===================================
.. Explain scenario limitations here, this should be at a design level rather than discussing
.. faults or bugs.  If the system design only provide some expected functionality then provide
.. some insight at this point.

The *client* virtual machine needs to be located in a compute node where at least
one of the service functions (SFs) is placed. This is due to a limitation in OpenDaylight,
Nitrogen, which only installs the traffic classifier in the compute nodes where the SFs are.

Specific version of FD.IO
-----------------------

TO BE ADDED

References
==========

For more information about SFC, please visit:

https://wiki.opnfv.org/display/sfc/Service+Function+Chaining+Home

https://wiki.opendaylight.org/view/Service_Function_Chaining:Main

For more information on the OPNFV Euphrates release, please visit:

http://www.opnfv.org/euphrates
