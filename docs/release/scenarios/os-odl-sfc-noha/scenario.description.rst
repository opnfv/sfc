.. This work is licensed under a Creative Commons Attribution 4.0 International License.
.. http://creativecommons.org/licenses/by/4.0
.. (c) <optionally add copywriters name>

Introduction
============
.. In this section explain the purpose of the scenario and the types of capabilities provided

The os-odl-sfc-noha is intended to be used to install the OPNFV SFC project in a standard
OPNFV Non-High Availability mode. The OPNFV SFC project integrates the OpenDaylight SFC
project into the OPNFV environment. The OPNFV SFC Euphrates release uses the OpenDaylight
Nitrogen SR1 release.

Scenario components and composition
===================================
.. In this section describe the unique components that make up the scenario,
.. what each component provides and why it has been included in order
.. to communicate to the user the capabilities available in this scenario.

This scenario installs everything needed to use the SFC OpenDaylight project in an OPNFV
environment. Since this scenario is Non-High Availability, then only one controller and
one compute node will be deployed. The classifier used in this scenario is implemented
by the Netvirt OpenDaylight project.

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
with the OpenDaylight SFC project.

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

Specific version of OVS
-----------------------

SFC needs changes in OVS to include the Network Service Headers (NSH) Service Chaining
encapsulation. This OVS patch has been ongoing for quite a while (2 years+), and still
has not been officially merged. Previously, SFC used NSH from a branched version of OVS
based on 2.3.90, called the "Pritesh Patch". In the OpenDaylight Nitrogen SR1 release, SFC was
changed to use a newer, branched version of OVS based on 2.6.1, called the "Yi Yang
Patch".

The older version of OVS only supported VXLAN-GPE + NSH encapsulation, but the newer
version supports both ETH + NSH and VXLAN-GPE + ETH + NSH. Currently SFC is only
implemented with VXLAN-GPE + ETH + NSH.

Workaround for VXLAN and OpenStack
----------------------------------

When using NSH with VXLAN tunnels, its important that the VXLAN tunnel is terminated
in the SF VM. This allows the SF to see the NSH header, allowing it to decrement the
NSI and also to use the NSH metadata. When using VXLAN with OpenStack, the tunnels
are not terminated in the SF VM, but in the “br-int” OVS bridge. A work-around has
been created to address this issue, which can be found here:

http://artifacts.opnfv.org/sfc/danube/docs/design/architecture.html#ovs-nsh-patch-workaround

In subsequent versions of SFC, we will change the SFF-SF transport to be ETH + NSH,
which will obviate this work around.

References
==========

For more information about SFC, please visit:

https://wiki.opnfv.org/display/sfc/Service+Function+Chaining+Home

https://wiki.opendaylight.org/view/Service_Function_Chaining:Main

For more information on the OPNFV Euphrates release, please visit:

http://www.opnfv.org/euphrates

