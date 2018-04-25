.. This work is licensed under a Creative Commons Attribution 4.0 International License.
.. http://creativecommons.org/licenses/by/4.0

Requirements
------------

This section defines requirements for the initial OPNFV SFC implementation,
including those requirements driving upstream project enhancements.

Minimal Viable Requirement
++++++++++++++++++++++++++

Deploy a complete SFC solution by integrating OpenDaylight SFC with OpenStack
in an OPNFV environment.

Detailed Requirements
+++++++++++++++++++++

These are the Fraser specific requirements:

1 The supported Service Chaining encapsulation will be NSH VXLAN-GPE.

2 The version of OVS used must support NSH.

3 The SF VM life cycle will be managed by the Tacker VNF Manager.

4 The supported classifier is OpenDaylight NetVirt.

5 ODL will be the OpenStack Neutron backend and will handle all networking
  on the compute nodes.

6 Tacker will use the networking-sfc API to configure ODL

7 ODL will use flow based tunnels to create the VXLAN-GPE tunnels

Long Term Requirements
++++++++++++++++++++++

These requirements are out of the scope of the Fraser release.

1 Dynamic movement of SFs across multiple Compute nodes.

2 Load Balancing across multiple SFs

3 Support of a different MANO component apart from Tacker
