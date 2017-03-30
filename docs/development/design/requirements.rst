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

These are the Danube specific requirements:

1 The supported Service Chaining encapsulation will be NSH VXLAN-GPE.

2 The version of OVS used must support NSH.

3 The SF VM life cycle will be managed by the Tacker VNF Manager.

4 The supported classifier is OpenDaylight NetVirt.

5 ODL will be the OpenStack Neutron backend and will handle all networking
  on the compute nodes.

Long Term Requirements
++++++++++++++++++++++

These requirements are out of the scope of the Danube release.

1 Dynamic movement of SFs across multiple Compute nodes.

2 Load Balancing across multiple SFs

