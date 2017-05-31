.. This work is licensed under a Creative Commons Attribution 4.0 International License.
.. http://creativecommons.org/licenses/by/4.0

Use Cases
---------

This section outlines the Danube use cases driving the initial OPNFV
SFC implementation.

Use Case 1 - Two chains
***********************

This use case is  targeted on creating
simple Service Chains using Firewall Service Functions. As can be seen in the
following diagram, 2 service chains are created, each through a different
Service Function Firewall. Service Chain 1 will block HTTP, while Service
Chain 2 will block SSH.

.. image:: ./images/OPNFV_SFC_Brahmaputra_UseCase.jpg

Use Case 2 - One chain traverses two service functions
******************************************************

This use case creates two service functions, and a chain that makes the traffic
flow through both of them. More information is available in the OPNFV-SFC wiki:

https://wiki.opnfv.org/display/sfc/Functest+SFC-ODL+-+Test+2
