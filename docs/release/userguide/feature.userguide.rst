.. This work is licensed under a Creative Commons Attribution 4.0 International License.
.. http://creativecommons.org/licenses/by/4.0
.. (c) <optionally add copywriters name>

SFC description
=====================
.. Describe the specific features and how it is realised in the scenario in a brief manner
.. to ensure the user understand the context for the user guide instructions to follow.

The OPNFV SFC feature will create service chains, classifiers, and create VMs for Service
Functions, allowing for client traffic intended to be sent to a server to first traverse
the provisioned service chain.

The Service Chain creation consists of configuring the OpenDaylight SFC feature. This
configuration will in-turn configure Service Function Forwarders to route traffic to
Service Functions. A Service Function Forwarder in the context of OPNFV SFC is the
"br-int" OVS bridge on an Open Stack compute node.

The classifier(s) consist of configuring the OpenDaylight Netvirt feature. Netvirt is
a Neutron backend which handles the networking for VMs. Netvirt can also create simple
classification rules (5-tuples) to send specific traffic to a pre-configured Service
Chain. A common example of a classification rule would be to send all HTTP traffic
(tcp port 80) to a pre-configured Service Chain.

Service Function VM creation is performed via a VNF Manager. Currently, OPNFV SFC
is integrated with OpenStack Tacker, which in addition to being a VNF Manager, also
orchestrates the SFC configuration.  In OPNFV SFC Tacker creates service chains,
classification rules, creates VMs in OpenStack for Service Functions, and then
communicates the relevant configuration to OpenDaylight SFC.

SFC capabilities and usage
================================
.. Describe the specific capabilities and usage for <XYZ> feature.
.. Provide enough information that a user will be able to operate the feature on a deployed scenario.

The OPNFV SFC feature can be deployed with either the "os-odl-sfc-ha" or the
"os-odl-sfc-noha" scenario. SFC usage for both of these scenarios is the same.

Once the deployment has been completed, the SFC test cases use information
(e.g. INSTALLER IP, Controller IP, etc) of the environment which have been
retrieved first from the installer in order to execute the SFC test cases properly.
This is the default behavior.
In case there is not an installer in place and the server for the SFC test execution
has been prepared manually, installing all necessary components (e.g. OpenStack OpenDayLight etc)
by hand. The user should update the "pod.yaml" file, including the all necessary details
for each node which participates in the scenario.
In case the dovetail project triggers the SFC test scenarios, the "pod.yaml" file will be prepared
by dovetail project automatically.

As previously mentioned, Tacker is used as a VNF Manager and SFC Orchestrator. All
the configuration necessary to create working service chains and classifiers can
be performed using the Tacker command line. Refer to the `Tacker walkthrough <https://github.com/trozet/sfc-random/blob/master/tacker_sfc_apex_walkthrough.txt>`_
(step 3 and onwards) for more information.

SFC API usage guidelines and example
-----------------------------------------------
.. Describe with examples how to use specific features, provide API examples and details required to
.. operate the feature on the platform.

Refer to the `Tacker walkthrough <https://github.com/trozet/sfc-random/blob/master/tacker_sfc_apex_walkthrough.txt>`_
for Tacker usage guidelines and examples.
