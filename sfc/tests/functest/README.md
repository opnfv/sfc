# TESTS: FUNCTEST: OPNFV SFC

> supports two MANO components:

- [OSM](https://osm.etsi.org/)

  Read [OSM guide](https://wiki.opnfv.org/display/sfc/OSM+guide)
  to understand how the client, the server and VNFs are created.

- [Tacker](https://docs.openstack.org/tacker/latest/)

  Read [Tacker guide](https://wiki.opnfv.org/display/sfc/Tacker+guide)
  to understand how the client, the server and VNFs are created.

> When MANO component is not selected(`no_mano`), then networking-sfc is used
> to create the chain and classification rules.

## These are the currently available test cases:

### `TEST ONE CHAIN - sfc_one_chain_two_service_functions`

> One client, one server and two SFs are created.
> A chain is created where both SFs are included.
>
> vxlan_tool is started in both SFs and HTTP traffic is sent from the client to
> the server. If it works, the vxlan_tool is modified to block HTTP traffic.
> It is tried again and it should fail because packets are dropped. Then, that
> SF stops blocking and the other SF starts blocking HTTP and the connection is
> tried again.


### `TEST TWO CHAINS - sfc_two_chains_SSH_and_HTTP`

> One client, one server and two SFs are created.
> Two chains are created, having one SF each.
>
> vxlan_tool is started in both SFs, one SF blocks SSH traffic and the other SF
> block HTTP traffic. First, the client traffic is classified to chain1, where
> HTTP should work but SSH sould not. This is tested and after that the
> classification is changed to classified to chain2, where HTTP should not work
> but SSH should work. This is tested again.


### `TEST SYMMETRIC - sfc_symmetric_chain`

> One client and one server are created. The server will be running
> a web server on port 80.
>
> Then one Service Function (SF) is created. This service function will be
> running a firewall that blocks the traffic in a specific port (e.g. 22222).
> A symmetric service chain routing the traffic throught this SF will be
> created as well.
>
> 1st check: The client is able to reach the server and the response gets back
> to the client. Here the firewall is running without blocking any port.
>
> 2nd check: The client is not able to reach the server as the firewall
> is configured to block traffic on port 80, and the request from the client
> is blocked, as the symmetric service chain makes them go through
> the firewall.
>
> If the client is able to reach the server, it would be a symptom of the
> symmetric chain not working, as traffic would be flowing from client to
> server directly without traversing the SF.
>
> 3rd check: The client is able to reach the server, as the firewall
> is configured to block traffic on port 22222, and the response from the
> server is blocked.
>
> If the server is able to reach the client, it would be a symptom of the
> symmetric chain not working, as traffic would be flowing from server to
>  client directly without traversing the SF.
>
> 4th check: The client is able to reach the server and the response gets back
> to the client. Like in 1st check to verify test ends with same config
> as at the beginning.


### `TEST DELETION - sfc_chain_deletion`

> One client, one server and a SF are created.
> A service chain which routes the traffic through this SF will be created as well.
> After that the chain is deleted and re-created.
>
> vxlan_tool is started in the SF and HTTP traffic is sent from the client to the server.
> If it works, the vxlan_tool is modified to block HTTP traffic.
> It is tried again and it should fail because packets are dropped.
