# Remember to source the env variables $creds before
tacker sfc-classifier-delete red_http
tacker sfc-classifier-delete red_http_reverse
tacker sfc-delete red
tacker vnf-delete testVNF1
tacker vnfd-delete test-vnfd1
nova delete client
nova delete server
for line in $(neutron floatingip-list | cut -d" " -f2);do neutron floatingip-delete $line;done
