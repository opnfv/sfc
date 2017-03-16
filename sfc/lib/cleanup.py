import functest.utils.openstack_utils as os_utils
import functest.utils.openstack_tacker as os_tacker
import utils


def delete_vnfds():
    t = os_tacker.get_tacker_client()
    for vnfd in os_tacker.list_vnfds(t):
        os_tacker.delete_vnfd(t, vnfd_id=vnfd)


def delete_vnfs():
    t = os_tacker.get_tacker_client()
    for vnfd in os_tacker.list_vnfs(t):
        os_tacker.delete_vnfd(t, vnf_id=vnfd)


def delete_sfcs():
    t = os_tacker.get_tacker_client()
    for sfc in os_tacker.list_sfcs(t):
        os_tacker.delete_vnfd(t, sfc_id=sfc)


def delete_sfc_clfs():
    t = os_tacker.get_tacker_client()
    for sfc_clf in os_tacker.list_sfc_classifiers(t):
        os_tacker.delete_sfc_classifier(t, sfc_clf_id=sfc_clf)


def delete_floating_ips():
    n = os_utils.get_nova_client()
    for fip in os_utils.get_floating_ips(n):
        os_utils.delete_floating_ip(n, fip.id)


def delete_stacks():
    utils.run_cmd('openstack stack delete sfc --y')
    utils.run_cmd('openstack stack delete sfc_test1 --y')
    utils.run_cmd('openstack stack delete sfc_test2 --y')


def delete_instances():
    n = os_utils.get_nova_client()
    for inst in os_utils.get_instances(n):
        os_utils.delete_instance(n, inst.id)


def cleanup():
    delete_sfc_clfs()
    delete_sfcs()
    delete_vnfs()
    delete_stacks()
    delete_instances()
    delete_floating_ips()


if __name__ == '__main__':
    cleanup()
