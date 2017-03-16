import functest.utils.functest_logger as ft_logger
import functest.utils.openstack_utils as os_utils
import functest.utils.openstack_tacker as os_tacker
import utils


logger = ft_logger.Logger(__name__).getLogger()


def delete_vnfds():
    t = os_tacker.get_tacker_client()
    for vnfd in os_tacker.list_vnfds(t):
        logger.info("Removing vnfd: {0}".format(vnfd))
        os_tacker.delete_vnfd(t, vnfd_id=vnfd)


def delete_vnfs():
    t = os_tacker.get_tacker_client()
    for vnf in os_tacker.list_vnfs(t):
        logger.info("Removing vnf: {0}".format(vnf))
        os_tacker.delete_vnf(t, vnf_id=vnf)


def delete_sfcs():
    t = os_tacker.get_tacker_client()
    for sfc in os_tacker.list_sfcs(t):
        logger.info("Removing sfc: {0}".format(sfc))
        os_tacker.delete_sfc(t, sfc_id=sfc)


def delete_sfc_clfs():
    t = os_tacker.get_tacker_client()
    for sfc_clf in os_tacker.list_sfc_classifiers(t):
        logger.info("Removing sfc classifier: {0}".format(sfc_clf))
        os_tacker.delete_sfc_classifier(t, sfc_clf_id=sfc_clf)


def delete_floating_ips():
    n = os_utils.get_nova_client()
    for fip in os_utils.get_floating_ips(n):
        logger.info("Removing floating ip: {0}".format(fip.ip))
        os_utils.delete_floating_ip(n, fip.id)


def delete_stacks():
    logger.info("Removing stack: sfc")
    utils.run_cmd('openstack stack delete sfc --y')
    logger.info("Removing stack: sfc_test1")
    utils.run_cmd('openstack stack delete sfc_test1 --y')
    logger.info("Removing stack: sfc_test2")
    utils.run_cmd('openstack stack delete sfc_test2 --y')


def delete_instances():
    n = os_utils.get_nova_client()
    for inst in os_utils.get_instances(n):
        logger.info("Removing instance: {0}".format(inst.id))
        os_utils.delete_instance(n, inst.id)


def cleanup():
    delete_sfc_clfs()
    delete_sfcs()
    delete_vnfs()
    delete_stacks()
    delete_floating_ips()
    delete_instances()


if __name__ == '__main__':
    cleanup()
