import sys

import functest.utils.functest_logger as ft_logger
import functest.utils.openstack_utils as os_utils
import functest.utils.openstack_tacker as os_tacker
import sfc.lib.utils as utils


logger = ft_logger.Logger(__name__).getLogger()


def delete_odl_resources(odl_ip, odl_port, resource):
    rsrc_list = utils.get_odl_resource_list(odl_ip, odl_port, resource)
    elem_names = utils.odl_resource_list_names(resource, rsrc_list)
    for elem in elem_names:
        logger.info("Removing ODL resource: {0}/{1}".format(resource, elem))
        utils.delete_odl_resource_elem(odl_ip, odl_port, resource, elem)


def delete_vnfds():
    t = os_tacker.get_tacker_client()
    vnfds = os_tacker.list_vnfds(t)
    if vnfds is None:
        return
    for vnfd in vnfds:
        logger.info("Removing vnfd: {0}".format(vnfd))
        os_tacker.delete_vnfd(t, vnfd_id=vnfd)


def delete_vnfs():
    t = os_tacker.get_tacker_client()
    vnfs = os_tacker.list_vnfs(t)
    if vnfs is None:
        return
    for vnf in vnfs:
        logger.info("Removing vnf: {0}".format(vnf))
        os_tacker.delete_vnf(t, vnf_id=vnf)


def delete_sfcs():
    t = os_tacker.get_tacker_client()
    sfcs = os_tacker.list_sfcs(t)
    if sfcs is None:
        return
    for sfc in sfcs:
        logger.info("Removing sfc: {0}".format(sfc))
        os_tacker.delete_sfc(t, sfc_id=sfc)


def delete_sfc_clfs():
    t = os_tacker.get_tacker_client()
    sfc_clfs = os_tacker.list_sfc_classifiers(t)
    if sfc_clfs is None:
        return
    for sfc_clf in sfc_clfs:
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


def cleanup_odl(odl_ip, odl_port):
    delete_odl_resources(odl_ip, odl_port, 'service-function-forwarder')
    delete_odl_resources(odl_ip, odl_port, 'service-function-chain')
    delete_odl_resources(odl_ip, odl_port, 'service-function-path')
    delete_odl_resources(odl_ip, odl_port, 'service-function')


def cleanup(odl_ip=None, odl_port=None):
    delete_sfc_clfs()
    delete_sfcs()
    delete_vnfs()
    delete_stacks()
    delete_floating_ips()
    delete_instances()
    if odl_ip is not None and odl_port is not None:
        cleanup_odl(odl_ip, odl_port)


if __name__ == '__main__':
    if sys.argv > 2:
        cleanup(sys.argv[1], sys.argv[2])
    else:
        cleanup()
