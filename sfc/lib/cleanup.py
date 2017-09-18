import sys
import time
import logging
import functest.utils.openstack_utils as os_utils
import sfc.lib.openstack_tacker as os_tacker
import sfc.lib.utils as utils


logger = logging.getLogger(__name__)


def delete_odl_resources(odl_ip, odl_port, resource):
    rsrc_list = utils.get_odl_resource_list(odl_ip, odl_port, resource)
    elem_names = utils.odl_resource_list_names(resource, rsrc_list)
    for elem in elem_names:
        logger.info("Removing ODL resource: {0}/{1}".format(resource, elem))
        utils.delete_odl_resource_elem(odl_ip, odl_port, resource, elem)


def delete_odl_ietf_access_lists(odl_ip, odl_port):
    acl_list = utils.get_odl_acl_list(odl_ip, odl_port)
    acl_types_names = utils.odl_acl_types_names(acl_list)
    for acl_type, acl_name in acl_types_names:
        utils.delete_odl_acl(odl_ip, odl_port, acl_type, acl_name)


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


def delete_vnffgs():
    t = os_tacker.get_tacker_client()
    vnffgs = os_tacker.list_vnffgs(t)
    if vnffgs is None:
        return
    for vnffg in reversed(vnffgs):
        logger.info("Removing vnffg: {0}".format(vnffg))
        os_tacker.delete_vnffg(t, vnffg_id=vnffg)


def delete_vnffgds():
    t = os_tacker.get_tacker_client()
    vnffgds = os_tacker.list_vnffgds(t)
    if vnffgds is None:
        return
    for vnffgd in vnffgds:
        logger.info("Removing vnffgd: {0}".format(vnffgd))
        os_tacker.delete_vnffgd(t, vnffgd_id=vnffgd)


def delete_vims():
    t = os_tacker.get_tacker_client()
    vims = os_tacker.list_vims(t)
    if vims is None:
        return
    for vim in vims:
        logger.info("Removing vim: {0}".format(vim))
        os_tacker.delete_vim(t, vim_id=vim)


def delete_floating_ips():
    n = os_utils.get_nova_client()
    fips = os_utils.get_floating_ips(n)
    if fips is None:
        return
    for fip in fips:
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
    instances = os_utils.get_instances(n)
    if instances is None:
        return
    for inst in instances:
        logger.info("Removing instance: {0}".format(inst.id))
        os_utils.delete_instance(n, inst.id)


def cleanup_odl(odl_ip, odl_port):
    delete_odl_resources(odl_ip, odl_port, 'service-function-forwarder')
    delete_odl_resources(odl_ip, odl_port, 'service-function-chain')
    delete_odl_resources(odl_ip, odl_port, 'service-function-path')
    delete_odl_resources(odl_ip, odl_port, 'service-function')
    delete_odl_ietf_access_lists(odl_ip, odl_port)


def cleanup(odl_ip=None, odl_port=None):
    delete_vnffgs()
    delete_vnffgds()
    delete_vnfs()
    time.sleep(20)
    delete_vnfds()
    delete_vims()
    delete_stacks()
    delete_floating_ips()
    delete_instances()
    if odl_ip is not None and odl_port is not None:
        cleanup_odl(odl_ip, odl_port)


if __name__ == '__main__':
    if len(sys.argv) > 2:
        cleanup(sys.argv[1], sys.argv[2])
    else:
        cleanup()
