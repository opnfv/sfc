import sys
import time
import logging
import sfc.lib.openstack_utils as os_sfc_utils
import sfc.lib.odl_utils as odl_utils


logger = logging.getLogger(__name__)


def delete_odl_resources(odl_ip, odl_port, resource):
    rsrc_list = odl_utils.get_odl_resource_list(odl_ip, odl_port, resource)
    elem_names = odl_utils.odl_resource_list_names(resource, rsrc_list)
    for elem in elem_names:
        logger.info("Removing ODL resource: {0}/{1}".format(resource, elem))
        odl_utils.delete_odl_resource_elem(odl_ip, odl_port, resource, elem)


def delete_odl_ietf_access_lists(odl_ip, odl_port):
    acl_list = odl_utils.get_odl_acl_list(odl_ip, odl_port)
    acl_types_names = odl_utils.odl_acl_types_names(acl_list)
    for acl_type, acl_name in acl_types_names:
        odl_utils.delete_odl_acl(odl_ip, odl_port, acl_type, acl_name)


def delete_vnfds():
    t = os_sfc_utils.get_tacker_client()
    vnfds = os_sfc_utils.list_vnfds(t)
    if vnfds is None:
        return
    for vnfd in vnfds:
        logger.info("Removing vnfd: {0}".format(vnfd))
        os_sfc_utils.delete_vnfd(t, vnfd_id=vnfd)


def delete_vnfs():
    t = os_sfc_utils.get_tacker_client()
    vnfs = os_sfc_utils.list_vnfs(t)
    if vnfs is None:
        return
    for vnf in vnfs:
        logger.info("Removing vnf: {0}".format(vnf))
        os_sfc_utils.delete_vnf(t, vnf_id=vnf)


def delete_vnffgs():
    t = os_sfc_utils.get_tacker_client()
    vnffgs = os_sfc_utils.list_vnffgs(t)
    if vnffgs is None:
        return
    for vnffg in reversed(vnffgs):
        logger.info("Removing vnffg: {0}".format(vnffg))
        os_sfc_utils.delete_vnffg(t, vnffg_id=vnffg)


def delete_vnffgds():
    t = os_sfc_utils.get_tacker_client()
    vnffgds = os_sfc_utils.list_vnffgds(t)
    if vnffgds is None:
        return
    for vnffgd in vnffgds:
        logger.info("Removing vnffgd: {0}".format(vnffgd))
        os_sfc_utils.delete_vnffgd(t, vnffgd_id=vnffgd)


def delete_vims():
    t = os_sfc_utils.get_tacker_client()
    vims = os_sfc_utils.list_vims(t)
    if vims is None:
        return
    for vim in vims:
        logger.info("Removing vim: {0}".format(vim))
        os_sfc_utils.delete_vim(t, vim_id=vim)


# Creators is a list full of SNAPs objects
def delete_openstack_objects(creators):
    for creator in reversed(creators):
        try:
            creator.clean()
        except Exception as e:
            logger.error('Unexpected error cleaning - %s', e)


def cleanup_odl(odl_ip, odl_port):
    delete_odl_resources(odl_ip, odl_port, 'service-function-forwarder')
    delete_odl_resources(odl_ip, odl_port, 'service-function-chain')
    delete_odl_resources(odl_ip, odl_port, 'service-function-path')
    delete_odl_resources(odl_ip, odl_port, 'service-function')
    delete_odl_ietf_access_lists(odl_ip, odl_port)


def cleanup(creators, odl_ip=None, odl_port=None):
    delete_vnffgs()
    delete_vnffgds()
    delete_vnfs()
    time.sleep(20)
    delete_vnfds()
    delete_vims()
    delete_openstack_objects(creators)
    if odl_ip is not None and odl_port is not None:
        cleanup_odl(odl_ip, odl_port)


def cleanup_from_bash(odl_ip=None, odl_port=None):
    delete_vnffgs()
    delete_vnffgds()
    delete_vnfs()
    time.sleep(20)
    delete_vnfds()
    delete_vims()
    if odl_ip is not None and odl_port is not None:
        cleanup_odl(odl_ip, odl_port)


if __name__ == '__main__':
    if len(sys.argv) > 2:
        cleanup_from_bash(sys.argv[1], sys.argv[2])
