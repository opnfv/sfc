import logging
import os
import time
import json
import yaml
import functest.utils.openstack_utils as os_utils
from tackerclient.tacker import client as tackerclient
from functest.utils.constants import CONST

from snaps.openstack.tests import openstack_tests
from snaps.openstack.create_image import OpenStackImage
from snaps.config.image import ImageConfig

from snaps.config.flavor import FlavorConfig
from snaps.openstack.create_flavor import OpenStackFlavor

from snaps.config.network import NetworkConfig, SubnetConfig, PortConfig
from snaps.openstack.create_network import OpenStackNetwork

from snaps.config.router import RouterConfig
from snaps.openstack.create_router import OpenStackRouter

from snaps.config.security_group import (
    Protocol, SecurityGroupRuleConfig, Direction, SecurityGroupConfig)

from snaps.openstack.create_security_group import OpenStackSecurityGroup

from snaps.openstack.create_instance import OpenStackVmInstance

from snaps.config.vm_inst import VmInstanceConfig, FloatingIpConfig

logger = logging.getLogger(__name__)
DEFAULT_TACKER_API_VERSION = '1.0'


class OpenStackSFC:

    def __init__(self):
        creds_override = None
        self.os_creds = openstack_tests.get_credentials(
            os_env_file=CONST.__getattribute__('openstack_creds'),
            overrides=creds_override)
        self.creators = []

    def register_glance_image(self, name, img_format, url, public):
        image_settings = ImageConfig(name=name, img_format=img_format, url=url,
                                     public=public)
        image = OpenStackImage(self.os_creds, image_settings)
        image_id = image.create()
        if image_id is None:
            logger.error("Failed to create the image")
            raise Exception("Failed to create the image")

        self.creators.append(image)
        return image_id

    def create_flavor(self, name, ram, disk, vcpus):
        flavor_settings = FlavorConfig(name=name, ram=ram, disk=disk,
                                       vcpus=vcpus)
        flavor = OpenStackFlavor(self.os_creds, flavor_settings)
        flavor_id = flavor.create()
        if flavor is None or flavor_id is None:
            logger.error("Failed to create custom flavor")
            raise Exception("Failed to create custom flavor")

        self.creators.append(flavor)
        return flavor_id

    def create_network_infrastructure(self, net_name, subnet_name, subnet_cidr,
                                      router_name):
        # Network and subnet
        subnet_settings = SubnetConfig(name=subnet_name, cidr=subnet_cidr)
        network_settings = NetworkConfig(name=net_name,
                                         subnet_settings=subnet_settings)
        network = OpenStackNetwork(self.os_creds, network_settings)
        network_id = network.create()

        if network_id is None:
            logger.error("Failed to create the network")
            raise Exception("Failed to create the network")

        self.creators.append(network)

        # Router
        ext_network_name = CONST.__getattribute__('EXTERNAL_NETWORK')

        router_settings = RouterConfig(name=router_name,
                                       external_gateway=ext_network_name,
                                       internal_subnets=subnet_name)

        router = OpenStackRouter(self.os_creds, router_settings)
        router_id = router.create()

        if router_id is None:
            logger.error("Failed to create the router")
            raise Exception("Failed to create the router")

        self.creators.append(router)

        return network_id, router_id

    def create_security_group(self, sec_grp_name):
        rule_ping = SecurityGroupRuleConfig(sec_grp_name=sec_grp_name,
                                            direction=Direction.ingress,
                                            protocol=Protocol.icmp)

        rule_ssh = SecurityGroupRuleConfig(sec_grp_name=sec_grp_name,
                                           direction=Direction.ingress,
                                           protocol=Protocol.tcp,
                                           port_range_min=22,
                                           port_range_max=22)

        rule_http = SecurityGroupRuleConfig(sec_grp_name=sec_grp_name,
                                            direction=Direction.ingress,
                                            protocol=Protocol.tcp,
                                            port_range_min=80,
                                            port_range_max=80)

        rules = [rule_ping, rule_ssh, rule_http]

        secgroup_settings = SecurityGroupConfig(name=sec_grp_name,
                                                rule_settings=rules)

        sec_grp = OpenStackSecurityGroup(self.os_creds, secgroup_settings)
        sec_group_id = sec_grp.create()
        if sec_group_id is None:
            logger.error("Failed to create the security group")
            raise Exception("Failed to create the router")

        self.creators.append(sec_grp)

        return sec_group_id

    def create_instance(self, vm_name, flavor_name, image_name, network_name,
                        secgrp_name, av_zone):

        port_settings = PortConfig(name=vm_name + '-port',
                                   network_name=network_name)

        instance_settings = VmInstanceConfig(name=vm_name, flavor=flavor_name,
                                             security_group_names=secgrp_name,
                                             port_settings=[port_settings],
                                             availability_zone=av_zone)

        instance = OpenStackVmInstance(self.os_creds, instance_settings,
                                       image_name)

        instance_id = instance.create()

        if instance_id is None:
            logger.error("Failed to create the instance")
            raise Exception("Failed to create the instance")

        self.creators.append(instance)
        return instance_id

    def get_av_zones(self):
        '''
        Return the availability zone each host belongs to
        '''
        nova_client = os_utils.get_nova_client()
        hosts = os_utils.get_hypervisors(nova_client)
        return ['nova::{0}'.format(host) for host in hosts]

    def get_compute_client(self):
        '''
        Return the compute where the client sits
        '''
        nova_client = os_utils.get_nova_client()
        hosts = os_utils.get_hypervisors(nova_client)
        for compute in hosts:
            vms = nova_client.servers.list(search_opts={'host': compute})
            for vm in vms:
                if "client" in vm.name:
                    return compute
        return False

    def assign_floating_ips(self, router_name):
        '''
        Assign a floating ips to all the VMs
        '''
        fips = []
        for creator in self.creators:
            if (type(creator) == "OpenStackVmInstance"):
                name = creator.instance_settings.name + "-float"
                port_name = creator.instance_settings.port_settings
                float_ip = FloatingIpConfig(name=name,
                                            port_name=port_name,
                                            router_name=router_name)
                ip = creator.add_floating_ip(float_ip)
                fips.append(ip)

        return fips

    def get_neutron_interfaces(self, vm):
        '''
        Get the interfaces of an instance
        '''
        nova_client = os_utils.get_nova_client()
        interfaces = nova_client.servers.interface_list(vm.id)
        return interfaces

    def get_client_port_id(self, vm):
        '''
        Get the neutron port id of the client
        '''
        interfaces = self.get_neutron_interfaces(vm)
        if len(interfaces) > 1:
            raise Exception("Client has more than one interface."
                            "Not expected!")
        return interfaces[0].id

# TACKER SECTION #


def get_tacker_client_version():
    api_version = os.getenv('OS_TACKER_API_VERSION')
    if api_version is not None:
        logger.info("OS_TACKER_API_VERSION is set in env as '%s'", api_version)
        return api_version
    return DEFAULT_TACKER_API_VERSION


def get_tacker_client(other_creds={}):
    sess = os_utils.get_session(other_creds)
    return tackerclient.Client(get_tacker_client_version(), session=sess)


def get_id_from_name(tacker_client, resource_type, resource_name):
    try:
        req_params = {'fields': 'id', 'name': resource_name}
        endpoint = '/{0}s'.format(resource_type)
        resp = tacker_client.get(endpoint, params=req_params)
        endpoint = endpoint.replace('-', '_')
        return resp[endpoint[1:]][0]['id']
    except Exception, e:
        logger.error("Error [get_id_from_name(tacker_client, "
                     "resource_type, resource_name)]: %s" % e)
        return None


def get_vnfd_id(tacker_client, vnfd_name):
    return get_id_from_name(tacker_client, 'vnfd', vnfd_name)


def get_vim_id(tacker_client, vim_name):
    return get_id_from_name(tacker_client, 'vim', vim_name)


def get_vnf_id(tacker_client, vnf_name, timeout=5):
    vnf_id = None
    while vnf_id is None and timeout >= 0:
        vnf_id = get_id_from_name(tacker_client, 'vnf', vnf_name)
        if vnf_id is None:
            logger.info("Could not retrieve ID for vnf with name [%s]."
                        " Retrying." % vnf_name)
            time.sleep(1)
            timeout -= 1
    return vnf_id


def get_vnffg_id(tacker_client, vnffg_name, timeout=5):
    vnffg_id = None
    while vnffg_id is None and timeout >= 0:
        vnffg_id = get_id_from_name(tacker_client, 'vnffg', vnffg_name)
        if vnffg_id is None:
            logger.info("Could not retrieve ID for vnffg with name [%s]."
                        " Retrying." % vnffg_name)
            time.sleep(1)
            timeout -= 1
    return vnffg_id


def get_vnffgd_id(tacker_client, vnffgd_name):
    return get_id_from_name(tacker_client, 'vnffgd', vnffgd_name)


def list_vnfds(tacker_client, verbose=False):
    try:
        vnfds = tacker_client.list_vnfds(retrieve_all=True)
        if not verbose:
            vnfds = [vnfd['id'] for vnfd in vnfds['vnfds']]
        return vnfds
    except Exception, e:
        logger.error("Error [list_vnfds(tacker_client)]: %s" % e)
        return None


def create_vnfd(tacker_client, tosca_file=None, vnfd_name=None):
    try:
        vnfd_body = {}
        if tosca_file is not None:
            with open(tosca_file) as tosca_fd:
                vnfd_body = tosca_fd.read()
            logger.info('VNFD template:\n{0}'.format(vnfd_body))
        return tacker_client.create_vnfd(
            body={"vnfd": {"attributes": {"vnfd": vnfd_body},
                  "name": vnfd_name}})
    except Exception, e:
        logger.error("Error [create_vnfd(tacker_client, '%s')]: %s"
                     % (tosca_file, e))
        return None


def delete_vnfd(tacker_client, vnfd_id=None, vnfd_name=None):
    try:
        vnfd = vnfd_id
        if vnfd is None:
            if vnfd_name is None:
                raise Exception('You need to provide VNFD id or VNFD name')
            vnfd = get_vnfd_id(tacker_client, vnfd_name)
        return tacker_client.delete_vnfd(vnfd)
    except Exception, e:
        logger.error("Error [delete_vnfd(tacker_client, '%s', '%s')]: %s"
                     % (vnfd_id, vnfd_name, e))
        return None


def list_vnfs(tacker_client, verbose=False):
    try:
        vnfs = tacker_client.list_vnfs(retrieve_all=True)
        if not verbose:
            vnfs = [vnf['id'] for vnf in vnfs['vnfs']]
        return vnfs
    except Exception, e:
        logger.error("Error [list_vnfs(tacker_client)]: %s" % e)
        return None


def create_vnf(tacker_client, vnf_name, vnfd_id=None,
               vnfd_name=None, vim_id=None, vim_name=None, param_file=None):
    try:
        vnf_body = {
            'vnf': {
                'attributes': {},
                'name': vnf_name
            }
        }
        if param_file is not None:
            params = None
            with open(param_file) as f:
                params = f.read()
            vnf_body['vnf']['attributes']['param_values'] = params

        if vnfd_id is not None:
            vnf_body['vnf']['vnfd_id'] = vnfd_id
        else:
            if vnfd_name is None:
                raise Exception('vnfd id or vnfd name is required')
            vnf_body['vnf']['vnfd_id'] = get_vnfd_id(tacker_client, vnfd_name)

        if vim_id is not None:
            vnf_body['vnf']['vim_id'] = vim_id
        else:
            if vim_name is None:
                raise Exception('vim id or vim name is required')
            vnf_body['vnf']['vim_id'] = get_vim_id(tacker_client, vim_name)
        return tacker_client.create_vnf(body=vnf_body)

    except Exception, e:
        logger.error("error [create_vnf(tacker_client,"
                     " '%s', '%s', '%s')]: %s"
                     % (vnf_name, vnfd_id, vnfd_name, e))
        return None


def get_vnf(tacker_client, vnf_id=None, vnf_name=None):
    try:
        if vnf_id is None and vnf_name is None:
            raise Exception('You must specify vnf_id or vnf_name')

        _id = get_vnf_id(tacker_client, vnf_name) if vnf_id is None else vnf_id

        if _id is not None:
            all_vnfs = list_vnfs(tacker_client, verbose=True)['vnfs']
            return next((vnf for vnf in all_vnfs if vnf['id'] == _id), None)
        else:
            raise Exception('Could not retrieve ID from name [%s]' % vnf_name)

    except Exception, e:
        logger.error("Could not retrieve VNF [vnf_id=%s, vnf_name=%s] - %s"
                     % (vnf_id, vnf_name, e))
        return None


def wait_for_vnf(tacker_client, vnf_id=None, vnf_name=None, timeout=100):
    try:
        vnf = get_vnf(tacker_client, vnf_id, vnf_name)
        if vnf is None:
            raise Exception("Could not retrieve VNF - id='%s', name='%s'"
                            % vnf_id, vnf_name)
        logger.info('Waiting for vnf {0}'.format(str(vnf)))
        while vnf['status'] != 'ACTIVE' and timeout >= 0:
            if vnf['status'] == 'ERROR':
                raise Exception('Error when booting vnf %s' % vnf['id'])
            elif vnf['status'] == 'PENDING_CREATE':
                time.sleep(3)
                timeout -= 3
            vnf = get_vnf(tacker_client, vnf_id, vnf_name)

        if (timeout < 0):
            raise Exception('Timeout when booting vnf %s' % vnf['id'])

        return vnf['id']
    except Exception, e:
        logger.error("error [wait_for_vnf(tacker_client, '%s', '%s')]: %s"
                     % (vnf_id, vnf_name, e))
        return None


def delete_vnf(tacker_client, vnf_id=None, vnf_name=None):
    try:
        vnf = vnf_id
        if vnf is None:
            if vnf_name is None:
                raise Exception('You need to provide a VNF id or name')
            vnf = get_vnf_id(tacker_client, vnf_name)
        return tacker_client.delete_vnf(vnf)
    except Exception, e:
        logger.error("Error [delete_vnf(tacker_client, '%s', '%s')]: %s"
                     % (vnf_id, vnf_name, e))
        return None


def create_vim(tacker_client, vim_file=None):
    try:
        vim_body = {}
        if vim_file is not None:
            with open(vim_file) as vim_fd:
                vim_body = json.load(vim_fd)
            logger.info('VIM template:\n{0}'.format(vim_body))
        return tacker_client.create_vim(body=vim_body)
    except Exception, e:
        logger.error("Error [create_vim(tacker_client, '%s')]: %s"
                     % (vim_file, e))
        return None


def create_vnffgd(tacker_client, tosca_file=None, vnffgd_name=None):
    try:
        vnffgd_body = {}
        if tosca_file is not None:
            with open(tosca_file) as tosca_fd:
                vnffgd_body = yaml.safe_load(tosca_fd)
            logger.info('VNFFGD template:\n{0}'.format(vnffgd_body))
        return tacker_client.create_vnffgd(
            body={'vnffgd': {'name': vnffgd_name,
                  'template': {'vnffgd': vnffgd_body}}})
    except Exception, e:
        logger.error("Error [create_vnffgd(tacker_client, '%s')]: %s"
                     % (tosca_file, e))
        return None


def create_vnffg(tacker_client, vnffg_name=None, vnffgd_id=None,
                 vnffgd_name=None, param_file=None):
    '''
      Creates the vnffg which will provide the RSP and the classifier
    '''
    try:
        vnffg_body = {
            'vnffg': {
                'attributes': {},
                'name': vnffg_name
            }
        }
        if param_file is not None:
            params = None
            with open(param_file) as f:
                params = f.read()
            params_dict = yaml.safe_load(params)
            vnffg_body['vnffg']['attributes']['param_values'] = params_dict
        if vnffgd_id is not None:
            vnffg_body['vnffg']['vnffgd_id'] = vnffgd_id
        else:
            if vnffgd_name is None:
                raise Exception('vnffgd id or vnffgd name is required')
            vnffg_body['vnffg']['vnffgd_id'] = get_vnffgd_id(tacker_client,
                                                             vnffgd_name)
        return tacker_client.create_vnffg(body=vnffg_body)
    except Exception, e:
        logger.error("error [create_vnffg(tacker_client,"
                     " '%s', '%s', '%s')]: %s"
                     % (vnffg_name, vnffgd_id, vnffgd_name, e))
        return None


def list_vnffgds(tacker_client, verbose=False):
    try:
        vnffgds = tacker_client.list_vnffgds(retrieve_all=True)
        if not verbose:
            vnffgds = [vnffgd['id'] for vnffgd in vnffgds['vnffgds']]
        return vnffgds
    except Exception, e:
        logger.error("Error [list_vnffgds(tacker_client)]: %s" % e)
        return None


def list_vnffgs(tacker_client, verbose=False):
    try:
        vnffgs = tacker_client.list_vnffgs(retrieve_all=True)
        if not verbose:
            vnffgs = [vnffg['id'] for vnffg in vnffgs['vnffgs']]
        return vnffgs
    except Exception, e:
        logger.error("Error [list_vnffgs(tacker_client)]: %s" % e)
        return None


def delete_vnffg(tacker_client, vnffg_id=None, vnffg_name=None):
    try:
        vnffg = vnffg_id
        if vnffg is None:
            if vnffg_name is None:
                raise Exception('You need to provide a VNFFG id or name')
            vnffg = get_vnffg_id(tacker_client, vnffg_name)
        return tacker_client.delete_vnffg(vnffg)
    except Exception, e:
        logger.error("Error [delete_vnffg(tacker_client, '%s', '%s')]: %s"
                     % (vnffg_id, vnffg_name, e))
        return None


def delete_vnffgd(tacker_client, vnffgd_id=None, vnffgd_name=None):
    try:
        vnffgd = vnffgd_id
        if vnffgd is None:
            if vnffgd_name is None:
                raise Exception('You need to provide VNFFGD id or VNFFGD name')
            vnffgd = get_vnffgd_id(tacker_client, vnffgd_name)
        return tacker_client.delete_vnffgd(vnffgd)
    except Exception, e:
        logger.error("Error [delete_vnffgd(tacker_client, '%s', '%s')]: %s"
                     % (vnffgd_id, vnffgd_name, e))
        return None


def list_vims(tacker_client, verbose=False):
    try:
        vims = tacker_client.list_vims(retrieve_all=True)
        if not verbose:
            vims = [vim['id'] for vim in vims['vims']]
        return vims
    except Exception, e:
        logger.error("Error [list_vims(tacker_client)]: %s" % e)
        return None


def delete_vim(tacker_client, vim_id=None, vim_name=None):
    try:
        vim = vim_id
        if vim is None:
            if vim_name is None:
                raise Exception('You need to provide VIM id or VIM name')
            vim = get_vim_id(tacker_client, vim_name)
        return tacker_client.delete_vim(vim)
    except Exception, e:
        logger.error("Error [delete_vim(tacker_client, '%s', '%s')]: %s"
                     % (vim_id, vim_name, e))
        return None


def get_tacker_items():
    tacker_client = get_tacker_client()
    logger.debug("VIMs: %s" % list_vims(tacker_client))
    logger.debug("VNFDs: %s" % list_vnfds(tacker_client))
    logger.debug("VNFs: %s" % list_vnfs(tacker_client))
    logger.debug("VNFFGDs: %s" % list_vnffgds(tacker_client))
    logger.debug("VNFFGs: %s" % list_vnffgs(tacker_client))


def register_vim(tacker_client, vim_file=None):
    tmp_file = '/tmp/register-vim.json'
    if vim_file is not None:
        with open(vim_file) as f:
            json_dict = json.load(f)

        json_dict['vim']['auth_url'] = CONST.__getattribute__('OS_AUTH_URL')
        json_dict['vim']['auth_cred']['password'] = CONST.__getattribute__(
                                                        'OS_PASSWORD')

        json.dump(json_dict, open(tmp_file, 'w'))

    create_vim(tacker_client, vim_file=tmp_file)


def create_vnf_in_av_zone(
                          tacker_client,
                          vnf_name,
                          vnfd_name,
                          vim_name,
                          default_param_file,
                          av_zone=None):
    param_file = default_param_file

    if av_zone is not None or av_zone != 'nova':
        param_file = os.path.join(
            '/tmp',
            'param_{0}.json'.format(av_zone.replace('::', '_')))
        data = {
               'zone': av_zone
               }
        with open(param_file, 'w+') as f:
            json.dump(data, f)
    create_vnf(tacker_client,
               vnf_name,
               vnfd_name=vnfd_name,
               vim_name=vim_name,
               param_file=param_file)


def create_vnffg_with_param_file(tacker_client, vnffgd_name, vnffg_name,
                                 default_param_file, neutron_port):
    param_file = default_param_file

    if neutron_port is not None:
        param_file = os.path.join(
            '/tmp',
            'param_{0}.json'.format(neutron_port))
        data = {
               'net_src_port_id': neutron_port
               }
        with open(param_file, 'w+') as f:
            json.dump(data, f)
    create_vnffg(tacker_client,
                 vnffgd_name=vnffgd_name,
                 vnffg_name=vnffg_name,
                 param_file=param_file)
