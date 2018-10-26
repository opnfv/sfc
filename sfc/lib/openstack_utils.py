import os
import time
import json
import logging
import yaml


from tackerclient.tacker import client as tackerclient
from functest.utils import constants
from functest.utils import env
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
import snaps.openstack.create_instance as cr_inst
from snaps.config.vm_inst import VmInstanceConfig, FloatingIpConfig
from snaps.openstack.utils import (
    nova_utils, neutron_utils, heat_utils, keystone_utils)

logger = logging.getLogger(__name__)
DEFAULT_TACKER_API_VERSION = '1.0'


class OpenStackSFC:

    def __init__(self):
        self.os_creds = openstack_tests.get_credentials(
            os_env_file=constants.ENV_FILE)
        self.creators = []
        self.nova = nova_utils.nova_client(self.os_creds)
        self.neutron = neutron_utils.neutron_client(self.os_creds)
        self.heat = heat_utils.heat_client(self.os_creds)
        self.keystone = keystone_utils.keystone_client(self.os_creds)

    def register_glance_image(self, name, url, img_format, public):
        logger.info("Registering the image...")
        # Check whether the image is local or not
        if 'http' in url:
            image_settings = ImageConfig(name=name,
                                         img_format=img_format,
                                         url=url,
                                         public=public,
                                         image_user='admin')
        else:
            image_settings = ImageConfig(name=name,
                                         img_format=img_format,
                                         image_file=url,
                                         public=public,
                                         image_user='admin')

        # TODO Remove this when tacker is part of SNAPS
        self.image_settings = image_settings

        image_creator = OpenStackImage(self.os_creds, image_settings)
        image_creator.create()

        self.creators.append(image_creator)
        return image_creator

    def create_flavor(self, name, ram, disk, vcpus):
        logger.info("Creating the flavor...")
        flavor_settings = FlavorConfig(name=name, ram=ram, disk=disk,
                                       vcpus=vcpus)
        flavor_creator = OpenStackFlavor(self.os_creds, flavor_settings)
        flavor = flavor_creator.create()

        self.creators.append(flavor_creator)
        return flavor

    def create_network_infrastructure(self, net_name, subnet_name, subnet_cidr,
                                      router_name):
        logger.info("Creating networks...")
        # Network and subnet
        subnet_settings = SubnetConfig(name=subnet_name, cidr=subnet_cidr)
        network_settings = NetworkConfig(name=net_name,
                                         subnet_settings=[subnet_settings])
        network_creator = OpenStackNetwork(self.os_creds, network_settings)
        network = network_creator.create()

        self.creators.append(network_creator)

        # Router
        logger.info("Creating the router...")
        ext_network_name = env.get('EXTERNAL_NETWORK')

        router_settings = RouterConfig(name=router_name,
                                       external_gateway=ext_network_name,
                                       internal_subnets=[subnet_name])

        router_creator = OpenStackRouter(self.os_creds, router_settings)
        router = router_creator.create()

        self.creators.append(router_creator)

        return network, router

    def create_security_group(self, sec_grp_name):
        logger.info("Creating the security groups...")
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

        sec_group_creator = OpenStackSecurityGroup(self.os_creds,
                                                   secgroup_settings)
        sec_group = sec_group_creator.create()

        self.creators.append(sec_group_creator)

        return sec_group

    def create_instance(self, vm_name, flavor_name, image_creator, network,
                        secgrp, av_zone, ports, port_security=True):
        logger.info("Creating the instance {}...".format(vm_name))
        port_settings = []
        for port in ports:
            port_settings.append(
                    PortConfig(name=port,
                               port_security_enabled=port_security,
                               network_name=network.name))
        if port_security:
            instance_settings = VmInstanceConfig(
                name=vm_name, flavor=flavor_name,
                security_group_names=str(secgrp.name),
                port_settings=port_settings,
                availability_zone=av_zone)
        else:
            instance_settings = VmInstanceConfig(
                name=vm_name, flavor=flavor_name,
                port_settings=port_settings,
                availability_zone=av_zone)

        instance_creator = cr_inst.OpenStackVmInstance(
            self.os_creds,
            instance_settings,
            image_creator.image_settings)

        instance = instance_creator.create(block=True)

        self.creators.append(instance_creator)
        return instance, instance_creator

    def get_av_zones(self):
        '''
        Return the availability zone each host belongs to
        '''
        hosts = nova_utils.get_hypervisor_hosts(self.nova)
        return ['nova::{0}'.format(host) for host in hosts]

    def get_compute_client(self):
        '''
        Return the compute where the client sits
        '''
        return self.get_vm_compute('client')

    def get_compute_server(self):
        '''
        Return the compute where the server sits
        '''
        return self.get_vm_compute('server')

    def get_vm_compute(self, vm_name):
        '''
        Return the compute where the vm sits
        '''
        for creator in self.creators:
            # We want to filter the vm creators
            if hasattr(creator, 'get_vm_inst'):
                # We want to fetch by vm_name
                if creator.get_vm_inst().name == vm_name:
                    return creator.get_vm_inst().compute_host

        raise Exception("There is no VM with name '{}'!!".format(vm_name))

    def assign_floating_ip(self, router, vm, vm_creator):
        '''
        Assign floating ips to all the VMs
        '''
        name = vm.name + "-float"
        port_name = vm.ports[0].name
        float_ip = FloatingIpConfig(name=name,
                                    port_name=port_name,
                                    router_name=router.name)
        ip = vm_creator.add_floating_ip(float_ip)

        return ip.ip

    # We need this function because tacker VMs cannot be created through SNAPs
    def assign_floating_ip_vnfs(self, router, ips=None):
        '''
        Assign floating ips to all the SFs. Optionally specify the
        subnet IPs that a floating IP should be assigned to, assuming that the
        SF is connected to a single subnet globally and per port.
        '''
        stacks = self.heat.stacks.list()
        fips = []
        project_name = 'admin'
        for stack in stacks:
            servers = heat_utils.get_stack_servers(self.heat,
                                                   self.nova,
                                                   self.neutron,
                                                   self.keystone,
                                                   stack,
                                                   project_name)
            sf_creator = cr_inst.generate_creator(self.os_creds,
                                                  servers[0],
                                                  self.image_settings,
                                                  project_name)

            name = servers[0].name + "-float"
            if ips is None:
                port_name = servers[0].ports[0].name
            else:
                port_name = None
                for port in servers[0].ports:
                    if port.ips[0]['ip_address'] in ips:
                        port_name = port.name
                        break

            if port_name is None:
                err_msg = "The VNF {} does not have any suitable port {} " \
                          "for floating IP assignment".format(
                            name,
                            'with ip any of ' + str(ips) if ips else '')
                logger.error(err_msg)
                raise Exception(err_msg)

            float_ip = FloatingIpConfig(name=name,
                                        port_name=port_name,
                                        router_name=router.name)
            ip = sf_creator.add_floating_ip(float_ip)
            self.creators.append(sf_creator)
            fips.append(ip.ip)

        return fips

    def get_instance_port(self, vm, vm_creator, port_name=None):
        '''
        Get the neutron port id of the client
        '''
        if not port_name:
            port_name = vm.name + "-port"
        port = vm_creator.get_port_by_name(port_name)
        if port is not None:
            return port
        else:
            logger.error("The VM {0} does not have any port"
                         " with name {1}".format(vm.name, port_name))
            raise Exception("Client VM does not have the desired port")

    def delete_all_security_groups(self):
        '''
        Deletes all the available security groups

        Needed until this bug is fixed:
        https://bugs.launchpad.net/networking-odl/+bug/1763705
        '''
        sec_groups = neutron_utils.list_security_groups(self.neutron)
        for sg in sec_groups:
            neutron_utils.delete_security_group(self.neutron, sg)

    def wait_for_vnf(self, vnf_creator):
        '''
        Waits for VNF to become active
        '''
        return vnf_creator.vm_active(block=True, poll_interval=5)

    def create_port_groups(self, vnf_ports, vm_instance):
        '''
        Creates a networking-sfc port pair and group
        '''
        logger.info("Creating the port pairs for %s" % vm_instance.name)
        port_pair = dict()
        port_pair['name'] = vm_instance.name + '-connection-points'
        port_pair['description'] = 'port pair for ' + vm_instance.name

        # In the symmetric testcase ingres != egress (VNF has 2 interfaces)
        if len(vnf_ports) == 1:
            port_pair['ingress'] = vnf_ports[0].id
            port_pair['egress'] = vnf_ports[0].id
        elif len(vnf_ports) == 2:
            port_pair['ingress'] = vnf_ports[0].id
            port_pair['egress'] = vnf_ports[1].id
        else:
            logger.error("Only SFs with one or two ports are supported")
            raise Exception("Failed to create port pairs")
        port_pair_info = \
            self.neutron.create_sfc_port_pair({'port_pair': port_pair})
        if not port_pair_info:
            logger.warning("Chain creation failed due to port pair "
                           "creation failed for vnf %(vnf)s",
                           {'vnf': vm_instance.name})
            return None

        logger.info("Creating the port pair groups for %s" % vm_instance.name)
        port_pair_group = {}
        port_pair_group['name'] = vm_instance.name + '-port-pair-group'
        port_pair_group['description'] = \
            'port pair group for ' + vm_instance.name
        port_pair_group['port_pairs'] = []
        port_pair_group['port_pairs'].append(port_pair_info['port_pair']['id'])
        ppg_config = {'port_pair_group': port_pair_group}
        port_pair_group_info = \
            self.neutron.create_sfc_port_pair_group(ppg_config)
        if not port_pair_group_info:
            logger.warning("Chain creation failed due to port pair group "
                           "creation failed for vnf "
                           "%(vnf)", vm_instance.name)
            return None

        return port_pair_group_info['port_pair_group']['id']

    def create_chain(self, port_groups, neutron_port, port, protocol,
                     vnffg_name, symmetrical, server_port=None,
                     server_ip=None):
        '''
        Create the classifier
        '''
        logger.info("Creating the classifier...")

        if symmetrical:
            sfc_classifier_params = {'name': vnffg_name + '-classifier',
                                     'destination_ip_prefix': server_ip,
                                     'logical_source_port': neutron_port,
                                     'logical_destination_port': server_port,
                                     'destination_port_range_min': port,
                                     'destination_port_range_max': port,
                                     'protocol': protocol}
        else:
            sfc_classifier_params = {'name': vnffg_name + '-classifier',
                                     'logical_source_port': neutron_port,
                                     'destination_port_range_min': port,
                                     'destination_port_range_max': port,
                                     'protocol': protocol}

        fc_config = {'flow_classifier': sfc_classifier_params}
        fc_info = \
            self.neutron.create_sfc_flow_classifier(fc_config)

        logger.info("Creating the chain...")
        port_chain = {}
        port_chain['name'] = vnffg_name + '-port-chain'
        port_chain['description'] = 'port-chain for SFC'
        port_chain['port_pair_groups'] = port_groups
        port_chain['flow_classifiers'] = []
        port_chain['flow_classifiers'].append(fc_info['flow_classifier']['id'])
        if symmetrical:
            port_chain['chain_parameters'] = {}
            port_chain['chain_parameters']['symmetric'] = True
        chain_config = {'port_chain': port_chain}
        return self.neutron.create_sfc_port_chain(chain_config)

    def delete_port_groups(self):
        '''
        Delete all port groups and port pairs
        '''
        logger.info("Deleting the port groups...")
        ppg_list = self.neutron.list_sfc_port_pair_groups()['port_pair_groups']
        for ppg in ppg_list:
            self.neutron.delete_sfc_port_pair_group(ppg['id'])

        logger.info("Deleting the port pairs...")
        pp_list = self.neutron.list_sfc_port_pairs()['port_pairs']
        for pp in pp_list:
            self.neutron.delete_sfc_port_pair(pp['id'])

    def delete_chain(self):
        '''
        Delete the classifiers and the chains
        '''
        logger.info("Deleting the chain...")
        pc_list = self.neutron.list_sfc_port_chains()['port_chains']
        for pc in pc_list:
            self.neutron.delete_sfc_port_chain(pc['id'])

        logger.info("Deleting the classifiers...")
        fc_list = self.neutron.list_sfc_flow_classifiers()['flow_classifiers']
        for fc in fc_list:
            self.neutron.delete_sfc_flow_classifier(fc['id'])


# TACKER SECTION #
def get_tacker_client_version():
    api_version = os.getenv('OS_TACKER_API_VERSION')
    if api_version is not None:
        logger.info("OS_TACKER_API_VERSION is set in env as '%s'", api_version)
        return api_version
    return DEFAULT_TACKER_API_VERSION


def get_tacker_client(other_creds={}):
    creds_override = None
    os_creds = openstack_tests.get_credentials(
        os_env_file=constants.ENV_FILE,
        overrides=creds_override)
    sess = keystone_utils.keystone_session(os_creds)
    return tackerclient.Client(get_tacker_client_version(), session=sess)


def get_id_from_name(tacker_client, resource_type, resource_name):
    try:
        params = {'fields': 'id', 'name': resource_name}
        collection = resource_type + 's'
        path = '/' + collection
        resp = tacker_client.list(collection, path, **params)
        return resp[collection][0]['id']
    except Exception as e:
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
    except Exception as e:
        logger.error("Error [list_vnfds(tacker_client)]: %s" % e)
        return None


def create_vnfd(tacker_client, tosca_file=None, vnfd_name=None):
    logger.info("Creating the vnfd...")
    try:
        vnfd_body = {}
        if tosca_file is not None:
            with open(tosca_file) as tosca_fd:
                vnfd = tosca_fd.read()
                vnfd_body = yaml.safe_load(vnfd)
            logger.info('VNFD template:\n{0}'.format(vnfd))
        return tacker_client.create_vnfd(
            body={"vnfd": {"attributes": {"vnfd": vnfd_body},
                  "name": vnfd_name}})
    except Exception as e:
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
    except Exception as e:
        logger.error("Error [delete_vnfd(tacker_client, '%s', '%s')]: %s"
                     % (vnfd_id, vnfd_name, e))
        return None


def list_vnfs(tacker_client, verbose=False):
    try:
        vnfs = tacker_client.list_vnfs(retrieve_all=True)
        if not verbose:
            vnfs = [vnf['id'] for vnf in vnfs['vnfs']]
        return vnfs
    except Exception as e:
        logger.error("Error [list_vnfs(tacker_client)]: %s" % e)
        return None


def create_vnf(tacker_client, vnf_name, vnfd_id=None,
               vnfd_name=None, vim_id=None, vim_name=None, param_file=None):
    logger.info("Creating the vnf...")
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

    except Exception as e:
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

    except Exception as e:
        logger.error("Could not retrieve VNF [vnf_id=%s, vnf_name=%s] - %s"
                     % (vnf_id, vnf_name, e))
        return None


def get_vnf_ip(tacker_client, vnf_id=None, vnf_name=None):
    """
    Get the management ip of the first VNF component as obtained from the
    tacker REST API:

        {
        "vnf": {
            ...
            "mgmt_url": "{\"VDU1\": \"192.168.120.3\"}",
            ...
        }
    """
    vnf = get_vnf(tacker_client, vnf_id, vnf_name)
    return json.loads(vnf['mgmt_url']).values()[0]


def wait_for_vnf(tacker_client, vnf_id=None, vnf_name=None, timeout=100):
    try:
        vnf = get_vnf(tacker_client, vnf_id, vnf_name)
        if vnf is None:
            raise Exception("Could not retrieve VNF - id='%s', name='%s'"
                            % (vnf_id, vnf_name))
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
    except Exception as e:
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
    except Exception as e:
        logger.error("Error [delete_vnf(tacker_client, '%s', '%s')]: %s"
                     % (vnf_id, vnf_name, e))
        return None


def create_vim(tacker_client, vim_file=None):
    logger.info("Creating the vim...")
    try:
        vim_body = {}
        if vim_file is not None:
            with open(vim_file) as vim_fd:
                vim_body = json.load(vim_fd)
            logger.info('VIM template:\n{0}'.format(vim_body))
        return tacker_client.create_vim(body=vim_body)
    except Exception as e:
        logger.error("Error [create_vim(tacker_client, '%s')]: %s"
                     % (vim_file, e))
        return None


def create_vnffgd(tacker_client, tosca_file=None, vnffgd_name=None):
    logger.info("Creating the vnffgd...")
    try:
        vnffgd_body = {}
        if tosca_file is not None:
            with open(tosca_file) as tosca_fd:
                vnffgd = tosca_fd.read()
                vnffgd_body = yaml.safe_load(vnffgd)
            logger.info('VNFFGD template:\n{0}'.format(vnffgd))
        return tacker_client.create_vnffgd(
            body={'vnffgd': {'name': vnffgd_name,
                  'template': {'vnffgd': vnffgd_body}}})
    except Exception as e:
        logger.error("Error [create_vnffgd(tacker_client, '%s')]: %s"
                     % (tosca_file, e))
        return None


def create_vnffg(tacker_client, vnffg_name=None, vnffgd_id=None,
                 vnffgd_name=None, param_file=None, symmetrical=False):
    '''
      Creates the vnffg which will provide the RSP and the classifier
    '''
    logger.info("Creating the vnffg...")
    try:
        vnffg_body = {
            'vnffg': {
                'attributes': {},
                'name': vnffg_name,
                'symmetrical': symmetrical
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
    except Exception as e:
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
    except Exception as e:
        logger.error("Error [list_vnffgds(tacker_client)]: %s" % e)
        return None


def list_vnffgs(tacker_client, verbose=False):
    try:
        vnffgs = tacker_client.list_vnffgs(retrieve_all=True)
        if not verbose:
            vnffgs = [vnffg['id'] for vnffg in vnffgs['vnffgs']]
        return vnffgs
    except Exception as e:
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
    except Exception as e:
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
    except Exception as e:
        logger.error("Error [delete_vnffgd(tacker_client, '%s', '%s')]: %s"
                     % (vnffgd_id, vnffgd_name, e))
        return None


def list_vims(tacker_client, verbose=False):
    try:
        vims = tacker_client.list_vims(retrieve_all=True)
        if not verbose:
            vims = [vim['id'] for vim in vims['vims']]
        return vims
    except Exception as e:
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
    except Exception as e:
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

        json_dict['vim']['auth_url'] = os.environ['OS_AUTH_URL']
        json_dict['vim']['auth_cred']['password'] = os.environ['OS_PASSWORD']

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
                                 default_param_file, client_port,
                                 server_port=None, server_ip=None):
    param_file = default_param_file
    data = {}
    if client_port:
        data['net_src_port_id'] = client_port
    if server_port:
        data['net_dst_port_id'] = server_port
    if server_ip:
        data['ip_dst_prefix'] = server_ip

    if client_port is not None or server_port is not None:
        param_file = os.path.join(
            '/tmp',
            'param_{0}.json'.format(vnffg_name))
        with open(param_file, 'w+') as f:
            json.dump(data, f)

    symmetrical = True if client_port and server_port else False

    create_vnffg(tacker_client,
                 vnffgd_name=vnffgd_name,
                 vnffg_name=vnffg_name,
                 param_file=param_file,
                 symmetrical=symmetrical)
