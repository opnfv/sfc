import logging
import os
import time
import json
import yaml
import functest.utils.openstack_utils as os_utils
from tackerclient.tacker import client as tackerclient
from functest.utils.constants import CONST


logger = logging.getLogger(__name__)
DEFAULT_TACKER_API_VERSION = '1.0'


def get_av_zones():
    '''
    Return the availability zone each host belongs to
    '''
    nova_client = os_utils.get_nova_client()
    hosts = os_utils.get_hypervisors(nova_client)
    return ['nova::{0}'.format(host) for host in hosts]


def get_compute_client():
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


def setup_neutron(neutron_client, net, subnet, router, subnet_cidr):
    n_dict = os_utils.create_network_full(neutron_client,
                                          net,
                                          subnet,
                                          router,
                                          subnet_cidr)
    if not n_dict:
        logger.error("failed to create neutron network")
        return False

    return n_dict["net_id"]


def create_secgroup_rule(neutron_client, sg_id, direction, protocol,
                         port_range_min=None, port_range_max=None):
    # We create a security group in 2 steps
    # 1 - we check the format and set the json body accordingly
    # 2 - we call neturon client to create the security group

    # Format check
    json_body = {'security_group_rule': {'direction': direction,
                                         'security_group_id': sg_id,
                                         'protocol': protocol}}
    # parameters may be
    # - both None => we do nothing
    # - both Not None => we add them to the json description
    # but one cannot be None is the other is not None
    if (port_range_min is not None and port_range_max is not None):
        # add port_range in json description
        json_body['security_group_rule']['port_range_min'] = port_range_min
        json_body['security_group_rule']['port_range_max'] = port_range_max
        logger.debug("Security_group format set (port range included)")
    else:
        # either both port range are set to None => do nothing
        # or one is set but not the other => log it and return False
        if port_range_min is None and port_range_max is None:
            logger.debug("Security_group format set (no port range mentioned)")
        else:
            logger.error("Bad security group format."
                         "One of the port range is not properly set:"
                         "range min: {},"
                         "range max: {}".format(port_range_min,
                                                port_range_max))
            return False

    # Create security group using neutron client
    try:
        neutron_client.create_security_group_rule(json_body)
        return True
    except:
        return False


def setup_ingress_egress_secgroup(neutron_client, protocol,
                                  min_port=None, max_port=None):
    secgroups = os_utils.get_security_groups(neutron_client)
    for sg in secgroups:
        # TODO: the version of the create_secgroup_rule function in
        # functest swallows the exception thrown when a secgroup rule
        # already exists and prints a ton of noise in the test output.
        # Instead of making changes in functest code this late in the
        # release cycle, we keep our own version without the exception
        # logging. We must find a way to properly cleanup sec group
        # rules using "functest openstack clean" or pretty printing the
        # specific exception in the next release
        create_secgroup_rule(neutron_client, sg['id'],
                             'ingress', protocol,
                             port_range_min=min_port,
                             port_range_max=max_port)
        create_secgroup_rule(neutron_client, sg['id'],
                             'egress', protocol,
                             port_range_min=min_port,
                             port_range_max=max_port)


def create_security_groups(neutron_client, secgroup_name, secgroup_descr):
    sg_id = os_utils.create_security_group_full(neutron_client,
                                                secgroup_name, secgroup_descr)
    setup_ingress_egress_secgroup(neutron_client, "icmp")
    setup_ingress_egress_secgroup(neutron_client, "tcp", 22, 22)
    setup_ingress_egress_secgroup(neutron_client, "tcp", 80, 80)
    setup_ingress_egress_secgroup(neutron_client, "udp", 67, 68)
    return sg_id


def create_instance(nova_client, name, flavor, image_id, network_id, sg_id,
                    secgroup_name=None, fixed_ip=None,
                    av_zone='', userdata=None, files=None):
    logger.info("Creating instance '%s'..." % name)
    logger.debug(
        "Configuration:\n name=%s \n flavor=%s \n image=%s \n"
        " network=%s\n secgroup=%s \n hypervisor=%s \n"
        " fixed_ip=%s\n files=%s\n userdata=\n%s\n"
        % (name, flavor, image_id, network_id, sg_id,
           av_zone, fixed_ip, files, userdata))
    instance = os_utils.create_instance_and_wait_for_active(
        flavor,
        image_id,
        network_id,
        name,
        config_drive=True,
        userdata=userdata,
        av_zone=av_zone,
        fixed_ip=fixed_ip,
        files=files)

    if instance is None:
        logger.error("Error while booting instance.")
        return None

    if secgroup_name:
        logger.debug("Adding '%s' to security group '%s'..."
                     % (name, secgroup_name))
    else:
        logger.debug("Adding '%s' to security group '%s'..."
                     % (name, sg_id))
    os_utils.add_secgroup_to_instance(nova_client, instance.id, sg_id)

    return instance


def assign_floating_ip(nova_client, neutron_client, instance_id):
    instance = nova_client.servers.get(instance_id)
    floating_ip = os_utils.create_floating_ip(neutron_client)['fip_addr']
    instance.add_floating_ip(floating_ip)
    logger.info("Assigned floating ip [%s] to instance [%s]"
                % (floating_ip, instance.name))

    return floating_ip


def get_nova_id(tacker_client, resource, vnf_id=None, vnf_name=None):
    vnf = get_vnf(tacker_client, vnf_id, vnf_name)
    try:
        if vnf is None:
            raise Exception("VNF not found")
        heat = os_utils.get_heat_client()
        resource = heat.resources.get(vnf['instance_id'], resource)
        return resource.attributes['id']
    except:
        logger.error("Cannot get nova ID for VNF (id='%s', name='%s')"
                     % (vnf_id, vnf_name))
        return None


def get_neutron_interfaces(vm):
    '''
    Get the interfaces of an instance
    '''
    nova_client = os_utils.get_nova_client()
    interfaces = nova_client.servers.interface_list(vm.id)
    return interfaces


def get_client_port_id(vm):
    '''
    Get the neutron port id of the client
    '''
    interfaces = get_neutron_interfaces(vm)
    if len(interfaces) > 1:
        raise Exception("Client has more than one interface. Not expected!")
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
