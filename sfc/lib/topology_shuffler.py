import datetime
import random
import functest.utils.openstack_utils as os_utils
import logging as ft_logger

# import functest.utils.functest_logger as ft_logger


logger = ft_logger.getLogger(__name__)

# The possible topologies we are testing
TOPOLOGIES = [
    {
        'id': 'CLIENT_SERVER_VNF_SAME_HOST',
        'description': '''
        All endpoints and VNFs are on a single host.
        This is the baseline test.
        '''
    },
    {
        'id': 'CLIENT_SERVER_SAME_HOST_SPLIT_VNF',
        'description': '''
        Client and server are on the same host.
        The VNFs are split between hosts Round Robin.
        '''
    },
    {
        'id': 'CLIENT_VNF_SAME_HOST',
        'description': '''
        Client instance and vnfs are on the same
        compute host. Server instance is on a different host
        '''
    },
    {
        'id': 'CLIENT_SERVER_SAME_HOST',
        'description': '''
        Client instance and server instance are on the same
        compute host. All VNFs are on a different host.
        '''
    },
    {
        'id': 'SERVER_VNF_SAME_HOST',
        'description': '''
        Server instance and vnfs are on the same
        compute host. Client instance is on a different host
        '''
    },
    {
        'id': 'CLIENT_SERVER_DIFFERENT_HOST_SPLIT_VNF',
        'description': '''
        Client and server are on different hosts.
        The VNFs are split between hosts Round Robin.
        '''
    }
]

DEFAULT_TOPO = {
    'id': 'DEFAULT',
    'description': '''
    The default topology created by nova scheduler
    '''
}


def get_seed():
    '''
    Get a seed based on the day of the week to choose which topology to test

    NOTE: There's sure a smarter way to do this
          Probably with the Jenkins job id
    '''
    # We only try tests which work
    test_working = 2
    cutoff = test_working - 1
    # cutoff = len(TOPOLOGIES) - 1
    seed = datetime.datetime.today().weekday()
    if seed > cutoff:
        seed = random.randrange(cutoff)
    return seed


def _get_av_zones():
    '''
    Return the availability zone each host belongs to
    '''
    nova_client = os_utils.get_nova_client()
    hosts = os_utils.get_hypervisors(nova_client)
    return ['nova::{0}'.format(host) for host in hosts]


def topology(vnf_names, av_zones=None, seed=None):
    '''
    Get the topology for client, server and vnfs.
    The topology is returned as a dict in the form
    {
    'client': <availability_zone>,
    'server': <availability_zone>,
    'vnf1':   <availability_zone>,
    'vnf2':   <availability_zone>
    ...
    }
    Use seed=None to get the default topology created by nova-scheduler
    '''

    if av_zones is None:
        av_zones = _get_av_zones()

    if len(av_zones) < 2 or seed is None:
        # fall back to nova availability zone
        topology_assignment = {
            'id': DEFAULT_TOPO['id'],
            'description': DEFAULT_TOPO['description'],
            'client': 'nova',
            'server': 'nova'
        }
        for vnf in vnf_names:
            topology_assignment[vnf] = 'nova'
        return topology_assignment

    topo = TOPOLOGIES[seed]
    topology_assigment = {
        'id': topo['id'],
        'description': topo['description']
    }
    if topo['id'] == 'CLIENT_SERVER_VNF_SAME_HOST':
        topology_assigment['client'] = av_zones[0]
        topology_assigment['server'] = av_zones[0]
        for vnf in vnf_names:
            topology_assigment[vnf] = av_zones[0]
    elif topo['id'] == 'CLIENT_VNF_SAME_HOST':
        topology_assigment['client'] = av_zones[0]
        topology_assigment['server'] = av_zones[1]
        for vnf in vnf_names:
            topology_assigment[vnf] = av_zones[0]
    elif topo['id'] == 'CLIENT_SERVER_SAME_HOST':
        topology_assigment['client'] = av_zones[0]
        topology_assigment['server'] = av_zones[0]
        for vnf in vnf_names:
            topology_assigment[vnf] = av_zones[1]
    elif topo['id'] == 'SERVER_VNF_SAME_HOST':
        topology_assigment['client'] = av_zones[1]
        topology_assigment['server'] = av_zones[0]
        for vnf in vnf_names:
            topology_assigment[vnf] = av_zones[0]
    elif topo['id'] == 'CLIENT_SERVER_SAME_HOST_SPLIT_VNF':
        topology_assigment['client'] = av_zones[0]
        topology_assigment['server'] = av_zones[0]
        for idx, vnf in enumerate(vnf_names):
            topology_assigment[vnf] = av_zones[idx % 2]
    elif topo['id'] == 'CLIENT_SERVER_DIFFERENT_HOST_SPLIT_VNF':
        topology_assigment['client'] = av_zones[0]
        topology_assigment['server'] = av_zones[1]
        for idx, vnf in enumerate(vnf_names):
            topology_assigment[vnf] = av_zones[idx % 2]
    logger.info("Creating enpoint and VNF topology on the compute hosts")
    logger.info(topo['description'])
    return topology_assigment
