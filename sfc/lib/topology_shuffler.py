import datetime
import random
import functest.utils.openstack_utils as os_utils
import functest.utils.functest_logger as ft_logger


logger = ft_logger.Logger(__name__).getLogger()

# The possible topologies we are testing
TOPOLOGIES = [
    {
        'id': 'CLIENT_VNF_SAME_HOST',
        'description': '''
        Client instance and vnfs are are on the same
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
        Server instance and vnfs are are on the same
        compute host. Server instance is on a different host
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


def _get_seed():
    '''
    Get a seed based on the day of the week to choose which topology to test

    NOTE: There's sure a smarter way to do this
          Probably with the Jenkins job id
    '''
    cutoff = len(TOPOLOGIES - 1)
    seed = datetime.datetime.today().weekday()
    if seed > cutoff:
        seed = random.randrange(cutoff)
    return seed


def _split_host_aggregates():
    '''
    Gets all the compute hosts and creates an aggregate for each.
    Aggregates are named based on the convention compute1, compute2, ...
    '''
    nova_client = os_utils.get_nova_client()
    hosts = os_utils.get_hypervisors(nova_client)
    aggregates = []
    for idx, host in enumerate(hosts):
        az_name = 'compute{0}'.format(idx)
        # aggregate name is the same as availability zone name
        os_utils.create_aggregate_with_host(
            nova_client, az_name, az_name, host)
        aggregates.append(az_name)
    # aggregates and av zones abstractions are tightly coupled in nova
    return aggregates


def clean_host_aggregates(aggregates):
    '''
    Clean all the created host aggregates
    '''
    nova_client = os_utils.get_nova_client()
    for aggregate in aggregates:
        if not os_utils.delete_aggregate(nova_client, aggregate):
            logger.error('Could not delete aggregate {0}'
                         .format(aggregate))


def topology(vnf_names, host_aggregates=None, seed=None):
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
    Use seed=-1 to get the default topology created by nova-scheduler
    '''

    if host_aggregates is None:
        host_aggregates = _split_host_aggregates()
    if len(host_aggregates) < 2 or seed is None:
        return None

    topology = TOPOLOGIES[seed]
    topology_assigment = {}
    if topology['id'] == 'CLIENT_VNF_SAME_HOST':
        topology_assigment['client'] = host_aggregates[0]
        topology_assigment['server'] = host_aggregates[1]
        for vnf in vnf_names:
            topology_assigment[vnf] = host_aggregates[0]
    elif topology['id'] == 'CLIENT_SERVER_SAME_HOST':
        topology_assigment['client'] = host_aggregates[0]
        topology_assigment['server'] = host_aggregates[0]
        for vnf in vnf_names:
            topology_assigment[vnf] = host_aggregates[1]
    elif topology['id'] == 'SERVER_VNF_SAME_HOST':
        topology_assigment['client'] = host_aggregates[1]
        topology_assigment['server'] = host_aggregates[0]
        for vnf in vnf_names:
            topology_assigment[vnf] = host_aggregates[0]
    elif topology['id'] == 'CLIENT_SERVER_SAME_HOST_SPLIT_VNF':
        topology_assigment['client'] = host_aggregates[0]
        topology_assigment['server'] = host_aggregates[0]
        idx = 0
        for vnf in vnf_names:
            topology_assigment[vnf] = host_aggregates[idx % 2]
            idx += 1
    elif topology['id'] == 'CLIENT_SERVER_DIFFERENT_HOST_SPLIT_VNF':
        topology_assigment['client'] = host_aggregates[0]
        topology_assigment['server'] = host_aggregates[1]
        idx = 0
        for vnf in vnf_names:
            topology_assigment[vnf] = host_aggregates[idx % 2]
            idx += 1
    logger.info("Creating enpoint and VNF topology on the compute hosts")
    logger.info(topology['description'])
    return topology_assigment
