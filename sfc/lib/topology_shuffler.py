import datetime
import random
import functest.utils.openstack_utils as os_utils
import functest.utils.functest_logger as ft_logger


logger = ft_logger.Logger(__name__).getLogger()


class TopologyShuffler(object):
    def __init__(self, seed=None):
        # With the assumptions of 2 compute hosts
        self.mutations = [
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

        self.seed = (seed if seed is not None else self._get_seed())

    def _get_seed(self):
        # There's sure a smarter way to do this
        # Probably with the Jenkins job id
        cutoff = len(self.mutations - 1)
        seed = datetime.datetime.today().weekday()
        if seed > cutoff:
            seed = random.randrange(cutoff)

    def _split_host_aggregates(self):
        '''
        Splits compute hosts into aggregates
        '''
        nova_client = os_utils.get_nova_client()
        hosts = os_utils.get_hypervisors(nova_client)
        av_zones = []
        for idx, host in enumerate(hosts):
            az_name = 'compute{0}'.format(idx)
            # aggregate name is the same as availability zone name
            os_utils.create_aggregate_with_host(
                nova_client, az_name, az_name, host)
            av_zones.append(az_name)
        # aggregates and av zones abstractions are tightly coupled in nova
        self.aggregates = av_zones
        return av_zones

    def clean_host_aggregates(self):
        nova_client = os_utils.get_nova_client()
        for aggregate in self.aggregates:
            if not os_utils.delete_aggregate(nova_client, aggregate):
                logger.error('Could not delete aggregate {0}'
                             .format(aggregate))

    def assign(self, vnf_names, av_zones=None):
        '''
        Assumption: 2 compute hosts
        '''
        mutation = self.mutations[self.seed]
        if av_zones is None:
            av_zones = self._split_host_aggregates()
        if len(av_zones) != 2:
            return None

        assignment = {}
        if mutation['id'] == 'CLIENT_VNF_SAME_HOST':
            assignment['client'] = av_zones[0]
            assignment['server'] = av_zones[1]
            for vnf in vnf_names:
                assignment[vnf] = av_zones[0]
        elif mutation['id'] == 'CLIENT_SERVER_SAME_HOST':
            assignment['client'] = av_zones[0]
            assignment['server'] = av_zones[0]
            for vnf in vnf_names:
                assignment[vnf] = av_zones[1]
        elif mutation['id'] == 'SERVER_VNF_SAME_HOST':
            assignment['client'] = av_zones[1]
            assignment['server'] = av_zones[0]
            for vnf in vnf_names:
                assignment[vnf] = av_zones[0]
        elif mutation['id'] == 'CLIENT_SERVER_SAME_HOST_SPLIT_VNF':
            assignment['client'] = av_zones[0]
            assignment['server'] = av_zones[0]
            idx = 0
            for vnf in vnf_names:
                assignment[vnf] = av_zones[idx % 2]
                idx += 1
        elif mutation['id'] == 'CLIENT_SERVER_DIFFERENT_HOST_SPLIT_VNF':
            assignment['client'] = av_zones[0]
            assignment['server'] = av_zones[1]
            idx = 0
            for vnf in vnf_names:
                assignment[vnf] = av_zones[idx % 2]
                idx += 1
        logger.info("Creating enpoint and VNF assignment to compute hosts")
        logger.info(mutation['description'])
        return assignment
