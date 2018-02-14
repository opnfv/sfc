import os
import sys
import logging

from opnfv.utils import ovs_logger as ovs_log
from opnfv.deployment.factory import Factory as DeploymentFactory
from sfc.lib import config as sfc_config
from sfc.lib import odl_utils as odl_utils
import sfc.lib.test_utils as test_utils
from sfc.lib.results import Results
import sfc.lib.openstack_utils as os_sfc_utils
import sfc.lib.topology_shuffler as topo_shuffler

logger = logging.getLogger(__name__)


class CommonTestCase():

    openstack_sfc = os_sfc_utils.OpenStackSFC()

    def preparation_openstack(self, COMMON_CONFIG, TESTCASE_CONFIG, logger, supported_installers):

        # COMMON_CONFIG = sfc_config.CommonConfig()
        # logger = logging.getLogger(__name__)
        # TESTCASE_CONFIG = sfc_config.TestcaseConfig('sfc_chain_deletion')

        deployment_handler = DeploymentFactory.get_handler(
            COMMON_CONFIG.installer_type,
            COMMON_CONFIG.installer_ip,
            COMMON_CONFIG.installer_user,
            COMMON_CONFIG.installer_password,
            COMMON_CONFIG.installer_key_file)

        installer_type = os.environ.get("INSTALLER_TYPE")

        # supported_installers = ['fuel', 'apex', 'osa']

        if installer_type not in supported_installers:
            logger.error(
                '\033[91mYour installer is not supported yet\033[0m')
            sys.exit(1)

        installer_ip = os.environ.get("INSTALLER_IP")
        if not installer_ip:
            logger.error(
                '\033[91minstaller ip is not set\033[0m')
            logger.error(
                '\033[91mexport INSTALLER_IP=<ip>\033[0m')
            sys.exit(1)

        cluster = COMMON_CONFIG.installer_cluster
        openstack_nodes = (deployment_handler.get_nodes({'cluster': cluster})
                           if cluster is not None
                           else deployment_handler.get_nodes())

        compute_nodes = [node for node in openstack_nodes
                         if node.is_compute()]

        for compute in compute_nodes:
            logger.info("This is a compute: %s" % compute.ip)

        results = Results(COMMON_CONFIG.line_length)
        results.add_to_summary(0, "=")
        results.add_to_summary(2, "STATUS", "SUBTEST")
        results.add_to_summary(0, "=")

        custom_flv = openstack_sfc.create_flavor(
            COMMON_CONFIG.flavor,
            COMMON_CONFIG.ram_size_in_mb,
            COMMON_CONFIG.disk_size_in_gb,
            COMMON_CONFIG.vcpu_count)
        if not custom_flv:
            logger.error("Failed to create custom flavor")
            sys.exit(1)

        tacker_client = os_sfc_utils.get_tacker_client()
        os_sfc_utils.register_vim(tacker_client, vim_file=COMMON_CONFIG.vim_file)

        ovs_logger = ovs_log.OVSLogger(
            os.path.join(COMMON_CONFIG.sfc_test_dir, 'ovs-logs'),
            COMMON_CONFIG.functest_results_dir)

        network, router = openstack_sfc.create_network_infrastructure(
            TESTCASE_CONFIG.net_name,
            TESTCASE_CONFIG.subnet_name,
            TESTCASE_CONFIG.subnet_cidr,
            TESTCASE_CONFIG.router_name)

        sg = openstack_sfc.create_security_group(TESTCASE_CONFIG.secgroup_name)

        image_creator = openstack_sfc.register_glance_image(
            COMMON_CONFIG.image_name,
            COMMON_CONFIG.image_url,
            COMMON_CONFIG.image_format,
            'public')

        return ovs_logger, network, router, sg, image_creator

    def create_custom_vnfd(self, COMMON_CONFIG, tacker_client, test_case_name, vnfd_name):

        # vnf_names = ['testVNF1', 'testVNF2']

        # topo_seed = topo_shuffler.get_seed()  # change to None for nova av zone
        # testTopology = topo_shuffler.topology(vnf_names, openstack_sfc,
        #                                       seed=topo_seed)

        # logger.info('This test is run with the topology {0}'
        #             .format(testTopology['id']))
        # logger.info('Topology description: {0}'
        #             .format(testTopology['description']))

        # client_instance, client_creator = openstack_sfc.create_instance(
        #     CLIENT, COMMON_CONFIG.flavor, image_creator, network, sg,
        #     av_zone=testTopology['client'])
        #
        # server_instance, server_creator = openstack_sfc.create_instance(
        #     SERVER, COMMON_CONFIG.flavor, image_creator, network, sg,
        #     av_zone=testTopology['server'])

        # server_ip = server_instance.ports[0].ips[0]['ip_address']

        tosca_file = os.path.join(COMMON_CONFIG.sfc_test_dir,
                                 COMMON_CONFIG.vnfd_dir,
                                 test_case_name)

        os_sfc_utils.create_vnfd(tacker_client,
                                 tosca_file,
                                 vnfd_name)

    def create_custom_av(self, COMMON_CONFIG, tacker_client, vnf_names, av_member1, av_member2, topo_seed):

        openstack_sfc = os_sfc_utils.OpenStackSFC()
        test_topology = topo_shuffler.topology(vnf_names, openstack_sfc, seed=topo_seed)
        default_param_file = os.path.join(
            COMMON_CONFIG.sfc_test_dir,
            COMMON_CONFIG.vnfd_dir,
            COMMON_CONFIG.vnfd_default_params_file)

        logger.info('This test is run with the topology {0}'
                    .format(test_topology['id']))
        logger.info('Topology description: {0}'
                    .format(test_topology['description']))

        os_sfc_utils.create_vnf_in_av_zone(
            tacker_client, vnf_names[0], av_member1, av_member2,
            default_param_file, test_topology[vnf_names[0]])

        vnf_id = os_sfc_utils.wait_for_vnf(tacker_client, vnf_names)
        if vnf_id is None:
            logger.error('ERROR while booting vnfs')
            sys.exit(1)

    def prepare_server_client_elements(self, COMMON_CONFIG, SERVER, image_creator, vnf_names, topo_seed, network, sg):

        test_topology = topo_shuffler.topology(vnf_names, openstack_sfc, seed=topo_seed)

        server_instance, server_creator = openstack_sfc.create_instance(
            SERVER, COMMON_CONFIG.flavor, image_creator, network, sg,
            av_zone=test_topology['server'])

        client_instance, client_creator = openstack_sfc.create_instance(
            CLIENT, COMMON_CONFIG.flavor, image_creator, network, sg,
            av_zone=test_topology['client'])

        return server_instance, server_creator, client_instance, client_creator

    def custom_floating_ip(self, router, client_instance, client_creator, server_instance, server_creator):
        logger.info("Assigning floating IPs to instances")

        client_floating_ip = openstack_sfc.assign_floating_ip(router,
                                                              client_instance,
                                                              client_creator)
        server_floating_ip = openstack_sfc.assign_floating_ip(router,
                                                              server_instance,
                                                              server_creator)

        return server_floating_ip, client_floating_ip

    def custom_sf_floating_ip(self, router):
        logger.info("Assigning floating IPs to instances")

        fips_sfs = openstack_sfc.assign_floating_ip_vnfs(router)
        sf1_floating_ip = fips_sfs[0]
        sf2_floating_ip = fips_sfs[1]

        return sf1_floating_ip, sf2_floating_ip

    def check_floating_ips(self, fips, sf1_floating_ip, sf2_floating_ip, server_floating_ip, odl_ip, odl_port):
        for ip in fips:
            logger.info("Checking connectivity towards floating IP [%s]" % ip)
            if not test_utils.ping(ip, retries=50, retry_timeout=3):
                logger.error("Cannot ping floating IP [%s]" % ip)
                os_sfc_utils.get_tacker_items()
                odl_utils.get_odl_items(odl_ip, odl_port)
                sys.exit(1)
            logger.info("Successful ping to floating IP [%s]" % ip)

        if not test_utils.check_ssh([sf1_floating_ip, sf2_floating_ip]):
            logger.error("Cannot establish SSH connection to the SFs")
            sys.exit(1)

        logger.info("Starting HTTP server on %s" % server_floating_ip)
        if not test_utils.start_http_server(server_floating_ip):
            logger.error('\033[91mFailed to start HTTP server on %s\033[0m'
                         % server_floating_ip)
            sys.exit(1)

        logger.info("Starting SSH firewall on %s" % sf1_floating_ip)
        test_utils.start_vxlan_tool(sf1_floating_ip, block="22")
        logger.info("Starting HTTP firewall on %s" % sf2_floating_ip)
        test_utils.start_vxlan_tool(sf2_floating_ip, block="80")

    def present_results_ssh(self, COMMON_CONFIG, server_instance, deployment_handler, compute_nodes, client_floating_ip,
                            ovs_logger):

        cluster = COMMON_CONFIG.installer_cluster
        openstack_nodes = (deployment_handler.get_nodes({'cluster': cluster})
                           if cluster is not None
                           else deployment_handler.get_nodes())

        server_ip = server_instance.ports[0].ips[0]['ip_address']
        controller_nodes = [node for node in openstack_nodes
                            if node.is_controller()]
        controller_clients = test_utils.get_ssh_clients(controller_nodes)
        compute_clients = test_utils.get_ssh_clients(compute_nodes)
        results = Results(COMMON_CONFIG.line_length)
        results.add_to_summary(0, "=")
        results.add_to_summary(2, "STATUS", "SUBTEST")
        results.add_to_summary(0, "=")

        logger.info("Test SSH")
        if test_utils.is_ssh_blocked(client_floating_ip, server_ip):
            results.add_to_summary(2, "PASS", "SSH Blocked")
            verdict = True
        else:
            error = ('\033[91mTEST 1 [FAILED] ==> SSH NOT BLOCKED\033[0m')
            logger.error(error)
            test_utils.capture_ovs_logs(
                ovs_logger, controller_clients, compute_clients, error)
            results.add_to_summary(2, "FAIL", "SSH Blocked")
            verdict = False

        # logger.info("Test HTTP")
        # if not test_utils.is_http_blocked(client_floating_ip, server_ip):
        #     results.add_to_summary(2, "PASS", "HTTP works")
        #     verdict = "PASS"
        # else:
        #     error = ('\033[91mTEST 2 [FAILED] ==> HTTP BLOCKED\033[0m')
        #     logger.error(error)
        #     test_utils.capture_ovs_logs(
        #         ovs_logger, controller_clients, compute_clients, error)
        #     results.add_to_summary(2, "FAIL", "HTTP works")
        #     verdict = "FAIL"

        logger.info("Changing the classification")
        return results, verdict

    def remove_vnff(self, tacker_client, vnffg_name, vnffgd_name):
        os_sfc_utils.delete_vnffg(tacker_client, vnffg_name)

        os_sfc_utils.delete_vnffgd(tacker_client, vnffgd_name)

    def path_join(self, COMMON_CONFIG, TESTCASE_CONFIG, tacker_client, client_instance, vnf_name, conn_name):

        default_param_file = os.path.join(
                COMMON_CONFIG.sfc_test_dir,
                COMMON_CONFIG.vnfd_dir,
                COMMON_CONFIG.vnfd_default_params_file)

        tosca_file = os.path.join(COMMON_CONFIG.sfc_test_dir,
                                  COMMON_CONFIG.vnffgd_dir,
                                  TESTCASE_CONFIG.test_vnffgd_red)

        os_sfc_utils.create_vnffgd(tacker_client,
                                   tosca_file=tosca_file,
                                   vnffgd_name=vnf_name)

        neutron_port = openstack_sfc.get_client_port_id(client_instance, client_creator)
        os_sfc_utils.create_vnffg_with_param_file(tacker_client, vnf_name,
                                                  conn_name,
                                                  default_param_file,
                                                  neutron_port.id)

    def present_results_http(self, COMMON_CONFIG, client_floating_ip, server_instance, ovs_logger, deployment_handler,
                             compute_nodes):

        cluster = COMMON_CONFIG.installer_cluster
        openstack_nodes = (deployment_handler.get_nodes({'cluster': cluster})
                           if cluster is not None
                           else deployment_handler.get_nodes())

        server_ip = server_instance.ports[0].ips[0]['ip_address']
        controller_nodes = [node for node in openstack_nodes
                            if node.is_controller()]
        controller_clients = test_utils.get_ssh_clients(controller_nodes)
        compute_clients = test_utils.get_ssh_clients(compute_nodes)

        results = Results(COMMON_CONFIG.line_length)
        results.add_to_summary(0, "=")
        results.add_to_summary(2, "STATUS", "SUBTEST")
        results.add_to_summary(0, "=")

        logger.info("Test HTTP")
        if test_utils.is_http_blocked(client_floating_ip, server_ip):
            results.add_to_summary(2, "PASS", "HTTP Blocked")
            verdict = True
        else:
            error = ('\033[91mTEST 3 [FAILED] ==> HTTP WORKS\033[0m')
            logger.error(error)
            test_utils.capture_ovs_logs(
                ovs_logger, controller_clients, compute_clients, error)
            results.add_to_summary(2, "FAIL", "HTTP Blocked")
            verdict = False

        # logger.info("Test SSH")
        # if not test_utils.is_ssh_blocked(client_floating_ip, server_ip):
        #     results.add_to_summary(2, "PASS", "SSH works")
        # else:
        #     error = ('\033[91mTEST 4 [FAILED] ==> SSH BLOCKED\033[0m')
        #     logger.error(error)
        #     test_utils.capture_ovs_logs(
        #         ovs_logger, controller_clients, compute_clients, error)
        #     results.add_to_summary(2, "FAIL", "SSH works")
        return results, verdict

    def installer_deployment_nodes(self, COMMON_CONFIG):
        deployment_handler = DeploymentFactory.get_handler(
            COMMON_CONFIG.installer_type,
            COMMON_CONFIG.installer_ip,
            COMMON_CONFIG.installer_user,
            COMMON_CONFIG.installer_password,
            COMMON_CONFIG.installer_key_file)

        cluster = COMMON_CONFIG.installer_cluster

        openstack_nodes = (deployment_handler.get_nodes({'cluster': cluster})
                           if cluster is not None
                           else deployment_handler.get_nodes())

        compute_nodes = [node for node in openstack_nodes
                         if node.is_compute()]
        controller_nodes = [node for node in openstack_nodes
                            if node.is_controller()]

        return compute_nodes, controller_nodes

    def installer_deployment_odl(self, COMMON_CONFIG):
        deployment_handler = DeploymentFactory.get_handler(
            COMMON_CONFIG.installer_type,
            COMMON_CONFIG.installer_ip,
            COMMON_CONFIG.installer_user,
            COMMON_CONFIG.installer_password,
            COMMON_CONFIG.installer_key_file)

        cluster = COMMON_CONFIG.installer_cluster

        openstack_nodes = (deployment_handler.get_nodes({'cluster': cluster})
                           if cluster is not None
                           else deployment_handler.get_nodes())

        odl_ip, odl_port = odl_utils.get_odl_ip_port(openstack_nodes)

        return odl_ip, odl_port, deployment_handler

    def prepare_topology(self, vnfs):

        topo_seed = topo_shuffler.get_seed()
        test_topology = topo_shuffler.topology(vnfs, openstack_sfc, seed=topo_seed)

        return test_topology, topo_seed

    def prepare_client_resources(self, COMMON_CONFIG, compute_nodes, controller_nodes):

        custom_flv = openstack_sfc.create_flavor(
            COMMON_CONFIG.flavor,
            COMMON_CONFIG.ram_size_in_mb,
            COMMON_CONFIG.disk_size_in_gb,
            COMMON_CONFIG.vcpu_count)
        if not custom_flv:
            logger.error("Failed to create custom flavor")
            sys.exit(1)

        controller_clients = test_utils.get_ssh_clients(controller_nodes)
        compute_clients = test_utils.get_ssh_clients(compute_nodes)

        return compute_clients, controller_clients

    def block_http_trafic(self, sf1_floating_ip, sf2_floating_ip, client_floating_ip, ovs_logger, controller_clients, server_ip, compute_clients, results):
        test_utils.stop_vxlan_tool(sf2_floating_ip)
        logger.info("Starting HTTP firewall on %s" % sf2_floating_ip)
        test_utils.start_vxlan_tool(sf2_floating_ip, block="80")
        logger.info("Stopping HTTP firewall on %s" % sf1_floating_ip)
        test_utils.stop_vxlan_tool(sf1_floating_ip)

        logger.info("Test HTTP again blocking SF2")
        if test_utils.is_http_blocked(client_floating_ip, server_ip):
            results.add_to_summary(2, "PASS", "HTTP Blocked")
            verdict = True
        else:
            error = ('\033[91mTEST 3 [FAILED] ==> HTTP WORKS\033[0m')
            logger.error(error)
            test_utils.capture_ovs_logs(
                ovs_logger, controller_clients, compute_clients, error)
            results.add_to_summary(2, "FAIL", "HTTP not blocked")
            verdict = False

        return results, verdict
