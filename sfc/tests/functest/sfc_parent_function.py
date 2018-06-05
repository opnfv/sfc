import os
import sys
import logging
import sfc.lib.test_utils as test_utils
import sfc.lib.openstack_utils as os_sfc_utils
import sfc.lib.topology_shuffler as topo_shuffler

from opnfv.utils import ovs_logger as ovs_log
from opnfv.deployment.factory import Factory as DeploymentFactory
from sfc.lib import config as sfc_config
from sfc.lib import odl_utils as odl_utils
from sfc.lib.results import Results


logger = logging.getLogger(__name__)
CLIENT = "client"
SERVER = "server"
openstack_sfc = os_sfc_utils.OpenStackSFC()
COMMON_CONFIG = sfc_config.CommonConfig()
results = Results(COMMON_CONFIG.line_length)


class SfcCommonTestCase(object):

    def __init__(self,  testcase_config, supported_installers, vnfs):

        self.compute_nodes = None
        self.controller_clients = None
        self.compute_clients = None
        self.tacker_client = None
        self.ovs_logger = None
        self.network = None
        self.router = None
        self.sg = None
        self.image_creator = None
        self.vnf_image_creator = None
        self.creators = None
        self.odl_ip = None
        self.odl_port = None
        self.default_param_file = None
        self.topo_seed = None
        self.test_topology = None
        self.server_instance = None
        self.server_creator = None
        self.client_instance = None
        self.client_creator = None
        self.server_ip = None
        self.vnf_id = None
        self.client_floating_ip = None
        self.server_floating_ip = None
        self.fips_sfs = None
        self.neutron_port = None
        self.testcase_config = testcase_config
        self.vnfs = vnfs

        self.prepare_env(testcase_config, supported_installers, vnfs)

    def prepare_env(self, testcase_config, supported_installers, vnfs):
        """Prepare the testcase environment and the components
        that the test scenario is going to use later on.

        :param testcase_config: the input test config file
        :param supported_installers: the supported installers for this tc
        :param vnfs: the names of vnfs
        :return: Environment preparation
        """

        deployment_handler = DeploymentFactory.get_handler(
            COMMON_CONFIG.installer_type,
            COMMON_CONFIG.installer_ip,
            COMMON_CONFIG.installer_user,
            COMMON_CONFIG.installer_password,
            COMMON_CONFIG.installer_key_file)

        installer_type = os.environ.get("INSTALLER_TYPE")

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

        self.compute_nodes = [node for node in openstack_nodes
                              if node.is_compute()]

        for compute in self.compute_nodes:
            logger.info("This is a compute: %s" % compute.ip)

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

        controller_nodes = [node for node in openstack_nodes
                            if node.is_controller()]

        self.controller_clients = test_utils.get_ssh_clients(controller_nodes)
        self.compute_clients = test_utils.get_ssh_clients(self.compute_nodes)

        self.tacker_client = os_sfc_utils.get_tacker_client()
        os_sfc_utils.register_vim(self.tacker_client,
                                  vim_file=COMMON_CONFIG.vim_file)

        self.ovs_logger = ovs_log.OVSLogger(
            os.path.join(COMMON_CONFIG.sfc_test_dir, 'ovs-logs'),
            COMMON_CONFIG.functest_results_dir)

        self.network, self.router = openstack_sfc.\
            create_network_infrastructure(testcase_config.net_name,
                                          testcase_config.subnet_name,
                                          testcase_config.subnet_cidr,
                                          testcase_config.router_name)

        self.sg = openstack_sfc.create_security_group(
            testcase_config.secgroup_name)

        # Image for the vnf is registered
        self.vnf_image_creator = openstack_sfc.register_glance_image(
            COMMON_CONFIG.vnf_image_name,
            COMMON_CONFIG.vnf_image_url,
            COMMON_CONFIG.vnf_image_format,
            'public')

        # Image for the client/server is registered
        self.image_creator = openstack_sfc.register_glance_image(
            COMMON_CONFIG.image_name,
            COMMON_CONFIG.image_url,
            COMMON_CONFIG.image_format,
            'public')

        self.creators = openstack_sfc.creators

        self.odl_ip, self.odl_port = odl_utils.get_odl_ip_port(openstack_nodes)

        self.default_param_file = os.path.join(
            COMMON_CONFIG.sfc_test_dir,
            COMMON_CONFIG.vnfd_dir,
            COMMON_CONFIG.vnfd_default_params_file)

        self.topo_seed = topo_shuffler.get_seed()
        self.test_topology = topo_shuffler.topology(vnfs, openstack_sfc,
                                                    seed=self.topo_seed)

        logger.info('This test is run with the topology {0}'
                    .format(self.test_topology['id']))
        logger.info('Topology description: {0}'
                    .format(self.test_topology['description']))

        self.server_instance, self.server_creator = \
            openstack_sfc.create_instance(SERVER, COMMON_CONFIG.flavor,
                                          self.image_creator, self.network,
                                          self.sg,
                                          av_zone=self.test_topology['server'])

        self.client_instance, self.client_creator = \
            openstack_sfc.create_instance(CLIENT, COMMON_CONFIG.flavor,
                                          self.image_creator, self.network,
                                          self.sg,
                                          av_zone=self.test_topology['client'])
        logger.info('This test is run with the topology {0}'.format(
            self.test_topology['id']))
        logger.info('Topology description: {0}'.format(
            self.test_topology['description']))

        self.server_ip = self.server_instance.ports[0].ips[0]['ip_address']
        logger.info("Server instance received private ip [{}]".format(
            self.server_ip))

    def create_custom_vnfd(self, test_case_name, vnfd_name):
        """Create VNF Descriptor (VNFD)

        :param test_case_name: the name of test case
        :param vnfd_name: the name of vnfd
        :return: vnfd
        """

        tosca_file = os.path.join(COMMON_CONFIG.sfc_test_dir,
                                  COMMON_CONFIG.vnfd_dir, test_case_name)

        os_sfc_utils.create_vnfd(self.tacker_client,
                                 tosca_file=tosca_file,
                                 vnfd_name=vnfd_name)

    def create_custom_av(self, vnf_names, av_member1, av_member2):
        """Create custom 'av'

        :param vnf_names: names of available vnf(s)
        :param av_member1: the first member of av zone
        :param av_member2: the second member of av zone
        :return: av zone
        """

        logger.info('This test is run with the topology {0}'.
                    format(self.test_topology['id']))
        logger.info('Topology description: {0}'
                    .format(self.test_topology['description']))

        os_sfc_utils.create_vnf_in_av_zone(
            self.tacker_client, vnf_names, av_member1, av_member2,
            self.default_param_file, self.test_topology[vnf_names])

        self.vnf_id = os_sfc_utils.wait_for_vnf(self.tacker_client,
                                                vnf_name=vnf_names)
        if self.vnf_id is None:
            logger.error('ERROR while booting vnfs')
            sys.exit(1)

    def assign_floating_ip_client_server(self):
        """Assign floating IPs on the router about server and the client
        instances

        :return: Floating IPs for client and server
        """

        logger.info("Assigning floating IPs to client and server instances")

        self.client_floating_ip = openstack_sfc.assign_floating_ip(
            self.router, self.client_instance, self.client_creator)
        self.server_floating_ip = openstack_sfc.assign_floating_ip(
            self.router, self.server_instance, self.server_creator)

    def assign_floating_ip_sfs(self, vnf_ip=None):
        """Assign floating IPs to service function

        :param vnf_ip: IP of vnf - optional
        :return: The list fips_sfs consist of the available IPs for service
                 functions
        """

        logger.info("Assigning floating IPs to service functions")

        self.fips_sfs = openstack_sfc.assign_floating_ip_vnfs(self.router,
                                                              vnf_ip)

    def check_floating_ips(self):
        """Check the responsivness of the floating IPs

        :return: The responsivness of IPs in the fips_sfs list is checked
        """

        fips = [self.client_floating_ip, self.server_floating_ip]

        for sf in self.fips_sfs:
            fips.append(sf)

        for ip in fips:
            logger.info("Checking connectivity towards floating IP [%s]" % ip)
            if not test_utils.ping(ip, retries=50, retry_timeout=3):
                logger.error("Cannot ping floating IP [%s]" % ip)
                os_sfc_utils.get_tacker_items()
                odl_utils.get_odl_items(self.odl_ip, self.odl_port)
                sys.exit(1)
            logger.info("Successful ping to floating IP [%s]" % ip)

        if not test_utils.check_ssh(self.fips_sfs):
            logger.error("Cannot establish SSH connection to the SFs")
            sys.exit(1)

    def start_services_in_vm(self):
        """Start the HTTP server in the server VM as well as the vxlan tool for
           the SFs IPs included in the fips_sfs list

        :return: HTTP server and vxlan tools are started
        """

        logger.info("Starting HTTP server on %s" % self.server_floating_ip)
        if not test_utils.start_http_server(self.server_floating_ip):
            logger.error('\033[91mFailed to start HTTP server on %s\033[0m'
                         % self.server_floating_ip)
            sys.exit(1)

        for sf_floating_ip in self.fips_sfs:
            logger.info("Starting vxlan_tool on %s" % sf_floating_ip)
            test_utils.start_vxlan_tool(sf_floating_ip)

    def present_results_ssh(self):
        """Check whether the connection between server and client using
        SSH protocol is blocked or not.

        :return: The results for the specific action of the scenario
        """

        logger.info("Test SSH")
        if test_utils.is_ssh_blocked(self.client_floating_ip, self.server_ip):
            results.add_to_summary(2, "PASS", "SSH Blocked")
        else:
            error = ('\033[91mTEST [FAILED] ==> SSH NOT BLOCKED\033[0m')
            logger.error(error)
            test_utils.capture_ovs_logs(
                self.ovs_logger, self.controller_clients, self.compute_clients,
                error)
            results.add_to_summary(2, "FAIL", "SSH Works")

        return results

    def present_results_allowed_ssh(self):
        """Check whether the connection between server and client using
        SSH protocol is available or not.

        :return: The results for the specific action of the scenario
        """

        logger.info("Test SSH")
        if not test_utils.is_ssh_blocked(self.client_floating_ip,
                                         self.server_ip):
            results.add_to_summary(2, "PASS", "SSH works")
        else:
            error = ('\033[91mTEST [FAILED] ==> SSH BLOCKED\033[0m')
            logger.error(error)
            test_utils.capture_ovs_logs(
                self.ovs_logger, self.controller_clients, self.compute_clients,
                error)
            results.add_to_summary(2, "FAIL", "SSH is blocked")

        return results

    def remove_vnffg(self, par_vnffg_name, par_vnffgd_name):
        """Delete the vnffg and the vnffgd items that have been created
        during the test scenario.

        :param par_vnffg_name: The vnffg name of network components
        :param par_vnffgd_name: The vnffgd name of network components
        :return: Remove the vnffg and vnffgd components
        """

        os_sfc_utils.delete_vnffg(self.tacker_client,
                                  vnffg_name=par_vnffg_name)

        os_sfc_utils.delete_vnffgd(self.tacker_client,
                                   vnffgd_name=par_vnffgd_name)

    def create_vnffg(self, testcase_config_name, vnf_name, conn_name):
        """Create the vnffg components following the instructions from
        relevant templates.

        :param testcase_config_name: The config input of the test case
        :param vnf_name: The name of the vnf
        :param conn_name: Protocol type / name of the component
        :return: Create the vnffg component
        """

        tosca_file = os.path.join(COMMON_CONFIG.sfc_test_dir,
                                  COMMON_CONFIG.vnffgd_dir,
                                  testcase_config_name)

        os_sfc_utils.create_vnffgd(self.tacker_client,
                                   tosca_file=tosca_file,
                                   vnffgd_name=vnf_name)

        self.neutron_port = openstack_sfc.get_client_port(self.client_instance,
                                                          self.client_creator)
        os_sfc_utils.create_vnffg_with_param_file(self.tacker_client, vnf_name,
                                                  conn_name,
                                                  self.default_param_file,
                                                  self.neutron_port.id)

    def present_results_http(self):
        """Check whether the connection between server and client using
        HTTP protocol is blocked or not.

        :return: The results for the specific action of the scenario
        """

        logger.info("Test HTTP")
        if test_utils.is_http_blocked(self.client_floating_ip, self.server_ip):
            results.add_to_summary(2, "PASS", "HTTP Blocked")
        else:
            error = ('\033[91mTEST [FAILED] ==> HTTP WORKS\033[0m')
            logger.error(error)
            test_utils.capture_ovs_logs(
                self.ovs_logger, self.controller_clients, self.compute_clients,
                error)
            results.add_to_summary(2, "FAIL", "HTTP works")

        return results

    def present_results_allowed_port_http(self, testcase_config):
        """Check whether the connection between server and client using
        HTTP protocol and for a specific port is available or not.

        :param testcase_config: The config input of the test case
        :return: The results for the specific action of the scenario
        """

        allowed_port = testcase_config.source_port
        logger.info("Test if HTTP from port %s works" % allowed_port)
        if not test_utils.is_http_blocked(
                self.client_floating_ip, self.server_ip, allowed_port):
            results.add_to_summary(2, "PASS", "HTTP works")
        else:
            error = ('\033[91mTEST [FAILED] ==> HTTP BLOCKED\033[0m')
            logger.error(error)
            test_utils.capture_ovs_logs(
                self.ovs_logger, self.controller_clients, self.compute_clients,
                error)
            results.add_to_summary(2, "FAIL", "HTTP is blocked")

        return results

    def present_results_blocked_port_http(self, testcase_config,
                                          test='HTTP'):
        """Check whether the connection between server and client using
        HTTP protocol and for a specific port is blocked or not.

        :param testcase_config: The config input of the test case
        :param test: custom test string to print on result summary
        :return: The results for the specific action of the scenario
        """

        allowed_port = testcase_config.source_port
        logger.info("Test if HTTP from port %s doesn't work" % allowed_port)
        if test_utils.is_http_blocked(
                self.client_floating_ip, self.server_ip, allowed_port):
            results.add_to_summary(2, "PASS", test + " blocked")
        else:
            error = ('\033[91mTEST [FAILED] ==> HTTP WORKS\033[0m')
            logger.error(error)
            test_utils.capture_ovs_logs(
                self.ovs_logger, self.controller_clients, self.compute_clients,
                error)
            results.add_to_summary(2, "FAIL", test + " works")

        return results

    def create_chain(self, testcase_config):
        """Create a connection chain for the test scenario purposes

        :param testcase_config: The config input of the test case
        :return: Create the proper chain for the specific test scenario
        """

        self.neutron_port = openstack_sfc.get_client_port(self.client_instance,
                                                          self.client_creator)
        odl_utils.create_chain(self.tacker_client, self.default_param_file,
                               self.neutron_port, COMMON_CONFIG,
                               testcase_config)

    def check_deletion(self):
        """Check that the deletion of the chain has been completed sucessfully.

        :return: Check that the chain has been completed deleted without
                 leftovers.
        """

        if not odl_utils.\
                check_vnffg_deletion(self.odl_ip, self.odl_port,
                                     self.ovs_logger,
                                     [self.neutron_port],
                                     self.client_instance.compute_host,
                                     self.compute_nodes):
            logger.debug("The chains were not correctly removed")
            raise Exception("Chains not correctly removed, test failed")

    def present_results_allowed_http(self):
        """Check whether the connection between server and client using
        HTTP protocol is available or not.

        :return: The results for the specific action of the scenario
        """

        if not test_utils.is_http_blocked(self.client_floating_ip,
                                          self.server_ip):
            results.add_to_summary(2, "PASS", "HTTP works")
        else:
            error = ('\033[91mTEST [FAILED] ==> HTTP BLOCKED\033[0m')
            logger.error(error)
            test_utils.capture_ovs_logs(
                self.ovs_logger, self.controller_clients, self.compute_clients,
                error)
            results.add_to_summary(2, "FAIL", "HTTP is blocked")

        return results

    def vxlan_blocking_start(self, floating_ip, port_blocked):
        """Start the vxlan tool for one floating IP and blocking
           a specific port.

        :param floating_ip: Floating IP
        :param port_blocked: Port
        :return: The port for the floating IP is blocked
        """

        test_utils.stop_vxlan_tool(floating_ip)
        logger.info("Starting HTTP firewall on %s" % floating_ip)
        test_utils.start_vxlan_tool(floating_ip, block=port_blocked)

    def vxlan_blocking_stop(self, floating_ip):
        """Stop the vxlan tool for a specific IP

        :param floating_ip: Floating IP
        :return: The vxlan tool for the specific floating IP is stopped
        """

        logger.info("Starting HTTP firewall on %s" % floating_ip)
        test_utils.stop_vxlan_tool(floating_ip)

    def vxlan_start_interface(self, floating_ip, interface, output, block):
        """Start the vxlan tool for one floating IP and blocking
           a specific interface.

        :param floating_ip: Floating IP
        :param interface: Interface
        :param output: output interface
        :param block: port
        :return: The interface or/and port for specific floating IP is blocked
        """

        logger.info("Starting vxlan_tool on %s" % floating_ip)
        test_utils.start_vxlan_tool(floating_ip, interface=interface,
                                    output=output, block=block)
