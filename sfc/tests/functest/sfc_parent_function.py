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
CLIENT = "client"
SERVER = "server"
openstack_sfc = os_sfc_utils.OpenStackSFC()
COMMON_CONFIG = sfc_config.CommonConfig()
results = Results(COMMON_CONFIG.line_length)


class SFCCommonTestCase(object):

    def preparation_openstack(self, testcase_config, logger,
                              supported_installers):
        """ Prepare the testcase environment and the components
        that the test scenario is going to use later on.
        Input : testcase_config,  logger, supported_installers
        Output : ovs_logger, network, router, sg, image_creator,
        creators
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

        compute_nodes = [node for node in openstack_nodes
                         if node.is_compute()]

        for compute in compute_nodes:
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

        tacker_client = os_sfc_utils.get_tacker_client()
        os_sfc_utils.register_vim(tacker_client,
                                  vim_file=COMMON_CONFIG.vim_file)

        ovs_logger = ovs_log.OVSLogger(
            os.path.join(COMMON_CONFIG.sfc_test_dir, 'ovs-logs'),
            COMMON_CONFIG.functest_results_dir)

        network, router = openstack_sfc.create_network_infrastructure(
            testcase_config.net_name,
            testcase_config.subnet_name,
            testcase_config.subnet_cidr,
            testcase_config.router_name)

        sg = openstack_sfc.create_security_group(testcase_config.secgroup_name)

        image_creator = openstack_sfc.register_glance_image(
            COMMON_CONFIG.image_name,
            COMMON_CONFIG.image_url,
            COMMON_CONFIG.image_format,
            'public')

        return ovs_logger, network, router, sg, image_creator, openstack_sfc\
            .creators

    def create_custom_vnfd(self, tacker_client, test_case_name, vnfd_name):
        """ Create VNF Descriptor (VNFD)
        Input : tacker_client, test_case_name, vnfd_name
        Output : -
        """

        tosca_file = os.path.join(COMMON_CONFIG.sfc_test_dir,
                                  COMMON_CONFIG.vnfd_dir, test_case_name)

        os_sfc_utils.create_vnfd(tacker_client,
                                 tosca_file=tosca_file,
                                 vnfd_name=vnfd_name)

    def create_custom_av(self, tacker_client, vnf_names, av_member1,
                         av_member2, test_topology):
        """ Create custom 'av'
        Input : tacker_client, vnf_names, av_member1, av_member2
                test_topology):
        Output : -
        """
        default_param_file = os.path.join(
            COMMON_CONFIG.sfc_test_dir,
            COMMON_CONFIG.vnfd_dir,
            COMMON_CONFIG.vnfd_default_params_file)

        logger.info('This test is run with the topology {0}'.
                    format(test_topology['id']))
        logger.info('Topology description: {0}'
                    .format(test_topology['description']))

        os_sfc_utils.create_vnf_in_av_zone(
            tacker_client, vnf_names, av_member1, av_member2,
            default_param_file, test_topology[vnf_names])

        vnf_id = os_sfc_utils.wait_for_vnf(tacker_client, vnf_name=vnf_names)
        if vnf_id is None:
            logger.error('ERROR while booting vnfs')
            sys.exit(1)

    def prepare_server_client_vm(self, image_creator, vnf_names, topo_seed,
                                 network, sg):
        """ Prepare server and client in the VMs
        Input : image_creator, vnf_names, topo_seed, network,
                sg
        Output : server_instance, server_creator, client_instance,
                 client_creator
        """

        test_topology = topo_shuffler.topology(vnf_names, openstack_sfc,
                                               seed=topo_seed)

        server_instance, server_creator = openstack_sfc.create_instance(
            SERVER, COMMON_CONFIG.flavor, image_creator, network, sg,
            av_zone=test_topology['server'])

        client_instance, client_creator = openstack_sfc.create_instance(
            CLIENT, COMMON_CONFIG.flavor, image_creator, network, sg,
            av_zone=test_topology['client'])

        return server_instance, server_creator, client_instance, client_creator

    def assign_floating_ip(self, router, client_instance, client_creator,
                           server_instance, server_creator):
        """ Assign floating IPs on the router about server and the client
            instances
        Input : router, client_instance, client_creator, server_instance,
                server_creator):
        Output : server_floating_ip, client_floating_ip
        """

        logger.info("Assigning floating IPs to instances")

        client_floating_ip = openstack_sfc.assign_floating_ip(router,
                                                              client_instance,
                                                              client_creator)
        server_floating_ip = openstack_sfc.assign_floating_ip(router,
                                                              server_instance,
                                                              server_creator)

        return server_floating_ip, client_floating_ip

    def custom_sf_floating_ip(self, router):
        """Assign floating IPs to service function
        Input : router
        Output:  sf1_floating_ip, sf2_floating_ip
        """

        logger.info("Assigning floating IPs to service functions")

        fips_sfs = openstack_sfc.assign_floating_ip_vnfs(router)
        sf1_floating_ip = fips_sfs[0]
        sf2_floating_ip = fips_sfs[1]

        return sf1_floating_ip, sf2_floating_ip

    def check_floating_ips(self, fips, sf1_floating_ip, sf2_floating_ip,
                           odl_ip, odl_port):
        """Check the responsivness of the floating IPs
        Input : fips, sf1_floating_ip, sf2_floating_ip, odl_ip, odl_port
        Output : -
        """

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

    def start_services_in_vm(self, server_floating_ip, sf1_floating_ip,
                             sf2_floating_ip):
        """Start the HTTP server in the server VM and
           Start the vxlan tool in the SFs
           Input: server_floating_ip, sf1_floating_ip, sf2_floating_ip
           Output : -
        """

        logger.info("Starting HTTP server on %s" % server_floating_ip)
        if not test_utils.start_http_server(server_floating_ip):
            logger.error('\033[91mFailed to start HTTP server on %s\033[0m'
                         % server_floating_ip)
            sys.exit(1)

        for sf_floating_ip in (sf1_floating_ip, sf2_floating_ip):
            logger.info("Starting vxlan_tool on %s" % sf_floating_ip)
            test_utils.start_vxlan_tool(sf_floating_ip)

    def present_results_ssh(self, server_instance, compute_nodes,
                            client_floating_ip, ovs_logger, openstack_nodes):
        """Check whether the connection between server and client using
           SSH protocol is blocked or not.
           Input : server_instance, compute_nodes, client_floating_ip,
                   ovs_logger, openstack_nodes
           Output : results
        """

        server_ip = server_instance.ports[0].ips[0]['ip_address']
        controller_nodes = [node for node in openstack_nodes
                            if node.is_controller()]
        controller_clients = test_utils.get_ssh_clients(controller_nodes)
        compute_clients = test_utils.get_ssh_clients(compute_nodes)

        logger.info("Test SSH")
        if test_utils.is_ssh_blocked(client_floating_ip, server_ip):
            results.add_to_summary(2, "PASS", "SSH Blocked")
        else:
            error = ('\033[91mTEST 1 [FAILED] ==> SSH NOT BLOCKED\033[0m')
            logger.error(error)
            test_utils.capture_ovs_logs(
                ovs_logger, controller_clients, compute_clients, error)
            results.add_to_summary(2, "FAIL", "SSH Blocked")

        return results

    def remove_vnffg(self, tacker_client, par_vnffg_name, par_vnffgd_name):
        """Delete the vnffg and the vnffgd items that have been created
           during the test scenario.
           Input : tacker_client, par_vnffg_name, par_vnffgd_name
           Output : -
        """

        os_sfc_utils.delete_vnffg(tacker_client, vnffg_name=par_vnffg_name)

        os_sfc_utils.delete_vnffgd(tacker_client, vnffgd_name=par_vnffgd_name)

    def create_vnffg(self, testcase_config, tacker_client, client_instance,
                     client_creator, vnf_name, conn_name):
        """Create the vnffg components following the instructions from
           relevant templates.
           Input : testcase_config, tacker_client, client_instance,
                   client_creator, vnf_name, conn_name
           Output : -
        """

        default_param_file = os.path.join(
            COMMON_CONFIG.sfc_test_dir,
            COMMON_CONFIG.vnfd_dir,
            COMMON_CONFIG.vnfd_default_params_file)

        tosca_file = os.path.join(COMMON_CONFIG.sfc_test_dir,
                                  COMMON_CONFIG.vnffgd_dir,
                                  testcase_config.test_vnffgd_red)

        os_sfc_utils.create_vnffgd(tacker_client,
                                   tosca_file=tosca_file,
                                   vnffgd_name=vnf_name)

        neutron_port = openstack_sfc.get_client_port(client_instance,
                                                     client_creator)
        os_sfc_utils.create_vnffg_with_param_file(tacker_client, vnf_name,
                                                  conn_name,
                                                  default_param_file,
                                                  neutron_port.id)

    def present_results_http(self, client_floating_ip, server_instance,
                             ovs_logger, compute_nodes, openstack_nodes):
        """Check whether the connection between server and client using
           HTTP protocol is blocked or not.
           Input : server_instance, compute_nodes, client_floating_ip,
                   ovs_logger, openstack_nodes
           Output : results
        """

        server_ip = server_instance.ports[0].ips[0]['ip_address']
        controller_nodes = [node for node in openstack_nodes
                            if node.is_controller()]
        controller_clients = test_utils.get_ssh_clients(controller_nodes)
        compute_clients = test_utils.get_ssh_clients(compute_nodes)

        logger.info("Test HTTP")
        if test_utils.is_http_blocked(client_floating_ip, server_ip):
            results.add_to_summary(2, "PASS", "HTTP Blocked")
        else:
            error = ('\033[91mTEST 3 [FAILED] ==> HTTP WORKS\033[0m')
            logger.error(error)
            test_utils.capture_ovs_logs(
                ovs_logger, controller_clients, compute_clients, error)
            results.add_to_summary(2, "FAIL", "HTTP Blocked")

        return results

    def get_installer_deployment_nodes(self):
        """ Get the needed for test scenario information from installer.
            Input : -
            Output : compute_nodes, controller_nodes
        """
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

    def get_deployment_odl(self):
        """Get the needed for test scenario information from OpenDayLight
           deployment.
           Input : -
           Output : odl_ip, odl_port, deployment_handler
        """
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
        """Prepare the information related to the topology. This
           will be used as input to the following methods.
           Input : vnfs
           Output : test_topology, topo_seed
        """

        topo_seed = topo_shuffler.get_seed()
        test_topology = topo_shuffler.topology(vnfs, openstack_sfc,
                                               seed=topo_seed)

        return test_topology, topo_seed

    def prepare_client_resources(self, compute_nodes, controller_nodes):
        """Prepare the information related to the client resources.
           This will be used as input to the following methods.
           Input : compute_nodes, controller_nodes
           Output : compute_clients, controller_clients
        """

        controller_clients = test_utils.get_ssh_clients(controller_nodes)
        compute_clients = test_utils.get_ssh_clients(compute_nodes)

        return compute_clients, controller_clients

    def present_results_allowed_port_http(self, testcase_config,
                                          client_floating_ip, server_instance,
                                          ovs_logger, compute_nodes,
                                          openstack_nodes):
        """Check whether the connection between server and client using
           HTTP protocol and for a specific port is available or not.
           Input : server_instance, compute_nodes, client_floating_ip,
                   ovs_logger, openstack_nodes, testcase_config
           Output : results
        """

        server_ip = server_instance.ports[0].ips[0]['ip_address']
        controller_nodes = [node for node in openstack_nodes
                            if node.is_controller()]
        controller_clients = test_utils.get_ssh_clients(controller_nodes)
        compute_clients = test_utils.get_ssh_clients(compute_nodes)

        allowed_port = testcase_config.allowed_source_port
        logger.info("Test if HTTP from port %s works" % allowed_port)
        if not test_utils.is_http_blocked(
                client_floating_ip, server_ip, allowed_port):
            results.add_to_summary(2, "PASS", "HTTP works")
        else:
            error = ('\033[91mTEST 1 [FAILED] ==> HTTP BLOCKED\033[0m')
            logger.error(error)
            test_utils.capture_ovs_logs(
                ovs_logger, controller_clients, compute_clients, error)
            results.add_to_summary(2, "FAIL", "HTTP works")

        return results

    def create_chain(self, testcase_config, client_instance, client_creator):
        """Create a connection chain for the test scenario purposes
           Input : testcase_config, client_instance, client_creator
           Output : -
        """

        default_param_file = os.path.join(
            COMMON_CONFIG.sfc_test_dir,
            COMMON_CONFIG.vnfd_dir,
            COMMON_CONFIG.vnfd_default_params_file)

        tacker_client = os_sfc_utils.get_tacker_client()

        neutron_port = openstack_sfc.get_client_port(client_instance,
                                                     client_creator)
        odl_utils.create_chain(tacker_client, default_param_file, neutron_port,
                               COMMON_CONFIG, testcase_config)

    def check_deletion(self, odl_ip, odl_port, ovs_logger, compute_nodes,
                       openstack_client):
        """Check that of the chain has been completed sucessfully.
           Input : odl_ip, odl_port, ovs_logger, compute_nodes,
                   openstack_client
           Output : -
        """

        if not odl_utils.check_vnffg_deletion(odl_ip, odl_port, ovs_logger,
                                              openstack_client,
                                              compute_nodes):
            logger.debug("The chains were not correctly removed")
            raise Exception("Chains not correctly removed, test failed")

    def present_results_allowed_http(self, client_floating_ip, server_instance,
                                     ovs_logger, compute_nodes,
                                     openstack_nodes):
        """Check whether the connection between server and client using
           HTTP protocol is available or not.
           Input : server_instance, compute_nodes, client_floating_ip,
                   ovs_logger, openstack_nodes
           Output : results
        """

        server_ip = server_instance.ports[0].ips[0]['ip_address']
        controller_nodes = [node for node in openstack_nodes
                            if node.is_controller()]
        controller_clients = test_utils.get_ssh_clients(controller_nodes)
        compute_clients = test_utils.get_ssh_clients(compute_nodes)

        if not test_utils.is_http_blocked(client_floating_ip, server_ip):
            results.add_to_summary(2, "PASS", "HTTP works")
        else:
            error = ('\033[91mTEST 1 [FAILED] ==> HTTP BLOCKED\033[0m')
            logger.error(error)
            test_utils.capture_ovs_logs(
                ovs_logger, controller_clients, compute_clients, error)
            results.add_to_summary(2, "FAIL", "HTTP works")

        return results

    def vxlan_blocking_change(self, floating_ip, port_blocked):
        """ Start the vxlan tool for one floating IP and blocking
            a specific port.
            Input : floating_ip, port_blocked
            Output : -
        """

        test_utils.stop_vxlan_tool(floating_ip)
        logger.info("Starting HTTP firewall on %s" % floating_ip)
        test_utils.start_vxlan_tool(floating_ip, block=port_blocked)

    def vxlan_blocking_stop(self, floating_ip):
        """Stop the vxlan tool for a specific IP
           Input : floating_ip
           Output : -
        """

        logger.info("Starting HTTP firewall on %s" % floating_ip)
        test_utils.stop_vxlan_tool(floating_ip)

    def get_openstack_nodes(self, deployment_handler):
        """Get openstack nodes information. This will be used as
           input to the following methods.
           Input : deployment_handler
           Output : openstack_nodes
        """

        cluster = COMMON_CONFIG.installer_cluster
        openstack_nodes = (deployment_handler.get_nodes({'cluster': cluster})
                           if cluster is not None
                           else deployment_handler.get_nodes())

        return openstack_nodes