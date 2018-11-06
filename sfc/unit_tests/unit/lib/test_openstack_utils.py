#!/usr/bin/env python

###############################################################################
# Copyright (c) 2018 Venkata Harshavardhan Reddy Allu and others.
#
# All rights reserved. This program and the accompanying materials
# are made available under the terms of the Apache License, Version 2.0
# which accompanies this distribution, and is available at
# http://www.apache.org/licenses/LICENSE-2.0
###############################################################################

import unittest

from mock import call
from mock import Mock
from mock import patch
from mock import DEFAULT

import sfc.lib.openstack_utils as os_sfc_utils
from tackerclient.v1_0 import client as tacker_client

__author__ = "Harshavardhan Reddy <venkataharshavardhan_ven@srmuniv.edu.in>"


class SfcOpenStackUtilsTesting(unittest.TestCase):

    def setUp(self):
        self.patcher1 = patch.object(os_sfc_utils.constants,
                                     'ENV_FILE', autospec=True)
        self.patcher2 = patch.object(os_sfc_utils.openstack_tests,
                                     'get_credentials', autospec=True)
        self.patcher3 = patch.object(os_sfc_utils.nova_utils,
                                     'nova_client', autospec=True)
        self.patcher4 = patch.object(os_sfc_utils.neutron_utils,
                                     'neutron_client', autospec=True)
        self.patcher5 = patch.object(os_sfc_utils.heat_utils,
                                     'heat_client', autospec=True)
        self.patcher6 = patch.object(os_sfc_utils.keystone_utils,
                                     'keystone_client', autospec=True)

        self.env_file = self.patcher1.start().return_value
        self.os_creds = self.patcher2.start().return_value
        self.nova = self.patcher3.start().return_value
        self.neutron = self.patcher4.start().return_value
        self.heat = self.patcher5.start().return_value
        self.keystone = self.patcher6.start().return_value

        self.os_sfc = os_sfc_utils.OpenStackSFC()

    def tearDown(self):
        self.patcher1.stop()
        self.patcher2.stop()
        self.patcher3.stop()
        self.patcher4.stop()
        self.patcher5.stop()
        self.patcher6.stop()

    @patch('sfc.lib.openstack_utils.logger', autospec=True)
    @patch('sfc.lib.openstack_utils.ImageConfig', autospec=True)
    @patch('sfc.lib.openstack_utils.OpenStackImage', autospec=True)
    def test_register_glance_image_is_local(self,
                                            mock_openstack_image,
                                            mock_image_config,
                                            mock_log):
        """
        Checks the proper functionality of register_glance_image
        function when the image is local
        """

        mock_os_image_ins = mock_openstack_image.return_value
        mock_image_config_ins = mock_image_config.return_value
        log_calls = [call('Registering the image...')]

        result = self.os_sfc.register_glance_image('name',
                                                   'url',
                                                   'img_format',
                                                   'public')
        assert result is mock_os_image_ins
        mock_log.info.assert_has_calls(log_calls)
        mock_image_config.assert_called_once_with(name='name',
                                                  img_format='img_format',
                                                  image_file='url',
                                                  public='public',
                                                  image_user='admin')

        mock_openstack_image.assert_called_with(self.os_creds,
                                                mock_image_config_ins)
        mock_os_image_ins.create.assert_called_once_with()
        self.assertEqual([mock_os_image_ins], self.os_sfc.creators)

    @patch('sfc.lib.openstack_utils.logger', autospec=True)
    @patch('sfc.lib.openstack_utils.ImageConfig', autospec=True)
    @patch('sfc.lib.openstack_utils.OpenStackImage', autospec=True)
    def test_register_glance_image_is_not_local(self,
                                                mock_openstack_image,
                                                mock_image_config,
                                                mock_log):
        """
        Checks the proper functionality of register_glance_image
        function when the image is not local
        """

        mock_os_image_ins = mock_openstack_image.return_value
        mock_image_config_ins = mock_image_config.return_value
        log_calls = [call('Registering the image...')]

        result = self.os_sfc.register_glance_image('name',
                                                   'http://url',
                                                   'img_format',
                                                   'public')
        assert result is mock_os_image_ins
        mock_log.info.assert_has_calls(log_calls)
        mock_image_config.assert_called_with(name='name',
                                             img_format='img_format',
                                             url='http://url',
                                             public='public',
                                             image_user='admin')

        mock_openstack_image.assert_called_with(self.os_creds,
                                                mock_image_config_ins)
        mock_os_image_ins.create.assert_called_once_with()
        self.assertEqual([mock_os_image_ins], self.os_sfc.creators)

    @patch('sfc.lib.openstack_utils.logger', autospec=True)
    @patch('sfc.lib.openstack_utils.FlavorConfig', autospec=True)
    @patch('sfc.lib.openstack_utils.OpenStackFlavor', autospec=True)
    def test_create_flavour(self,
                            mock_openstack_flavor,
                            mock_flavor_config,
                            mock_log):
        """
        Checks the proper functionality of create_flavor
        function
        """

        mock_openstack_flavor_ins = mock_openstack_flavor.return_value
        log_calls = [call('Creating the flavor...')]

        result = self.os_sfc.create_flavor('name',
                                           'ram',
                                           'disk',
                                           'vcpus')
        assert result is mock_openstack_flavor_ins.create.return_value
        self.assertEqual([mock_openstack_flavor_ins],
                         self.os_sfc.creators)
        mock_flavor_config.assert_called_once_with(name='name',
                                                   ram='ram',
                                                   disk='disk',
                                                   vcpus='vcpus')
        mock_log.info.assert_has_calls(log_calls)

    @patch('sfc.lib.openstack_utils.logger', autospec=True)
    @patch('sfc.lib.openstack_utils.env.get', autospec=True)
    @patch('sfc.lib.openstack_utils.RouterConfig', autospec=True)
    @patch('sfc.lib.openstack_utils.SubnetConfig', autospec=True)
    @patch('sfc.lib.openstack_utils.NetworkConfig', autospec=True)
    @patch('sfc.lib.openstack_utils.OpenStackRouter', autospec=True)
    @patch('sfc.lib.openstack_utils.OpenStackNetwork', autospec=True)
    def test_create_network_infrastructure(self,
                                           mock_openstack_network,
                                           mock_openstack_router,
                                           mock_network_config,
                                           mock_subnet_config,
                                           mock_router_config,
                                           mock_env_get,
                                           mock_log):
        """
        Checks the proper functionality of create_network_infrastructure
        function
        """

        net_ins = mock_openstack_network.return_value
        rou_ins = mock_openstack_router.return_value
        nec_ins = mock_network_config.return_value
        sub_ins = mock_subnet_config.return_value
        roc_ins = mock_router_config.return_value
        mock_env_get.return_value = 'nw_name'
        expected = (net_ins.create.return_value, rou_ins.create.return_value)
        log_calls = [call('Creating networks...'),
                     call('Creating the router...')]

        result = self.os_sfc.create_network_infrastructure('net_name',
                                                           'sn_name',
                                                           'subnet_cdir',
                                                           'router_name')
        self.assertEqual(expected, result)
        mock_subnet_config.assert_called_once_with(name='sn_name',
                                                   cidr='subnet_cdir')
        mock_network_config.assert_called_once_with(name='net_name',
                                                    subnet_settings=[sub_ins])
        mock_openstack_network.assert_called_once_with(self.os_creds,
                                                       nec_ins)
        mock_env_get.assert_called_once_with('EXTERNAL_NETWORK')
        mock_router_config.assert_called_once_with(name='router_name',
                                                   external_gateway='nw_name',
                                                   internal_subnets=['sn_name']
                                                   )
        mock_openstack_router.assert_called_once_with(self.os_creds, roc_ins)
        self.assertEqual([net_ins, rou_ins], self.os_sfc.creators)
        mock_log.info.assert_has_calls(log_calls)

    @patch('sfc.lib.openstack_utils.logger', autospec=True)
    @patch('sfc.lib.openstack_utils.Protocol', autospec=True)
    @patch('sfc.lib.openstack_utils.Direction', autospec=True)
    @patch('sfc.lib.openstack_utils.SecurityGroupConfig', autospec=True)
    @patch('sfc.lib.openstack_utils.OpenStackSecurityGroup', autospec=True)
    @patch('sfc.lib.openstack_utils.SecurityGroupRuleConfig', autospec=True)
    def test_create_security_group(self,
                                   mock_security_group_rule_config,
                                   mock_openstack_security_group,
                                   mock_security_group_config,
                                   mock_direction,
                                   mock_protocol,
                                   mock_log):
        """
        Checks the proper functionality of create_security_group
        function
        """

        oss_gro_ins = mock_openstack_security_group.return_value
        sec_gro_con_ins = mock_security_group_config.return_value
        mock_security_group_rule_config.side_effect = ['ping', 'ssh', 'http']
        ins = ['ping', 'ssh', 'http']

        sgrc_calls = [call(sec_grp_name='sec_grp_name',
                           direction=mock_direction.ingress,
                           protocol=mock_protocol.icmp),
                      call(sec_grp_name='sec_grp_name',
                           direction=mock_direction.ingress,
                           protocol=mock_protocol.tcp,
                           port_range_min=22,
                           port_range_max=22),
                      call(sec_grp_name='sec_grp_name',
                           direction=mock_direction.ingress,
                           protocol=mock_protocol.tcp,
                           port_range_min=80,
                           port_range_max=80)]

        log_calls = [call('Creating the security groups...')]

        result = self.os_sfc.create_security_group('sec_grp_name')
        assert result is oss_gro_ins.create.return_value
        self.assertEqual([oss_gro_ins], self.os_sfc.creators)
        mock_security_group_config.assert_called_once_with(name='sec_grp_name',
                                                           rule_settings=ins)
        mock_security_group_rule_config.assert_has_calls(sgrc_calls)
        mock_openstack_security_group.assert_called_once_with(self.os_creds,
                                                              sec_gro_con_ins)
        oss_gro_ins.create.assert_called_with()
        mock_log.info.assert_has_calls(log_calls)

    @patch('sfc.lib.openstack_utils.logger', autospec=True)
    @patch('sfc.lib.openstack_utils.PortConfig', autospec=True)
    @patch('sfc.lib.openstack_utils.VmInstanceConfig', autospec=True)
    @patch('sfc.lib.openstack_utils.cr_inst.OpenStackVmInstance',
           autospec=True)
    def test_create_instance_port_security_false(self,
                                                 mock_os_vm_instance,
                                                 mock_vm_instance_config,
                                                 mock_port_config,
                                                 mock_log):
        """
        Checks the proper functionality of create_instance
        function
        """

        vm_con_ins = mock_vm_instance_config.return_value
        pc_inss = ['pc_config1', 'pc_config2']
        mock_port_config.side_effect = pc_inss
        os_vm_ins = mock_os_vm_instance.return_value
        os_vm_ins_cre = os_vm_ins.create.return_value
        expected = (os_vm_ins_cre, os_vm_ins)
        secgrp = Mock()
        secgrp.name = 'sec_grp'
        network = Mock()
        network.name = 'nw_name'
        img_cre = Mock()
        img_cre.image_settings = 'image_settings'

        log_calls = [call('Creating the instance vm_name...')]
        pc_calls = [call(name='port1',
                         network_name='nw_name',
                         port_security_enabled=False),
                    call(name='port2',
                         network_name='nw_name',
                         port_security_enabled=False)]
        result = self.os_sfc.create_instance('vm_name',
                                             'flavor_name',
                                             img_cre,
                                             network,
                                             secgrp,
                                             'av_zone',
                                             ['port1', 'port2'],
                                             port_security=False)
        self.assertEqual(expected, result)
        mock_vm_instance_config.assert_called_once_with(name='vm_name',
                                                        flavor='flavor_name',
                                                        port_settings=pc_inss,
                                                        availability_zone='av'
                                                        '_zone')
        mock_os_vm_instance.assert_called_once_with(self.os_creds,
                                                    vm_con_ins,
                                                    'image_settings')
        self.assertEqual([os_vm_ins], self.os_sfc.creators)
        mock_log.info.assert_has_calls(log_calls)
        mock_port_config.assert_has_calls(pc_calls)

    @patch('sfc.lib.openstack_utils.logger', autospec=True)
    @patch('sfc.lib.openstack_utils.PortConfig', autospec=True)
    @patch('sfc.lib.openstack_utils.VmInstanceConfig', autospec=True)
    @patch('sfc.lib.openstack_utils.cr_inst.OpenStackVmInstance',
           autospec=True)
    def test_create_instance(self,
                             mock_os_vm_instance,
                             mock_vm_instance_config,
                             mock_port_config,
                             mock_log):
        """
        Checks the proper functionality of create_instance
        function
        """

        vm_con_ins = mock_vm_instance_config.return_value
        pc_inss = ['pc_config1', 'pc_config2']
        mock_port_config.side_effect = pc_inss
        os_vm_ins = mock_os_vm_instance.return_value
        os_vm_ins_cre = os_vm_ins.create.return_value
        expected = (os_vm_ins_cre, os_vm_ins)
        secgrp = Mock()
        secgrp.name = 'sec_grp'
        network = Mock()
        network.name = 'nw_name'
        img_cre = Mock()
        img_cre.image_settings = 'image_settings'

        log_calls = [call('Creating the instance vm_name...')]
        pc_calls = [call(name='port1',
                         network_name='nw_name',
                         port_security_enabled=True),
                    call(name='port2',
                         network_name='nw_name',
                         port_security_enabled=True)]
        result = self.os_sfc.create_instance('vm_name',
                                             'flavor_name',
                                             img_cre,
                                             network,
                                             secgrp,
                                             'av_zone',
                                             ['port1', 'port2'])
        self.assertEqual(expected, result)
        mock_vm_instance_config.assert_called_once_with(name='vm_name',
                                                        flavor='flavor_name',
                                                        security_group_names=''
                                                        'sec_grp',
                                                        port_settings=pc_inss,
                                                        availability_zone='av'
                                                        '_zone')
        mock_os_vm_instance.assert_called_once_with(self.os_creds,
                                                    vm_con_ins,
                                                    'image_settings')
        self.assertEqual([os_vm_ins], self.os_sfc.creators)
        mock_log.info.assert_has_calls(log_calls)
        mock_port_config.assert_has_calls(pc_calls)

    @patch('sfc.lib.openstack_utils.nova_utils.get_hypervisor_hosts',
           autospec=True)
    def test_get_av_zones(self, mock_get_hypervisor_hosts):
        """
        Checks the proper functionality of get_av_zone
        function
        """

        mock_get_hypervisor_hosts.return_value = ['host1', 'host2']
        result = self.os_sfc.get_av_zones()
        mock_get_hypervisor_hosts.assert_called_once_with(self.nova)
        self.assertEqual(['nova::host1', 'nova::host2'], result)

    @patch('sfc.lib.openstack_utils.OpenStackSFC.get_vm_compute',
           autospec=True, return_value='mock_client')
    def test_compute_client(self, mock_get_vm_compute):
        """
        Checks the proper functionality of get_compute_client
        function
        """

        result = self.os_sfc.get_compute_client()
        self.assertEqual('mock_client', result)
        mock_get_vm_compute.assert_called_once_with(self.os_sfc, 'client')

    @patch('sfc.lib.openstack_utils.OpenStackSFC.get_vm_compute',
           autospec=True, return_value='mock_server')
    def test_get_compute_server(self, mock_get_vm_compute):
        """
        Checks the proper functionality of get_compute_server
        function
        """

        result = self.os_sfc.get_compute_server()
        self.assertEqual('mock_server', result)
        mock_get_vm_compute.assert_called_once_with(self.os_sfc, 'server')

    def test_get_vm_compute_raised_exception(self):
        """
        Checks the proper functionality of get_vm_compute
        function when no VM with the given name is found
        """

        ErrorMSG = "There is no VM with name 'mock_vm_name'!!"
        with self.assertRaises(Exception) as cm:
            self.os_sfc.get_vm_compute('mock_vm_name')

        self.assertEqual(cm.exception.message, ErrorMSG)

    def test_get_vm_compute(self):
        """
        Checks the proper functionality of get_vm_compute
        function
        """

        mock_cre_obj_1 = Mock()
        mock_cre_obj_2 = Mock()
        mock_cre_obj_1.get_vm_inst.return_value.name = 'pro_vm'
        mock_cre_obj_2.get_vm_inst.return_value.name = 'dev_vm'
        mock_cre_obj_2.get_vm_inst.return_value.compute_host = 'mock_host'
        self.os_sfc.creators = [mock_cre_obj_1, mock_cre_obj_2]

        result = self.os_sfc.get_vm_compute('dev_vm')
        self.assertEqual('mock_host', result)

    @patch('sfc.lib.openstack_utils.cr_inst.OpenStackVmInstance',
           autospec=True)
    @patch('sfc.lib.openstack_utils.FloatingIpConfig', autospec=True)
    def test_assign_floating_ip(self,
                                mock_floating_ip_config,
                                mock_os_vm):
        """
        Checks the proper functionality of assigning_floating_ip
        function
        """

        mock_router = Mock()
        mock_vm = Mock()
        mock_ip = Mock()
        mock_ip.ip = 'mock_ip'
        mock_router.name = 'mock_router_name'
        mock_vm.name = 'mock_vm_name'
        port_1 = port_2 = Mock()
        port_1.name = 'port_1'
        mock_vm.ports = [port_1, port_2]

        flo_ip_ins = mock_floating_ip_config.return_value
        mock_os_vm_ins = mock_os_vm.return_value
        mock_os_vm_ins.add_floating_ip.return_value = mock_ip
        result = self.os_sfc.assign_floating_ip(mock_router,
                                                mock_vm,
                                                mock_os_vm_ins)
        self.assertEqual('mock_ip', result)
        mock_floating_ip_config.assert_called_once_with(name='mock_vm_name'
                                                        '-float',
                                                        port_name='port_1',
                                                        router_name='mock_'
                                                        'router_name')
        mock_os_vm_ins.add_floating_ip.assert_called_once_with(flo_ip_ins)

    @patch('sfc.lib.openstack_utils.logger', autospec=True)
    @patch('sfc.lib.openstack_utils.heat_utils.get_stack_servers',
           autospec=True)
    @patch('sfc.lib.openstack_utils.cr_inst.generate_creator', autospec=True)
    def test_assign_floating_ip_vnfs_raised_exception_ips_provided(
            self, mock_generate_creator, mock_get_stack_servers, mock_log):
        """
        Checks the proper functionality of assign_floating_ip_vnfs
        function when server name does not have any floating IP assignment
        """

        ErrorMSG = "The VNF server_name-float does not have any suitable" + \
                   " port with ip any of ['floating_ip', 'other_ip'] for" + \
                   " floating IP assignment"
        log_calls = [call(ErrorMSG)]
        self.os_sfc.image_settings = 'image_settings'
        self.heat.stacks.list.return_value = ['stack_obj']
        mock_ips = ['floating_ip', 'other_ip']
        mock_server_obj = Mock()
        mock_port_obj = Mock()
        mock_server_obj.name = 'server_name'
        mock_server_obj.ports = [mock_port_obj]
        mock_port_obj.name = None
        mock_port_obj.ips = [{'ip_address': 'floating_ip'}]
        mock_get_stack_servers.return_value = [mock_server_obj]

        with self.assertRaises(Exception) as cm:
            self.os_sfc.assign_floating_ip_vnfs('router', mock_ips)

        self.assertEqual(cm.exception.message, ErrorMSG)
        mock_get_stack_servers.assert_called_once_with(self.heat,
                                                       self.nova,
                                                       self.neutron,
                                                       self.keystone,
                                                       'stack_obj',
                                                       'admin')
        mock_generate_creator.assert_called_once_with(self.os_creds,
                                                      mock_server_obj,
                                                      'image_settings',
                                                      'admin')
        mock_log.error.assert_has_calls(log_calls)

    @patch('sfc.lib.openstack_utils.logger', autospec=True)
    @patch('sfc.lib.openstack_utils.heat_utils.get_stack_servers',
           autospec=True)
    @patch('sfc.lib.openstack_utils.cr_inst.generate_creator', autospec=True)
    def test_assign_floating_ip_vnfs_raised_exception_ips_not_provided(
            self, mock_generate_creator, mock_get_stack_servers, mock_log):
        """
        Checks the proper functionality of assign_floating_ip_vnfs
        function when server name does not have any floating IP assignment
        """

        ErrorMSG = "The VNF server_name-float does not have any suitable" + \
                   " port  for floating IP assignment"
        log_calls = [call(ErrorMSG)]
        self.os_sfc.image_settings = 'image_settings'
        self.heat.stacks.list.return_value = ['stack_obj']
        mock_server_obj = Mock()
        mock_port_obj = Mock()
        mock_server_obj.name = 'server_name'
        mock_server_obj.ports = [mock_port_obj]
        mock_port_obj.name = None
        mock_port_obj.ips = [{'ip_address': 'floating_ip'}]
        mock_get_stack_servers.return_value = [mock_server_obj]

        with self.assertRaises(Exception) as cm:
            self.os_sfc.assign_floating_ip_vnfs('router')

        mock_get_stack_servers.assert_called_once_with(self.heat,
                                                       self.nova,
                                                       self.neutron,
                                                       self.keystone,
                                                       'stack_obj',
                                                       'admin')
        mock_generate_creator.assert_called_once_with(self.os_creds,
                                                      mock_server_obj,
                                                      'image_settings',
                                                      'admin')
        self.assertEqual(cm.exception.message, ErrorMSG)
        mock_log.error.assert_has_calls(log_calls)

    @patch('sfc.lib.openstack_utils.FloatingIpConfig', autospec=True)
    @patch('sfc.lib.openstack_utils.cr_inst.generate_creator',
           autospec=True)
    @patch('sfc.lib.openstack_utils.heat_utils.get_stack_servers',
           autospec=True)
    def test_assign_floating_ip_vnfs(self,
                                     mock_get_stack_servers,
                                     mock_generate_creator,
                                     mock_floating_ip_config):
        """
        Checks the proper functionality of assign_floating_ip_vnfs
        function
        """

        self.os_sfc.image_settings = 'image_settings'
        self.heat.stacks.list.return_value = ['stack_obj']

        mock_router = Mock()
        mock_server_obj = Mock()
        mock_ip_obj = Mock()
        mock_port_obj = Mock()
        mock_router.name = 'm_router'
        mock_server_obj.name = 'serv_obj'
        mock_server_obj.ports = [mock_port_obj]
        mock_ips = ['floating_ip', 'other_ip']
        mock_ip_obj.ip = 'mocked_ip'
        mock_port_obj.name = 'port_obj'
        mock_port_obj.ips = [{'ip_address': 'floating_ip'}]
        mock_get_stack_servers.return_value = [mock_server_obj]
        mock_os_vm_ins = mock_generate_creator.return_value
        float_ip_ins = mock_floating_ip_config.return_value
        mock_os_vm_ins.add_floating_ip.return_value = mock_ip_obj

        result = self.os_sfc.assign_floating_ip_vnfs(mock_router, mock_ips)
        self.assertEqual(['mocked_ip'], result)
        self.assertEqual([mock_os_vm_ins], self.os_sfc.creators)
        mock_get_stack_servers.assert_called_once_with(self.heat,
                                                       self.nova,
                                                       self.neutron,
                                                       self.keystone,
                                                       'stack_obj', 'admin')
        mock_generate_creator.assert_called_once_with(self.os_creds,
                                                      mock_server_obj,
                                                      'image_settings',
                                                      'admin')
        mock_floating_ip_config.assert_called_once_with(name='serv_obj-float',
                                                        port_name='port_obj',
                                                        router_name='m_router')
        mock_os_vm_ins.add_floating_ip.assert_called_once_with(float_ip_ins)

    @patch('sfc.lib.openstack_utils.logger', autospec=True)
    @patch('sfc.lib.openstack_utils.cr_inst.OpenStackVmInstance',
           autospec=True)
    def test_get_instance_port_raised_exceptioin(self,
                                                 mock_os_vm,
                                                 mock_log):
        """
        Checks the proper functionality of get_client_port
        function when no port is returned
        """

        mock_os_vm_ins = mock_os_vm.return_value
        mock_vm = Mock()
        mock_vm.name = 'mock_vm_name'
        mock_os_vm_ins.get_port_by_name.return_value = None
        ErrorMSG = 'Client VM does not have the desired port'
        log_calls = [call("The VM mock_vm_name does not have any port"
                          " with name mock_vm_name-port")]

        with self.assertRaises(Exception) as cm:
            self.os_sfc.get_instance_port(mock_vm, mock_os_vm_ins)

        self.assertEqual(cm.exception.message, ErrorMSG)
        mock_log.error.assert_has_calls(log_calls)

    @patch('sfc.lib.openstack_utils.logger', autospec=True)
    @patch('sfc.lib.openstack_utils.cr_inst.OpenStackVmInstance',
           autospec=True)
    def test_get_instance_port(self,
                               mock_os_vm,
                               mock_log):
        """
        Checks the proper functionality of get_client_port
        function when no port is returned
        """

        mock_os_vm_ins = mock_os_vm.return_value
        mock_vm = Mock()
        mock_vm.name = 'mock_vm_name'
        mock_os_vm_ins.get_port_by_name.return_value = 'mock_port'
        result = self.os_sfc.get_instance_port(mock_vm, mock_os_vm_ins)
        self.assertEqual('mock_port', result)

    @patch('sfc.lib.openstack_utils.neutron_utils.list_security_groups',
           autospec=True)
    @patch('sfc.lib.openstack_utils.neutron_utils.delete_security_group',
           autospec=True)
    def test_delete_all_security_groups(self,
                                        mock_delete_security_group,
                                        mock_list_security_groups):
        """
        Checks the proper functionality of delete_all_security_groups
        function
        """

        del_calls = [call(self.neutron, 'sec_group_1'),
                     call(self.neutron, 'sec_group_2')]
        mock_list_security_groups.return_value = ['sec_group_1', 'sec_group_2']
        self.os_sfc.delete_all_security_groups()
        mock_list_security_groups.assert_called_once_with(self.neutron)
        mock_delete_security_group.assert_has_calls(del_calls)

    @patch('snaps.openstack.create_instance.OpenStackVmInstance',
           autospec=True)
    def test_wait_for_vnf(self, mock_osvminstance):
        """
        Checks the method wait_for_vnf
        """

        mock_osvm_ins = mock_osvminstance.return_value
        mock_osvm_ins.vm_active.return_value = True
        result = self.os_sfc.wait_for_vnf(mock_osvm_ins)
        self.assertTrue(result)

    @patch('snaps.domain.vm_inst.VmInst', autospec=True)
    @patch('sfc.lib.openstack_utils.logger', autospec=True)
    def test_create_port_groups_raises_exception(self, mock_log, mock_vm):
        """
        Checks the create_port_groups when length of ports is greater than 2
        """
        mock_vm_ins = mock_vm.return_value
        mock_vm_ins.name = 'vm'
        log_calls_info = [call('Creating the port pairs for vm')]
        log_calls_err = [call('Only SFs with one or two ports are supported')]
        exception_message = "Failed to create port pairs"
        vnf_ports = ['p1', 'p2', 'p3']
        with self.assertRaises(Exception) as cm:
            self.os_sfc.create_port_groups(vnf_ports, mock_vm_ins)
        self.assertEqual(exception_message, cm.exception.message)
        mock_log.info.assert_has_calls(log_calls_info)
        mock_log.error.assert_has_calls(log_calls_err)

    @patch('snaps.domain.network.Port', autospec=True)
    @patch('snaps.domain.vm_inst.VmInst', autospec=True)
    @patch('sfc.lib.openstack_utils.logger', autospec=True)
    def test_create_port_groups_returns_none_from_pp(self, mock_log,
                                                     mock_vm,
                                                     mock_port):
        """
        Checks the create_port_groups when something goes wrong in port pair
        creation
        """
        mock_vm_ins = mock_vm.return_value
        mock_vm_ins.name = 'vm'
        log_calls_info = [call('Creating the port pairs for vm')]
        log_calls_warn = [call('Chain creation failed due to port pair '
                          'creation failed for vnf %(vnf)s', {'vnf': 'vm'})]
        mock_port_ins = mock_port.return_value
        mock_port_ins2 = mock_port.return_value
        mock_port_ins.id = '123abc'
        mock_port_ins2.id = '456def'
        self.neutron.create_sfc_port_pair.return_value = None
        result = self.os_sfc.create_port_groups(
            [mock_port_ins, mock_port_ins2], mock_vm_ins)
        self.assertIsNone(result)
        mock_log.info.assert_has_calls(log_calls_info)
        mock_log.warning.assert_has_calls(log_calls_warn)

    @patch('snaps.domain.network.Port', autospec=True)
    @patch('snaps.domain.vm_inst.VmInst', autospec=True)
    @patch('sfc.lib.openstack_utils.logger', autospec=True)
    def test_create_port_groups_exception_nopp(self, mock_log, mock_osvm,
                                               mock_port):
        """
        Checks the create_port_groups when openstack does not commit the pp
        """

        log_calls_info = [call('Creating the port pairs for vm')]
        mock_port_ins = mock_port.return_value
        mock_port_ins.id = '123abc'
        mock_vm_ins = mock_osvm.return_value
        mock_vm_ins.name = 'vm'
        exception_message = "Port pair was not committed in openstack"
        expected_port_pair = {'name': 'vm-connection-points',
                              'description': 'port pair for vm',
                              'ingress': '123abc',
                              'egress': '123abc'}
        self.neutron.create_sfc_port_pair.return_value = \
            {'port_pair': {'id': 'pp_id'}}
        self.neutron.list_sfc_port_pairs.return_value = \
            {'port_pairs': [{'id': 'xxxx'}]}
        with self.assertRaises(Exception) as cm:
            self.os_sfc.create_port_groups([mock_port_ins], mock_vm_ins)
        self.assertEqual(exception_message, cm.exception.message)
        self.neutron.create_sfc_port_pair.assert_has_calls(
            [call({'port_pair': expected_port_pair})])
        mock_log.info.assert_has_calls(log_calls_info)

    @patch('snaps.domain.network.Port', autospec=True)
    @patch('snaps.domain.vm_inst.VmInst', autospec=True)
    @patch('sfc.lib.openstack_utils.logger', autospec=True)
    def test_create_port_groups_returns_none_from_ppg(self, mock_log,
                                                      mock_vm,
                                                      mock_port):
        """
        Checks the create_port_groups when something goes wrong in port pair
        group creation
        """
        mock_vm_ins = mock_vm.return_value
        mock_vm_ins.name = 'vm'
        log_calls_info = [call('Creating the port pairs for vm'),
                          call('Creating the port pair groups for vm')]
        log_calls_warn = [call('Chain creation failed due to port pair group '
                               'creation failed for vnf %(vnf)', 'vm')]
        mock_port_ins = mock_port.return_value
        mock_port_ins.id = '123abc'
        self.neutron.create_sfc_port_pair.return_value = \
            {'port_pair': {'id': 'pp_id'}}
        self.neutron.list_sfc_port_pairs.return_value = \
            {'port_pairs': [{'id': 'pp_id'}]}
        self.neutron.create_sfc_port_pair_group.return_value = None
        result = self.os_sfc.create_port_groups([mock_port_ins], mock_vm_ins)
        self.assertIsNone(result)
        mock_log.info.assert_has_calls(log_calls_info)
        mock_log.warning.assert_has_calls(log_calls_warn)

    @patch('snaps.domain.network.Port', autospec=True)
    @patch('snaps.domain.vm_inst.VmInst', autospec=True)
    @patch('sfc.lib.openstack_utils.logger', autospec=True)
    def test_create_port_groups_returns_id(self, mock_log, mock_osvm,
                                           mock_port):
        """
        Checks the create_port_groups when everything goes as expected
        """

        log_calls_info = [call('Creating the port pairs for vm'),
                          call('Creating the port pair groups for vm')]
        mock_port_ins = mock_port.return_value
        mock_port_ins.id = '123abc'
        mock_osvm_ins = mock_osvm.return_value
        mock_osvm_ins.name = 'vm'
        expected_port_pair = {'name': 'vm-connection-points',
                              'description': 'port pair for vm',
                              'ingress': '123abc',
                              'egress': '123abc'}
        self.neutron.create_sfc_port_pair.return_value = \
            {'port_pair': {'id': 'pp_id'}}
        self.neutron.list_sfc_port_pairs.return_value = \
            {'port_pairs': [{'id': 'pp_id'}]}
        self.neutron.create_sfc_port_pair_group.return_value = \
            {'port_pair_group': {'id': 'pp_id'}}
        expected_port_pair_gr = {'name': 'vm-port-pair-group',
                                 'description': 'port pair group for vm',
                                 'port_pairs': ['pp_id']}

        self.os_sfc.create_port_groups([mock_port_ins], mock_osvm_ins)
        self.neutron.create_sfc_port_pair.assert_has_calls(
            [call({'port_pair': expected_port_pair})])
        self.neutron.create_sfc_port_pair_group.assert_has_calls(
            [call({'port_pair_group': expected_port_pair_gr})])
        mock_log.info.assert_has_calls(log_calls_info)

    @patch('sfc.lib.openstack_utils.logger', autospec=True)
    def test_create_chain(self, mock_log):
        """
        Checks the create_chain method
        """

        log_calls = [call('Creating the classifier...'),
                     call('Creating the chain...')]
        port_groups = ['1a', '2b']
        neutron_port = 'neutron_port_id'
        port = 80
        protocol = 'tcp'
        vnffg_name = 'red_http'
        symmetrical = False
        self.neutron.create_sfc_flow_classifier.return_value = \
            {'flow_classifier': {'id': 'fc_id'}}
        self.neutron.create_sfc_port_chain.return_value = \
            {'port_chain': {'id': 'pc_id'}}

        expected_sfc_classifier_params = {'name': vnffg_name + '-classifier',
                                          'logical_source_port': neutron_port,
                                          'destination_port_range_min': port,
                                          'destination_port_range_max': port,
                                          'protocol': protocol}
        expected_chain_config = {'name': vnffg_name + '-port-chain',
                                 'description': 'port-chain for SFC',
                                 'port_pair_groups': port_groups,
                                 'flow_classifiers': ['fc_id']}

        self.os_sfc.create_chain(port_groups, neutron_port, port,
                                 protocol, vnffg_name, symmetrical)

        self.neutron.create_sfc_flow_classifier.assert_has_calls(
            [call({'flow_classifier': expected_sfc_classifier_params})])
        self.neutron.create_sfc_port_chain.assert_has_calls(
            [call({'port_chain': expected_chain_config})])
        mock_log.info.assert_has_calls(log_calls)

    @patch('sfc.lib.openstack_utils.logger', autospec=True)
    def test_create_chain_symmetric(self, mock_log):
        """
        Checks the create_chain method
        """

        log_calls = [call('Creating the classifier...'),
                     call('Creating the chain...')]
        port_groups = ['1a', '2b']
        neutron_port = 'neutron_port_id'
        port = 80
        protocol = 'tcp'
        vnffg_name = 'red_http'
        symmetrical = True
        serv_p = '123abc'
        server_ip = '1.1.1.2'
        self.neutron.create_sfc_flow_classifier.return_value = \
            {'flow_classifier': {'id': 'fc_id'}}
        self.neutron.create_sfc_port_chain.return_value = \
            {'port_chain': {'id': 'pc_id'}}

        expected_sfc_classifier_params = {'name': vnffg_name + '-classifier',
                                          'logical_source_port': neutron_port,
                                          'destination_port_range_min': port,
                                          'destination_port_range_max': port,
                                          'destination_ip_prefix': server_ip,
                                          'logical_destination_port': serv_p,
                                          'protocol': protocol}
        expected_chain_config = {'name': vnffg_name + '-port-chain',
                                 'description': 'port-chain for SFC',
                                 'port_pair_groups': port_groups,
                                 'flow_classifiers': ['fc_id'],
                                 'chain_parameters': {'symmetric': True}}

        self.os_sfc.create_chain(port_groups, neutron_port, port,
                                 protocol, vnffg_name, symmetrical,
                                 server_port=serv_p, server_ip=server_ip)

        self.neutron.create_sfc_flow_classifier.assert_has_calls(
            [call({'flow_classifier': expected_sfc_classifier_params})])
        self.neutron.create_sfc_port_chain.assert_has_calls(
            [call({'port_chain': expected_chain_config})])
        mock_log.info.assert_has_calls(log_calls)

    @patch('sfc.lib.openstack_utils.logger', autospec=True)
    def test_delete_port_groups(self, mock_log):
        """
        Checks the delete_port_groups method
        """
        log_calls = [call('Deleting the port groups...'),
                     call('Deleting the port pairs...')]
        self.neutron.list_sfc_port_pair_groups.return_value = \
            {'port_pair_groups': [{'id': 'id_ppg1'}, {'id': 'id_ppg2'}]}
        self.neutron.list_sfc_port_pairs.return_value = \
            {'port_pairs': [{'id': 'id_pp1'}, {'id': 'id_pp2'}]}
        self.os_sfc.delete_port_groups()

        self.neutron.delete_sfc_port_pair_group.assert_has_calls(
            [call('id_ppg1'), call('id_ppg2')])
        self.neutron.delete_sfc_port_pair.assert_has_calls(
            [call('id_pp1'), call('id_pp2')])
        mock_log.info.assert_has_calls(log_calls)

    @patch('sfc.lib.openstack_utils.logger', autospec=True)
    def test_delete_chain(self, mock_log):
        """
        Checks the delete_chain method
        """
        log_calls = [call('Deleting the chain...'),
                     call('Deleting the classifiers...')]
        self.neutron.list_sfc_port_chains.return_value = \
            {'port_chains': [{'id': 'id_pc1'}]}
        self.neutron.list_sfc_flow_classifiers.return_value = \
            {'flow_classifiers': [{'id': 'id_fc1'}]}
        self.os_sfc.delete_chain()

        self.neutron.delete_sfc_port_chain.assert_has_calls([call('id_pc1')])
        self.neutron.delete_sfc_flow_classifier.assert_has_calls(
            [call('id_fc1')])
        mock_log.info.assert_has_calls(log_calls)


class SfcTackerSectionTesting(unittest.TestCase):
    def setUp(self):
        self.patcher = patch.object(tacker_client, 'Client', autospec=True)
        self.mock_tacker_client = self.patcher.start().return_value

    def tearDown(self):
        self.patcher.stop()

    @patch('os.getenv', autospec=True, return_value=None)
    @patch('sfc.lib.openstack_utils.logger', autospec=True)
    def test_get_tacker_client_version_returned_default(self,
                                                        mock_log,
                                                        mock_getenv):
        """
        Checks the proper functionality of get_tacker_client_version
        function when the os.getenv returns none
        """
        result = os_sfc_utils.get_tacker_client_version()
        self.assertEqual(result, '1.0')
        mock_getenv.assert_called_once_with('OS_TACKER_API_VERSION')
        mock_log.info.assert_not_called()

    @patch('os.getenv', autospec=True)
    @patch('sfc.lib.openstack_utils.logger', autospec=True)
    def test_get_tacker_client_version(self,
                                       mock_log,
                                       mock_getenv):
        """
        Checks the proper functionality of get_tacker_client_version
        function when the os.getenv returns version
        """

        ver = '2.0'
        mock_getenv.return_value = ver
        log_calls = [call("OS_TACKER_API_VERSION is set in env as '%s'", ver)]

        result = os_sfc_utils.get_tacker_client_version()
        self.assertEqual(result, ver)
        mock_getenv.assert_called_once_with('OS_TACKER_API_VERSION')
        mock_log.info.assert_has_calls(log_calls)

    @patch('sfc.lib.openstack_utils.logger', autospec=True)
    def test_get_id_from_name_returned_none(self, mock_log):
        """
        Checks the proper functionality of get_id_from_name
        function when tacker_client.list returns None
        """

        resource_name = 'mock_resource_name'
        resource_type = 'mock_resource_type'
        params = {'fields': 'id', 'name': resource_name}
        collection = resource_type + 's'
        path = '/' + collection
        self.mock_tacker_client.list.side_effect = Exception('ErrorMSG')
        log_calls = [call('Error [get_id_from_name(tacker_client, '
                          'resource_type, resource_name)]: ErrorMSG')]

        result = os_sfc_utils.get_id_from_name(self.mock_tacker_client,
                                               resource_type,
                                               resource_name)
        self.assertIsNone(result)
        self.mock_tacker_client.list.assert_called_once_with(collection,
                                                             path,
                                                             **params)
        mock_log.error.assert_has_calls(log_calls)

    @patch('sfc.lib.openstack_utils.openstack_tests.get_credentials',
           autospec=True, return_value='os_creds')
    @patch('sfc.lib.openstack_utils.keystone_utils.keystone_session',
           autospec=True, return_value='keystone_session_obj')
    @patch('sfc.lib.openstack_utils.constants.ENV_FILE', autospec=True)
    @patch('sfc.lib.openstack_utils.tackerclient.Client', autospec=True)
    def test_get_tacker_client(self, mock_tacker_client,
                               mock_env_file,
                               mock_keystone_session,
                               mock_get_credentials):
        """
        checks the proper functionality of get_tacker_client
        function
        """

        mock_tacker_client_ins = mock_tacker_client.return_value
        result = os_sfc_utils.get_tacker_client()
        assert result is mock_tacker_client_ins
        mock_get_credentials.assert_called_once_with(os_env_file=mock_env_file,
                                                     overrides=None)
        mock_keystone_session.assert_called_once_with('os_creds')
        mock_tacker_client.assert_called_once_with(
            '1.0', session='keystone_session_obj')

    @patch('sfc.lib.openstack_utils.logger', autospec=True)
    def test_get_id_from_name(self, mock_log):
        """
        Checks the proper functionality of get_id_from_name
        function when tacker_client.list returns id
        """

        resource_name = 'mock_resource_name'
        resource_type = 'mock_resource_type'
        params = {'fields': 'id', 'name': resource_name}
        collection = resource_type + 's'
        self.mock_tacker_client.list.return_value = {collection: {0: {'id':
                                                                  'mock_id'}}}
        path = '/' + collection
        result = os_sfc_utils.get_id_from_name(self.mock_tacker_client,
                                               resource_type,
                                               resource_name)
        self.assertEqual('mock_id', result)
        self.mock_tacker_client.list.assert_called_once_with(collection,
                                                             path,
                                                             **params)
        mock_log.error.assert_not_called()

    @patch('sfc.lib.openstack_utils.get_id_from_name', autospec=True)
    def test_get_vnfd_id(self, mock_get_id):
        """
        Checks the proper functionality of get_vnfd_id
        function
        """

        mock_get_id.return_value = 'id'
        result = os_sfc_utils.get_vnfd_id(self.mock_tacker_client,
                                          'vnfd_name')
        self.assertEqual('id', result)
        mock_get_id.assert_called_once_with(self.mock_tacker_client,
                                            'vnfd',
                                            'vnfd_name')

    @patch('sfc.lib.openstack_utils.get_id_from_name', autospec=True)
    def test_get_vim_id(self, mock_get_id):
        """
        Checks the proper fucntionality of get_vim_id
        function
        """

        mock_get_id.return_value = 'id'
        result = os_sfc_utils.get_vim_id(self.mock_tacker_client, 'vim_name')
        mock_get_id.assert_called_once_with(self.mock_tacker_client,
                                            'vim',
                                            'vim_name')
        self.assertEqual('id', result)

    @patch('time.sleep', autospec=True)
    @patch('sfc.lib.openstack_utils.logger', autospec=True)
    @patch('sfc.lib.openstack_utils.get_id_from_name', autospec=True)
    def test_get_vnf_id(self,
                        mock_get_id,
                        mock_log,
                        mock_sleep):
        """
        Checks the proper functionality of get_vnf_id
        function
        """

        vnf_name = 'mock_vnf'
        log_calls = [call("Could not retrieve ID for vnf with name [%s]."
                          " Retrying." % vnf_name)]

        get_id_calls = [call(self.mock_tacker_client, 'vnf', vnf_name)] * 2

        mock_get_id.side_effect = [None, 'vnf_id']

        result = os_sfc_utils.get_vnf_id(self.mock_tacker_client, vnf_name, 2)
        self.assertEqual('vnf_id', result)
        mock_sleep.assert_called_once_with(1)
        mock_log.info.assert_has_calls(log_calls)
        mock_get_id.assert_has_calls(get_id_calls)

    @patch('time.sleep', autospec=True)
    @patch('sfc.lib.openstack_utils.logger', autospec=True)
    @patch('sfc.lib.openstack_utils.get_id_from_name', autospec=True)
    def test_get_vnffg_id(self,
                          mock_get_id,
                          mock_log,
                          mock_sleep):
        """
        Checks the proper functionality of get_vnffg_id
        function
        """

        vnffg_name = 'mock_vnffg'
        log_calls = [call("Could not retrieve ID for vnffg with name [%s]."
                          " Retrying." % vnffg_name)]

        get_id_calls = [call(self.mock_tacker_client, 'vnffg', vnffg_name)] * 2

        mock_get_id.side_effect = [None, 'vnf_id']

        result = os_sfc_utils.get_vnffg_id(self.mock_tacker_client,
                                           vnffg_name,
                                           2)
        self.assertEqual('vnf_id', result)
        mock_sleep.assert_called_once_with(1)
        mock_log.info.assert_has_calls(log_calls)
        mock_get_id.assert_has_calls(get_id_calls)

    @patch('sfc.lib.openstack_utils.get_id_from_name', autospec=True)
    def test_get_vnffgd_id(self, mock_get_id):
        """
        Checks the proper functionality of get_vnffgd_id
        function
        """

        mock_get_id.return_value = 'id'
        result = os_sfc_utils.get_vnffgd_id(self.mock_tacker_client,
                                            'vnffgd_name')
        mock_get_id.assert_called_once_with(self.mock_tacker_client,
                                            'vnffgd',
                                            'vnffgd_name')
        self.assertEqual('id', result)

    @patch('sfc.lib.openstack_utils.logger', autospec=True)
    def test_list_vnfds_returned_none(self, mock_log):
        """
        Checks the proper functionality of list_vnfds
        function when the list_vnfds returns none
        """

        log_calls = [call('Error [list_vnfds(tacker_client)]: ErrorMSG')]
        self.mock_tacker_client.list_vnfds.side_effect = Exception('ErrorMSG')
        result = os_sfc_utils.list_vnfds(self.mock_tacker_client)
        mock_log.error.assert_has_calls(log_calls)
        self.mock_tacker_client.list_vnfds.assert_called_once_with(
            retrieve_all=True)
        self.assertIsNone(result)

    @patch('sfc.lib.openstack_utils.logger', autospec=True)
    def test_list_vnfds(self, mock_log):
        """
        Checks the proper functionality of list_vnfds
        function when the list_vnfds returns vnfds
        """

        vnfds = {
            'vnfds': [{'id': 1},
                      {'id': 2}]
        }
        self.mock_tacker_client.list_vnfds.return_value = vnfds
        result = os_sfc_utils.list_vnfds(self.mock_tacker_client)
        self.mock_tacker_client.list_vnfds.assert_called_once_with(
            retrieve_all=True)
        mock_log.assert_not_called()
        self.assertEqual([1, 2], result)

    @patch('sfc.lib.openstack_utils.logger', autospec=True)
    def test_create_vnfd_returned_none_tosca_file_not_provided(self, mock_log):
        """
        Checks the proper functionality of create_vnfd
        function when an exception is raised
        """

        log_calls = [call("Creating the vnfd..."),
                     call("Error [create_vnfd(tacker_client, 'None')]: "
                          "ErrorMSG")]

        self.mock_tacker_client.create_vnfd.side_effect = Exception('ErrorMSG')
        result = os_sfc_utils.create_vnfd(self.mock_tacker_client,
                                          None,
                                          'vnfd_name')
        self.assertIsNone(result)
        self.mock_tacker_client.create_vnfd.assert_called_once_with(
            body={'vnfd': {'attributes': {'vnfd': {}},
                           'name': 'vnfd_name'}})
        mock_log.info.assert_has_calls(log_calls[:1])
        mock_log.error.assert_has_calls(log_calls[1:])

    @patch('yaml.safe_load', autospec=True)
    @patch('__builtin__.open', autospec=True)
    @patch('sfc.lib.openstack_utils.logger', autospec=True)
    def test_create_vnfd_returned_none_tosca_file_provided(self,
                                                           mock_log,
                                                           mock_open,
                                                           mock_safe_load):
        """
        Checks the proper functionality of create_vnfd
        function when an exception is raised
        """

        log_calls = [call("Creating the vnfd..."),
                     call("VNFD template:\nmock_vnfd"),
                     call("Error [create_vnfd(tacker_client, 'tosca_file')]: "
                          "ErrorMSG")]

        open_handler = mock_open.return_value.__enter__.return_value
        open_handler.read.return_value = 'mock_vnfd'
        mock_safe_load.return_value = 'mock_vnfd_body'
        self.mock_tacker_client.create_vnfd.side_effect = Exception('ErrorMSG')
        result = os_sfc_utils.create_vnfd(self.mock_tacker_client,
                                          'tosca_file',
                                          'vnfd_name')
        self.assertIsNone(result)
        mock_open.assert_called_once_with('tosca_file')
        open_handler.read.assert_called_once_with()
        mock_safe_load.assert_called_once_with('mock_vnfd')
        mock_log.info.assert_has_calls(log_calls[:2])
        mock_log.error.assert_has_calls(log_calls[2:])

    @patch('yaml.safe_load', autospec=True)
    @patch('__builtin__.open', autospec=True)
    @patch('sfc.lib.openstack_utils.logger', autospec=True)
    def test_create_vnfd(self,
                         mock_log,
                         mock_open,
                         mock_safe_load):
        """
        Checks the proper functionality of create_vnfd
        function
        """

        log_calls = [call("VNFD template:\nmock_vnfd")]

        open_handler = mock_open.return_value.__enter__.return_value
        open_handler.read.return_value = 'mock_vnfd'
        mock_safe_load.return_value = 'mock_vnfd_body'
        result = os_sfc_utils.create_vnfd(self.mock_tacker_client,
                                          'tosca_file',
                                          'vnfd_name')
        assert result is self.mock_tacker_client.create_vnfd.return_value
        self.mock_tacker_client.create_vnfd.assert_called_once_with(
            body={"vnfd": {"attributes": {"vnfd": "mock_vnfd_body"},
                           "name": "vnfd_name"}})
        mock_open.assert_called_once_with('tosca_file')
        open_handler.read.assert_called_once_with()
        mock_safe_load.assert_called_once_with('mock_vnfd')
        mock_log.info.assert_has_calls(log_calls)
        mock_log.error.assert_not_called()

    @patch('sfc.lib.openstack_utils.logger', autospec=True)
    def test_delete_vnfd_returned_none(self, mock_log):
        """
        Checks the proper functionality of delete_vnfd
        function when an exception is raised
        """

        log_calls = [call("Error [delete_vnfd(tacker_client, 'None', 'None')]:"
                          " You need to provide VNFD id or VNFD name")]

        result = os_sfc_utils.delete_vnfd(self.mock_tacker_client)
        self.assertIsNone(result)
        mock_log.error.assert_has_calls(log_calls)

    @patch('sfc.lib.openstack_utils.get_vnfd_id',
           autospec=True, return_value='vnfd')
    def test_delete_vnfd(self, mock_get_vnfd_id):
        """
        Checks the proper functionality of delete_vnfd
        function
        """

        result = os_sfc_utils.delete_vnfd(self.mock_tacker_client,
                                          None,
                                          'vnfd_name')
        assert result is self.mock_tacker_client.delete_vnfd.return_value
        mock_get_vnfd_id.assert_called_once_with(self.mock_tacker_client,
                                                 'vnfd_name')
        self.mock_tacker_client.delete_vnfd.assert_called_once_with('vnfd')

    @patch('sfc.lib.openstack_utils.logger', autospec=True)
    def test_list_vnfs_returned_none(self, mock_log):
        """
        Checks the proper functionality of list_vnfs
        function
        """

        log_calls = [call("Error [list_vnfs(tacker_client)]: ErrorMSG")]

        self.mock_tacker_client.list_vnfs.side_effect = Exception('ErrorMSG')
        result = os_sfc_utils.list_vnfs(self.mock_tacker_client)
        self.assertIsNone(result)
        self.mock_tacker_client.list_vnfs.assert_called_once_with(
            retrieve_all=True)
        mock_log.error.assert_has_calls(log_calls)

    def test_list_vnfs(self):
        """
        Checks the proper functionality of list_vnfs
        function
        """
        vnfs = {'vnfs': [{'id': 1},
                         {'id': 2}]}

        self.mock_tacker_client.list_vnfs.return_value = vnfs
        result = os_sfc_utils.list_vnfs(self.mock_tacker_client)
        self.assertEqual([1, 2], result)
        self.mock_tacker_client.list_vnfs.assert_called_once_with(
            retrieve_all=True)

    @patch('sfc.lib.openstack_utils.logger', autospec=True)
    def test_create_vnf_returned_none_vnfd_not_provided(self, mock_log):
        """
        Checks the proper functionality of create_vnf
        function when an exception is raised
        """

        log_calls = [call("Creating the vnf..."),
                     call("error [create_vnf(tacker_client,"
                          " 'vnf_name', 'None', 'None')]: "
                          "vnfd id or vnfd name is required")]
        result = os_sfc_utils.create_vnf(self.mock_tacker_client, 'vnf_name')
        self.assertIsNone(result)
        mock_log.info.assert_has_calls(log_calls[:1])
        mock_log.error.assert_has_calls(log_calls[1:])

    @patch('sfc.lib.openstack_utils.logger', autospec=True)
    def test_create_vnf_returned_none_vnfd_provided(self, mock_log):
        """
        Checks the proper functionality of create_vnf
        function when an exception is raised
        """

        log_calls = [call("Creating the vnf..."),
                     call("error [create_vnf(tacker_client,"
                          " 'vnf_name', 'None', 'vnfd_name')]: "
                          "vim id or vim name is required")]
        result = os_sfc_utils.create_vnf(self.mock_tacker_client,
                                         'vnf_name',
                                         None,
                                         'vnfd_name',
                                         None,
                                         None)
        self.assertIsNone(result)
        mock_log.info.assert_has_calls(log_calls[:1])
        mock_log.error.assert_has_calls(log_calls[1:])

    @patch('__builtin__.open', autospec=True)
    @patch('sfc.lib.openstack_utils.logger', autospec=True)
    @patch('sfc.lib.openstack_utils.get_vim_id',
           autospec=True, return_value='vim_id')
    @patch('sfc.lib.openstack_utils.get_vnfd_id',
           autospec=True, return_value='vnfd_id')
    def test_create_vnf_vim_id_not_provided(self,
                                            mock_get_vnfd_id,
                                            mock_get_vim_id,
                                            mock_log,
                                            mock_open):
        """
        Checks the proper functionality of create_vnf
        function
        """
        mock_body = {'vnf': {'attributes': {'param_values': 'mock_data'},
                             'vim_id': 'vim_id',
                             'name': 'vnf_name',
                             'vnfd_id': 'vnfd_id'}}
        log_calls = [call('Creating the vnf...')]
        open_handler = mock_open.return_value.__enter__.return_value
        open_handler.read.return_value = 'mock_data'
        result = os_sfc_utils.create_vnf(self.mock_tacker_client,
                                         'vnf_name',
                                         None,
                                         'vnfd_name',
                                         None,
                                         'vim_name',
                                         'param_file')

        assert result is self.mock_tacker_client.create_vnf.return_value
        mock_get_vnfd_id.assert_called_once_with(self.mock_tacker_client,
                                                 'vnfd_name')
        mock_get_vim_id.assert_called_once_with(self.mock_tacker_client,
                                                'vim_name')
        mock_log.info.assert_has_calls(log_calls)
        self.mock_tacker_client.create_vnf.assert_called_once_with(
            body=mock_body)

    @patch('__builtin__.open', autospec=True)
    @patch('sfc.lib.openstack_utils.logger', autospec=True)
    def test_create_vnf_vim_id_provided(self, mock_log, mock_open):
        """
        Checks the proper functionality of create_vnf
        function
        """
        mock_body = {'vnf': {'attributes': {},
                             'vim_id': 'vim_id',
                             'name': 'vnf_name',
                             'vnfd_id': 'vnfd_id'}}
        log_calls = [call('Creating the vnf...')]
        open_handler = mock_open.return_value.__enter__.return_value
        open_handler.read.return_value = 'mock_data'

        result = os_sfc_utils.create_vnf(self.mock_tacker_client,
                                         'vnf_name',
                                         'vnfd_id',
                                         'vnfd_name',
                                         'vim_id',
                                         'vim_name')
        assert result is self.mock_tacker_client.create_vnf.return_value
        mock_log.info.assert_has_calls(log_calls)
        self.mock_tacker_client.create_vnf.assert_called_once_with(
            body=mock_body)

    @patch('sfc.lib.openstack_utils.logger', autospec=True)
    def test_get_vnf_returned_none_vnf_not_provided(self, mock_log):
        """
        Checks the proper functionality of get_vnf
        functionality when an exception is raised
        """

        log_calls = [call("Could not retrieve VNF [vnf_id=None, vnf_name=None]"
                          " - You must specify vnf_id or vnf_name")]

        result = os_sfc_utils.get_vnf(self.mock_tacker_client)
        self.assertIsNone(result)
        mock_log.error.assert_has_calls(log_calls)

    @patch('sfc.lib.openstack_utils.get_vnf_id',
           autospec=True, return_value=None)
    @patch('sfc.lib.openstack_utils.logger', autospec=True)
    def test_get_vnf_returned_none_vnf_provided(self,
                                                mock_log,
                                                mock_get_vnf_id):
        """
        Checks the proper functionality of get_vnf
        functionality when an exception is raised
        """

        log_calls = [call("Could not retrieve VNF [vnf_id=None, "
                          "vnf_name=vnf_name] - Could not retrieve ID from "
                          "name [vnf_name]")]
        result = os_sfc_utils.get_vnf(self.mock_tacker_client,
                                      None,
                                      'vnf_name')
        self.assertIsNone(result)
        mock_get_vnf_id.assert_called_once_with(self.mock_tacker_client,
                                                'vnf_name')
        mock_log.error.assert_has_calls(log_calls)

    @patch('sfc.lib.openstack_utils.logger', autospec=True)
    @patch('sfc.lib.openstack_utils.list_vnfs', autospec=True)
    def test_get_vnf(self,
                     mock_list_vnfs,
                     mock_log):
        """
        Checks the proper functionality of get_vnf
        function
        """

        vnf = {'vnfs': [{'id': 'default'},
                        {'id': 'vnf_id'}]}

        mock_list_vnfs.return_value = vnf
        result = os_sfc_utils.get_vnf(self.mock_tacker_client, 'vnf_id', None)
        self.assertDictEqual(vnf['vnfs'][1], result)
        mock_log.error.assert_not_called()

    @patch('json.loads', autospec=True)
    @patch('sfc.lib.openstack_utils.get_vnf', autospe=True)
    def test_get_vnf_ip(self,
                        mock_get_vnf,
                        mock_json_loads):
        """
        Checks the proper functionality of get_vnf_ip
        function
        """

        vnf = {"mgmt_url": {"VDU1": "192.168.120.3"}}
        mock_get_vnf.return_value = vnf
        mock_json_loads.return_value = vnf['mgmt_url']
        result = os_sfc_utils.get_vnf_ip(self.mock_tacker_client)
        self.assertEqual("192.168.120.3", result)
        mock_get_vnf.assert_called_once_with(self.mock_tacker_client,
                                             None,
                                             None)
        mock_json_loads.assert_called_once_with(vnf['mgmt_url'])

    @patch('sfc.lib.openstack_utils.logger', autospec=True)
    @patch('sfc.lib.openstack_utils.get_vnf', autospec=True)
    def test_wait_for_vnf_returned_none_unable_to_retrieve_vnf(self,
                                                               mock_get_vnf,
                                                               mock_log):
        """
        Checks the proper functionality of wait_for_vnf
        function when an Exception is raised
        """

        mock_get_vnf.return_value = None
        log_calls = [call("error [wait_for_vnf(tacker_client, 'vnf_id', "
                          "'vnf_name')]: Could not retrieve VNF - id='vnf_id',"
                          " name='vnf_name'")]

        result = os_sfc_utils.wait_for_vnf(self.mock_tacker_client,
                                           'vnf_id',
                                           'vnf_name',
                                           0)
        self.assertIsNone(result)
        mock_get_vnf.assert_called_once_with(self.mock_tacker_client,
                                             'vnf_id',
                                             'vnf_name')
        mock_log.error.assert_has_calls(log_calls)

    @patch('time.sleep', autospec=True)
    @patch('sfc.lib.openstack_utils.logger', autospec=True)
    @patch('sfc.lib.openstack_utils.get_vnf', autospec=True)
    def test_wait_for_vnf_returned_none_unable_to_boot_vnf(self,
                                                           mock_get_vnf,
                                                           mock_log,
                                                           mock_sleep):
        """
        Checks the proper functionality of wait_for_vnf
        function when an Exception is raised
        """

        mock_vnf_values = [{'id': 'vnf_id',
                            'status': 'ERROR'},
                           {'id': 'vnf_id',
                            'status': 'PEDNING_CREATE'}]
        mock_get_vnf.side_effect = mock_vnf_values
        log_calls = [call("Waiting for vnf %s" % str(mock_vnf_values[0])),
                     call("error [wait_for_vnf(tacker_client, 'vnf_id', "
                          "'vnf_name')]: Error when booting vnf vnf_id")]

        result = os_sfc_utils.wait_for_vnf(self.mock_tacker_client,
                                           'vnf_id',
                                           'vnf_name',
                                           0)
        self.assertIsNone(result)
        mock_get_vnf.assert_called_once_with(self.mock_tacker_client,
                                             'vnf_id',
                                             'vnf_name')
        mock_log.info.assert_has_calls(log_calls[:1])
        mock_log.error.assert_has_calls(log_calls[1:])

    @patch('time.sleep', autospec=True)
    @patch('sfc.lib.openstack_utils.logger', autospec=True)
    @patch('sfc.lib.openstack_utils.get_vnf', autospec=True)
    def test_wait_for_vnf_returned_none_timeout_booting_vnf(self,
                                                            mock_get_vnf,
                                                            mock_log,
                                                            mock_sleep):
        """
        Checks the proper functionality of wait_for_vnf
        function when an Exception is raised
        """

        mock_vnf_values = [{'id': 'vnf_id',
                            'status': 'PENDING_CREATE'},
                           {'id': 'vnf_id',
                            'status': 'PENDING_CREATE'}]
        mock_get_vnf.side_effect = mock_vnf_values
        log_calls = [call("Waiting for vnf %s" % str(mock_vnf_values[1])),
                     call("error [wait_for_vnf(tacker_client, 'vnf_id', "
                          "'vnf_name')]: Timeout when booting vnf vnf_id")]

        result = os_sfc_utils.wait_for_vnf(self.mock_tacker_client,
                                           'vnf_id',
                                           'vnf_name',
                                           0)
        self.assertIsNone(result)
        mock_get_vnf.assert_called_with(self.mock_tacker_client,
                                        'vnf_id',
                                        'vnf_name')
        mock_log.info.assert_has_calls(log_calls[:1])
        mock_log.error.assert_has_calls(log_calls[1:])

    @patch('time.sleep', autospec=True)
    @patch('sfc.lib.openstack_utils.logger', autospec=True)
    @patch('sfc.lib.openstack_utils.get_vnf', autospec=True)
    def test_wait_for_vnf(self,
                          mock_get_vnf,
                          mock_log,
                          mock_sleep):
        """
        Checks for the proper functionality of wait_for_vnf
        function
        """

        mock_vnf_values = [{'status': 'PENDING_CREATE',
                            'id': 'vnf_id'},
                           {'status': 'ACTIVE',
                            'id': 'vnf_id'}]

        log_calls = [call("Waiting for vnf %s" % mock_vnf_values[0])]

        mock_get_vnf.side_effect = mock_vnf_values

        result = os_sfc_utils.wait_for_vnf(self.mock_tacker_client,
                                           'vnf_id',
                                           'vnf_name',
                                           3)
        self.assertEqual('vnf_id', result)
        mock_log.info.assert_has_calls(log_calls)

    @patch('sfc.lib.openstack_utils.logger', autospec=True)
    def test_delete_vnf_returned_none(self, mock_log):
        """
        Checks the proper functionality of delete_vnf
        function
        """

        log_calls = [call("Error [delete_vnf(tacker_client, 'None', 'None')]:"
                          " You need to provide a VNF id or name")]
        result = os_sfc_utils.delete_vnf(self.mock_tacker_client)
        self.assertIsNone(result)
        mock_log.error.assert_has_calls(log_calls)

    @patch('sfc.lib.openstack_utils.logger', autospec=True)
    @patch('sfc.lib.openstack_utils.get_vnf_id', autospec=True)
    def test_delete_vnf(self,
                        mock_get_vnf_id,
                        mock_log):
        """
        Checks the proper functionality of delete_vnf
        function
        """

        mock_get_vnf_id.return_value = 'vnf'
        result = os_sfc_utils.delete_vnf(self.mock_tacker_client,
                                         None,
                                         'vnf_name')
        assert result is self.mock_tacker_client.delete_vnf.return_value
        mock_get_vnf_id.assert_called_once_with(self.mock_tacker_client,
                                                'vnf_name')
        self.mock_tacker_client.delete_vnf.assert_called_once_with('vnf')

    @patch('sfc.lib.openstack_utils.logger', autospec=True)
    def test_create_vim_returned_none(self,
                                      mock_log):
        """
        Checks the proper functionality of create_vim
        function when the vim_file is not provided
        """

        self.mock_tacker_client.create_vim.side_effect = Exception('ErrorMSG')
        log_calls = [[call("Creating the vim...")],
                     [call("Error [create_vim(tacker_client, 'None')]"
                           ": ErrorMSG")]]

        result = os_sfc_utils.create_vim(self.mock_tacker_client)
        self.assertIsNone(result)
        self.mock_tacker_client.create_vim.assert_called_once_with(body={})
        mock_log.info.assert_has_calls(log_calls[0])
        mock_log.error.assert_has_calls(log_calls[1])

    @patch('json.load', autospec=True)
    @patch('__builtin__.open', autospec=True)
    @patch('sfc.lib.openstack_utils.logger', autospec=True)
    def test_create_vim(self,
                        mock_log,
                        mock_open,
                        mock_json_loads):
        """
        Checks the proper functionality of create_vim
        function
        """

        log_calls = [call("Creating the vim..."),
                     call("VIM template:\nmock_data")]

        open_handler = mock_open.return_value.__enter__.return_value
        mock_json_loads.return_value = 'mock_data'
        result = os_sfc_utils.create_vim(self.mock_tacker_client, 'vim_file')
        assert result is self.mock_tacker_client.create_vim.return_value
        mock_log.info.assert_has_calls(log_calls)
        mock_open.assert_called_once_with('vim_file')
        mock_json_loads.assert_called_once_with(open_handler)
        mock_log.error.assert_not_called()

    @patch('sfc.lib.openstack_utils.logger', autospec=True)
    def test_create_vnffgd_returned_none(self, mock_log):
        """
        Checks the proper functionality of create_vnffgd
        function when create_vnffgd raises an Exception
        """

        self.mock_tacker_client.create_vnffgd.side_effect = Exception(
            'ErrorMSG')
        log_calls = [[call("Creating the vnffgd...")],
                     [call("Error [create_vnffgd(tacker_client, 'None')]"
                           ": ErrorMSG")]]

        result = os_sfc_utils.create_vnffgd(self.mock_tacker_client)
        self.assertIsNone(result)
        mock_log.info.assert_has_calls(log_calls[0])
        mock_log.error.assert_has_calls(log_calls[1])

    @patch('yaml.safe_load', autospec=True)
    @patch('__builtin__.open', autospec=True)
    @patch('sfc.lib.openstack_utils.logger', autospec=True)
    def test_create_vnffgd(self,
                           mock_log,
                           mock_open,
                           mock_safe_load):
        """
        Checks the proper functionality of create_vnffgd
        function
        """

        log_calls = [call('Creating the vnffgd...'),
                     call('VNFFGD template:\nmock_data')]

        vnffgd_body = {'id': 0, 'type': 'dict'}

        mock_vim_body = {'vnffgd': {'name': 'vnffgd_name',
                                    'template': {'vnffgd': vnffgd_body}}}

        open_handler = mock_open.return_value.__enter__.return_value
        open_handler.read.return_value = 'mock_data'
        mock_safe_load.return_value = {'id': 0, 'type': 'dict'}
        result = os_sfc_utils.create_vnffgd(self.mock_tacker_client,
                                            'tosca_file',
                                            'vnffgd_name')
        assert result is self.mock_tacker_client.create_vnffgd.return_value
        mock_open.assert_called_once_with('tosca_file')
        mock_safe_load.assert_called_once_with('mock_data')
        self.mock_tacker_client.create_vnffgd.assert_called_once_with(
            body=mock_vim_body)
        mock_log.info.assert_has_calls(log_calls)
        mock_log.error.assert_not_called()

    @patch('sfc.lib.openstack_utils.logger', autospec=True)
    def test_create_vnffg_returned_none(self, mock_log):
        """
        Checks the proper functionality of create_vnffg
        function when the vnffgd id or vnffg name is not provided
        """

        log_calls = [[call("Creating the vnffg...")],
                     [call("error [create_vnffg(tacker_client,"
                           " 'None', 'None', 'None')]: "
                           "vnffgd id or vnffgd name is required")]]

        result = os_sfc_utils.create_vnffg(self.mock_tacker_client)
        self.assertIsNone(result)
        mock_log.info.assert_has_calls(log_calls[0])
        mock_log.error.assert_has_calls(log_calls[1])

    @patch('yaml.safe_load', autospec=True)
    @patch('__builtin__.open', autospec=True)
    @patch('sfc.lib.openstack_utils.logger', autospec=True)
    @patch('sfc.lib.openstack_utils.get_vnffgd_id', autospec=True)
    def test_create_vnffg_vnffgd_id_not_provided(self,
                                                 mock_get_vnffgd_id,
                                                 mock_log,
                                                 mock_open,
                                                 mock_safe_load):
        """
        Checks the proper functionality of create_vnffg
        function when the vnffgd id or vnffg name is not provided
        """

        log_calls = [call('Creating the vnffg...')]
        vnffg_calls = [call(body={
                            'vnffg': {
                                'attributes': {'param_values': {'type': 'dict',
                                                                'id': 0}},
                                'vnffgd_id': 'mocked_vnffg_id',
                                'name': 'vnffg_name',
                                'symmetrical': False}})]
        mock_get_vnffgd_id.return_value = 'mocked_vnffg_id'
        open_handler = mock_open.return_value.__enter__.return_value
        open_handler.read.return_value = 'data'
        mock_safe_load.return_value = {'id': 0, 'type': 'dict'}

        result = os_sfc_utils.create_vnffg(self.mock_tacker_client,
                                           'vnffg_name',
                                           None,
                                           'vnffgd_name',
                                           'param_file')
        assert result is self.mock_tacker_client.create_vnffg.return_value
        mock_open.assert_called_once_with('param_file')
        open_handler.read.assert_called_once_with()
        mock_get_vnffgd_id.assert_called_once_with(self.mock_tacker_client,
                                                   'vnffgd_name')
        mock_safe_load.assert_called_once_with('data')
        mock_log.info.assert_has_calls(log_calls)
        self.mock_tacker_client.create_vnffg.assert_has_calls(vnffg_calls)

    @patch('yaml.safe_load', autospec=True)
    @patch('__builtin__.open', autospec=True)
    @patch('sfc.lib.openstack_utils.logger', autospec=True)
    def test_create_vnffg_vnffgd_id_provided(self,
                                             mock_log,
                                             mock_open,
                                             mock_safe_load):
        """
        Checks the proper functionality of create_vnffg
        function when the vnffgd id or vnffg name is not provided
        """

        log_calls = [call('Creating the vnffg...')]
        vnffg_calls = [call(body={
                            'vnffg': {
                                'attributes': {'param_values': {'type': 'dict',
                                                                'id': 0}},
                                'vnffgd_id': 'vnffgd_id',
                                'name': 'vnffg_name',
                                'symmetrical': False}})]
        open_handler = mock_open.return_value.__enter__.return_value
        open_handler.read.return_value = 'data'
        mock_safe_load.return_value = {'id': 0, 'type': 'dict'}

        result = os_sfc_utils.create_vnffg(self.mock_tacker_client,
                                           'vnffg_name',
                                           'vnffgd_id',
                                           'vnffgd_name',
                                           'param_file')
        assert result is self.mock_tacker_client.create_vnffg.return_value
        mock_open.assert_called_once_with('param_file')
        open_handler.read.assert_called_once_with()
        mock_safe_load.assert_called_once_with('data')
        mock_log.info.assert_has_calls(log_calls)
        self.mock_tacker_client.create_vnffg.assert_has_calls(vnffg_calls)

    @patch('sfc.lib.openstack_utils.logger', autospec=True)
    def test_list_vnffgds_returned_none(self, mock_log):
        """
        Checks the proper functionality of list_vnffgds
        function when list_vnffgds raises an Exception
        """

        self.mock_tacker_client.list_vnffgds.side_effect = Exception(
            'ErrorMSG')
        log_calls = [call('Error [list_vnffgds(tacker_client)]: ErrorMSG')]

        result = os_sfc_utils.list_vnffgds(self.mock_tacker_client)
        self.assertIsNone(result)
        self.mock_tacker_client.list_vnffgds.assert_called_once_with(
            retrieve_all=True)
        mock_log.error.assert_has_calls(log_calls)

    def test_list_vnffgds(self):
        """
        Checks the proper functtionality of list_vnffgds
        function
        """

        vnffgds = {'vnffgds': [{'id': 'vnffgd_obj_one'},
                               {'id': 'vnffgd_obj_two'}]}

        mock_vnffgds = ['vnffgd_obj_one', 'vnffgd_obj_two']

        self.mock_tacker_client.list_vnffgds.return_value = vnffgds
        result = os_sfc_utils.list_vnffgds(self.mock_tacker_client)
        self.assertEqual(mock_vnffgds, result)
        self.mock_tacker_client.list_vnffgds.assert_called_once_with(
            retrieve_all=True)

    @patch('sfc.lib.openstack_utils.logger', autospec=True)
    def test_list_vnffgs_returned_none(self, mock_log):
        """
        Checks the proper functionality of list_vnffgs
        function when list_vnffgs raises an Exception
        """

        self.mock_tacker_client.list_vnffgs.side_effect = Exception('ErrorMSG')
        log_calls = [call('Error [list_vnffgs(tacker_client)]: ErrorMSG')]

        result = os_sfc_utils.list_vnffgs(self.mock_tacker_client)
        self.assertIsNone(result)
        self.mock_tacker_client.list_vnffgs.assert_called_once_with(
            retrieve_all=True)
        mock_log.error.assert_has_calls(log_calls)

    def test_list_vnffgs(self):
        """
        Checks the proper functionality of list_vnffgs
        function
        """

        vnffgs = {'vnffgs': [{'id': 'vnffg_obj_one'},
                             {'id': 'vnffg_obj_two'}]}

        mock_vnffgs = ['vnffg_obj_one', 'vnffg_obj_two']

        self.mock_tacker_client.list_vnffgs.return_value = vnffgs
        result = os_sfc_utils.list_vnffgs(self.mock_tacker_client)
        self.assertEqual(mock_vnffgs, result)
        self.mock_tacker_client.list_vnffgs.assert_called_once_with(
            retrieve_all=True)

    @patch('sfc.lib.openstack_utils.logger', autospec=True)
    def test_delete_vnffg_returned_none(self, mock_log):
        """
        Checks the proper functionality of delete_vnffg
        function
        """

        log_calls = [call("Error [delete_vnffg(tacker_client, 'None', 'None')]"
                          ": You need to provide a VNFFG id or name")]

        result = os_sfc_utils.delete_vnffg(self.mock_tacker_client)
        self.assertIsNone(result)
        mock_log.error.assert_has_calls(log_calls)

    @patch('sfc.lib.openstack_utils.get_vnffg_id',
           autospec=True, return_value='vnffg')
    def test_delete_vnffg(self, mock_get_vnffg_id):
        """
        Checks the proper functionality of delete_vnffg
        function
        """

        self.mock_tacker_client.delete_vnffg.return_value = 'deleted'
        result = os_sfc_utils.delete_vnffg(self.mock_tacker_client,
                                           None,
                                           'vnffg_name')
        self.assertEqual('deleted', result)
        mock_get_vnffg_id.assert_called_once_with(self.mock_tacker_client,
                                                  'vnffg_name')
        self.mock_tacker_client.delete_vnffg.assert_called_once_with('vnffg')

    @patch('sfc.lib.openstack_utils.logger', autospec=True)
    def test_delete_vnffgd_returned_none(self, mock_log):
        """
        Checks the proper functionality of delete_vnffgd
        function
        """

        log_calls = [call("Error [delete_vnffgd(tacker_client, 'None', 'None')"
                          "]: You need to provide VNFFGD id or VNFFGD name")]

        result = os_sfc_utils.delete_vnffgd(self.mock_tacker_client)
        self.assertIsNone(result)
        mock_log.error.assert_has_calls(log_calls)

    @patch('sfc.lib.openstack_utils.get_vnffgd_id',
           autospec=True, return_value='vnffgd')
    def test_delete_vnffgd(self, mock_get_vnffgd_id):
        """
        Checks the proper functionality of delete_vnffgd
        function
        """

        self.mock_tacker_client.delete_vnffgd.return_value = 'deleted'
        result = os_sfc_utils.delete_vnffgd(self.mock_tacker_client,
                                            None,
                                            'vnffgd_name')
        self.assertEqual('deleted', result)
        mock_get_vnffgd_id.assert_called_once_with(self.mock_tacker_client,
                                                   'vnffgd_name')
        self.mock_tacker_client.delete_vnffgd.assert_called_once_with('vnffgd')

    @patch('sfc.lib.openstack_utils.logger', autospec=True)
    def test_list_vims_returned_none(self, mock_log):
        """
        Checks the proper functionality of list_vims
        function when VNFFGD id is not provided
        """

        self.mock_tacker_client.list_vims.side_effect = Exception('ErrorMSG')
        log_calls = [call('Error [list_vims(tacker_client)]: ErrorMSG')]

        result = os_sfc_utils.list_vims(self.mock_tacker_client)
        self.assertIsNone(result)
        self.mock_tacker_client.list_vims.assert_called_once_with(
            retrieve_all=True)
        mock_log.error.assert_has_calls(log_calls)

    def test_list_vims(self):
        """
        Checks the proper functionality list_vims
        function
        """

        vims = {'vims': [{'id': 'vim_obj_1'},
                         {'id': 'vim_obj_2'}]}

        mock_vims = ['vim_obj_1', 'vim_obj_2']

        self.mock_tacker_client.list_vims.return_value = vims
        result = os_sfc_utils.list_vims(self.mock_tacker_client)
        self.assertEqual(mock_vims, result)
        self.mock_tacker_client.list_vims.assert_called_once_with(
            retrieve_all=True)

    @patch('sfc.lib.openstack_utils.logger', autospec=True)
    def test_delete_vim_returned_none(self, mock_log):
        """
        Checks the proper functionality of delete_vim
        function when VIM id  and VIM name is not provided
        """

        log_calls = [call("Error [delete_vim(tacker_client, '%s', '%s')]: %s"
                          % (None, None, 'You need to provide '
                             'VIM id or VIM name'))]

        result = os_sfc_utils.delete_vim(self.mock_tacker_client)
        self.assertIsNone(result)
        mock_log.error.assert_has_calls(log_calls)

    @patch('sfc.lib.openstack_utils.get_vim_id',
           autospec=True, return_value='vim_id')
    def test_delete_vim(self, mock_get_vim_id):
        """
        Checks the proper functionality of delete_vim
        function
        """

        result = os_sfc_utils.delete_vim(self.mock_tacker_client,
                                         None,
                                         'vim_name')
        assert result is self.mock_tacker_client.delete_vim.return_value
        mock_get_vim_id.assert_called_once_with(self.mock_tacker_client,
                                                'vim_name')
        self.mock_tacker_client.delete_vim.assert_called_once_with('vim_id')

    @patch('sfc.lib.openstack_utils.get_tacker_client',
           autospec=True, return_value='tacker_client_obj')
    @patch('sfc.lib.openstack_utils.logger', autospec=True)
    def test_get_tacker_items(self,
                              mock_log,
                              mock_tacker_client):
        """
        Checks the proper functionality of get_tacker_items
        function
        """

        mock_dict = {'list_vims': DEFAULT,
                     'list_vnfds': DEFAULT,
                     'list_vnfs': DEFAULT,
                     'list_vnffgds': DEFAULT,
                     'list_vnffgs': DEFAULT}
        with patch.multiple('sfc.lib.openstack_utils',
                            **mock_dict) as mock_values:

            os_sfc_utils.get_tacker_items()

        mock_tacker_client.assert_called_once_with()
        self.assertEqual(5, mock_log.debug.call_count)
        for key in mock_values:
            mock_values[key].assert_called_once_with('tacker_client_obj')

    @patch('json.dump', autospec=True)
    @patch('json.load', autospec=True)
    @patch('__builtin__.open', autospec=True)
    @patch('sfc.lib.openstack_utils.create_vim', autospec=True)
    def test_register_vim(self,
                          mock_create_vim,
                          mock_open,
                          mock_json_loads,
                          mock_json_dump):
        """
        Checks the proper functionality of register_vim
        function
        """

        tmp_file = '/tmp/register-vim.json'
        open_handler = mock_open.return_value.__enter__.return_value
        open_calls = [call('vim_file'),
                      call(tmp_file, 'w')]

        mock_json_loads.return_value = {'vim': {'auth_cred':
                                                {'password': None},
                                                'auth_url': None}}

        json_dict = {'vim': {'auth_cred': {'password': 'os_auth_cred'},
                             'auth_url': 'os_auth_url'}}

        patch_dict = {'OS_AUTH_URL': 'os_auth_url',
                      'OS_PASSWORD': 'os_auth_cred'}

        with patch.dict('os.environ', patch_dict):
            os_sfc_utils.register_vim(self.mock_tacker_client, 'vim_file')
            mock_json_loads.assert_called_once_with(open_handler)
            mock_json_dump.assert_called_once_with(json_dict,
                                                   mock_open(tmp_file, 'w'))
            mock_open.assert_has_calls(open_calls, any_order=True)
            mock_create_vim.assert_called_once_with(self.mock_tacker_client,
                                                    vim_file=tmp_file)

    @patch('json.dump', autospec=True)
    @patch('__builtin__.open', autospec=True)
    @patch('sfc.lib.openstack_utils.create_vnf', autospec=True)
    @patch('os.path.join',
           autospec=True, return_value='/tmp/param_av_zone.json')
    def test_create_vnf_in_av_zone(self,
                                   mock_path_join,
                                   mock_create_vnf,
                                   mock_open,
                                   mock_json_dump):
        """
        Checks the proper fucntionality of test_create_vnf_in_av_zone
        fucntion
        """

        data = {'zone': 'av::zone'}
        param_file = '/tmp/param_av_zone.json'
        os_sfc_utils.create_vnf_in_av_zone(self.mock_tacker_client,
                                           'vnf_name',
                                           'vnfd_name',
                                           'vim_name',
                                           'param_file',
                                           'av::zone')
        open_handler = mock_open.return_value.__enter__.return_value
        mock_path_join.assert_called_once_with('/tmp', 'param_av_zone.json')
        mock_open.assert_called_once_with(param_file, 'w+')
        mock_json_dump.assert_called_once_with(data, open_handler)
        mock_create_vnf.assert_called_once_with(self.mock_tacker_client,
                                                'vnf_name',
                                                vnfd_name='vnfd_name',
                                                vim_name='vim_name',
                                                param_file=param_file)

    @patch('json.dump', autospec=True)
    @patch('__builtin__.open', autospec=True)
    @patch('sfc.lib.openstack_utils.create_vnffg', autospec=True)
    @patch('os.path.join', autospec=True, return_value='/tmp/param_name.json')
    def test_create_vnffg_with_param_file(self,
                                          mock_path_join,
                                          mock_create_vnffg,
                                          mock_open,
                                          mock_json_dump):
        """
        Checks the proper functionality of create_vnffg_with_param_file
        function
        """

        data = {
            'ip_dst_prefix': 'server_ip',
            'net_dst_port_id': 'server_port',
            'net_src_port_id': 'client_port'
        }
        param_file = '/tmp/param_name.json'
        os_sfc_utils.create_vnffg_with_param_file(self.mock_tacker_client,
                                                  'vnffgd_name',
                                                  'vnffg_name',
                                                  'default_param_file',
                                                  'client_port',
                                                  'server_port',
                                                  'server_ip')
        open_handler = mock_open.return_value.__enter__.return_value
        mock_path_join.assert_called_once_with('/tmp', 'param_vnffg_name.json')
        mock_open.assert_called_once_with(param_file, 'w+')
        mock_json_dump.assert_called_once_with(data, open_handler)
        mock_create_vnffg.assert_called_once_with(self.mock_tacker_client,
                                                  vnffgd_name='vnffgd_name',
                                                  vnffg_name='vnffg_name',
                                                  param_file=param_file,
                                                  symmetrical=True)
