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

import sfc.lib.odl_utils as odl_utils

__author__ = "Harshavardhan Reddy <venkataharshavardhan_ven@srmuniv.edu.in>"


class SfcOdlUtilsTesting(unittest.TestCase):

    @patch('re.compile', autospec=True)
    @patch('opnfv.utils.ovs_logger.OVSLogger', autospec=True)
    def test_actual_rsps_in_compute(self, mock_ovs_log, mock_compile):
        """
        Checks the proper functionality of actual_rsps_in_compute
        function
        """

        match_calls = [call('msg_1'), call('msg_2')]

        mf = Mock()
        mf.group.side_effect = ['msg_p_1', 'msg_p_2']
        mock_compile.return_value.match.side_effect = [mf, None]
        mock_ovs_log.ofctl_dump_flows.return_value = '\nflow_rep\nmsg_1\nmsg_2'

        result = odl_utils.actual_rsps_in_compute(mock_ovs_log, 'compute_ssh')

        self.assertEqual(['msg_p_1|msg_p_2'], result)
        mock_compile.return_value.match.assert_has_calls(match_calls)
        mock_ovs_log.ofctl_dump_flows.assert_called_once_with('compute_ssh',
                                                              'br-int', '101')

    @patch('sfc.lib.odl_utils.logger', autospec=True)
    @patch('sfc.lib.odl_utils.get_rsp', autospec=True)
    @patch('sfc.lib.odl_utils.get_odl_acl_list', autospec=True)
    @patch('sfc.lib.odl_utils.get_rsps_from_netvirt_acl_actions',
           autospec=True)
    def test_get_active_rsps_on_ports(self,
                                      mock_rsps_from_netvirt_acl_actions,
                                      mock_odl_acl_list,
                                      mock_get_rsp,
                                      mock_log):
        """
        Checks the proper functionality of get_active_rsps_on_ports
        function
        """

        log_calls = [call('ACL acl_obj_one does not have an ACE')]

        port_one = Mock()
        port_two = Mock()
        port_one.id = 's_p'
        port_two.id = 'd_p'
        neutron_ports = [port_one, port_two]

        mock_rsps_from_netvirt_acl_actions.return_value = ['rsp_obj_one',
                                                           'rsp_obj_two']

        mock_get_rsp.side_effect = [{'of-matches': ['of-match-one'],
                                     'reverse-path': 'r-path-one'},
                                    {'of-matches': ['of-match-two']}]

        mock_odl_acl_list.return_value = {'access-lists': {'acl': [
            {'acl-name': 'acl_obj_one',
             'access-list-entries': {'ace': []}},
            {'acl-name': 'acl_obj_two',
             'access-list-entries': {'ace': [{'matches': {
                 'destination-port-range': None}}]}},
            {'acl-name': 'acl_obj_three',
             'access-list-entries': {'ace': [{'matches': {
                 'destination-port-range': {'lower-port': 22},
                 'netvirt-sfc-acl:source-port-uuid': 's_p_uuid',
                 'netvirt-sfc-acl:destination-port-uuid': 'd_p_uuid'}}]}},
            {'acl-name': 'acl_obj_four',
             'access-list-entries': {'ace': [{'matches': {
                 'destination-port-range': {'lower-port': 22},
                 'netvirt-sfc-acl:source-port-uuid': 's_p',
                 'netvirt-sfc-acl:destination-port-uuid': 'd_p'},
                 'actions': 'm_actions'}]}}]}}

        expected = [{'of-matches': ['of-match-two', 'tp_dst=22']},
                    {'of-matches': ['of-match-one', 'tp_src=22'],
                     'reverse-path': 'r-path-one'}]

        result = odl_utils.get_active_rsps_on_ports('odl_ip',
                                                    'odl_port',
                                                    neutron_ports)

        self.assertEqual(sorted(expected), sorted(result))
        mock_log.warn.assert_has_calls(log_calls)
        mock_rsps_from_netvirt_acl_actions.assert_called_once_with('odl_ip',
                                                                   'odl_port',
                                                                   'm_actions')

    @patch('sfc.lib.odl_utils.get_odl_resource_elem', autospec=True)
    def test_get_rsps_from_netvirt_acl_actions(self, mock_odl_resource_elem):
        """
        Checks the proper functionality of get_rsps_from_netvirt_acl_actions
        function
        """

        netv = {'netvirt-sfc-acl:rsp-name': 'rsp-name',
                'netvirt-sfc-acl:sfp-name': 'sfp-name'}

        sfp_state = {'sfp-rendered-service-path': [{'name': 'sfp-rsp-one'},
                                                   {'name': 'sfp-rsp-two'}]}

        mock_odl_resource_elem.return_value = sfp_state
        rsp_names = ['rsp-name', 'sfp-rsp-one', 'sfp-rsp-two']

        result = odl_utils.get_rsps_from_netvirt_acl_actions('odl_ip',
                                                             'odl_port',
                                                             netv)
        self.assertEqual(rsp_names, result)
        mock_odl_resource_elem.assert_called_once_with('odl_ip', 'odl_port',
                                                       'service-function-path-'
                                                       'state', 'sfp-name',
                                                       datastore='operational')

    @patch('sfc.lib.odl_utils.get_odl_resource_elem',
           autospec=True, return_value='mocked_rsp')
    def test_get_rsp(self, mock_odl_resource_elem):
        """
        Checks the proper functionality of get_rsp
        function
        """

        result = odl_utils.get_rsp('odl_ip', 'odl_port', 'rsp_name')
        self.assertEqual('mocked_rsp', result)
        mock_odl_resource_elem.assert_called_once_with('odl_ip', 'odl_port',
                                                       'rendered-service-path',
                                                       'rsp_name',
                                                       datastore='operational')

    @patch('sfc.lib.odl_utils.get_active_rsps_on_ports', autospec=True)
    def test_promised_rsps_in_compute(self, mock_active_rsps_on_ports):
        """
        Checks the proper functionality of propmised_rsps_in_compute
        function
        """

        mock_active_rsps_on_ports.return_value = [
            {'of-matches': {'one': 'one'}, 'path-id': 1},
            {'of-matches': {'two': 'two'}, 'path-id': 2}]

        result = odl_utils.promised_rsps_in_compute('odl_ip', 'odl_port',
                                                    'compute_ports')

        self.assertEqual(['0x1|one', '0x2|two'], result)
        mock_active_rsps_on_ports.assert_called_once_with('odl_ip', 'odl_port',
                                                          'compute_ports')

    @patch('sfc.lib.odl_utils.logger', autospec=True)
    @patch('time.time', autospec=True, side_effect=[1, 2])
    def test_timethis(self,
                      mock_time,
                      mock_log):
        """
        Checks the proper functionality of timethis
        function
        """

        expected = ('mock_this', '1')
        log_calls = [call("mock_func(*('mock',), **{'name': 'this'}) "
                          "took: 1 sec")]

        @odl_utils.timethis
        def mock_func(msg, name=''):
            return msg+'_'+name

        result = mock_func('mock', name='this')
        self.assertEqual(result, expected)
        mock_log.info.assert_has_calls(log_calls)

    @patch('time.sleep', autospec=True)
    @patch('sfc.lib.odl_utils.logger', autospec=True)
    @patch('sfc.lib.odl_utils.find_compute', autospec=True)
    @patch('sfc.lib.odl_utils.get_odl_items', autospec=True)
    @patch('sfc.lib.odl_utils.promised_rsps_in_compute', autospec=True)
    @patch('sfc.lib.odl_utils.os_sfc_utils.get_tacker_items', autospec=True)
    def test_wait_for_classification_rules_rsps_not_configured(
            self, mock_get_tacker_items, mock_promised_rsps_in_compute,
            mock_get_odl_items, mock_find_compute, mock_log, mock_sleep):
        """
        Checks the proper functionality of wait_for_classification_rules
        function when rsps are not configured in ODL
        """

        log_calls = [call("Error when waiting for classification rules: "
                          "RSPs not configured in ODL")]

        mock_find_compute.return_value = 'mock_compute'
        mock_promised_rsps_in_compute.return_value = None

        odl_utils.wait_for_classification_rules('ovs_logger',
                                                'compute_nodes',
                                                'odl_ip',
                                                'odl_port',
                                                'compute_name',
                                                'neutron_ports')
        mock_promised_rsps_in_compute.assert_called_with('odl_ip',
                                                         'odl_port',
                                                         'neutron_ports')
        assert mock_promised_rsps_in_compute.call_count == 10
        mock_find_compute.assert_called_once_with('compute_name',
                                                  'compute_nodes')
        mock_sleep.assert_called_with(3)
        assert mock_sleep.call_count == 9
        mock_get_tacker_items.assert_called_once_with()
        mock_get_odl_items.assert_called_once_with('odl_ip', 'odl_port')
        mock_log.error.assert_has_calls(log_calls)

    @patch('time.sleep', autospec=True)
    @patch('sfc.lib.odl_utils.logger', autospec=True)
    @patch('sfc.lib.odl_utils.find_compute', autospec=True)
    @patch('sfc.lib.odl_utils.actual_rsps_in_compute', autospec=True)
    @patch('sfc.lib.odl_utils.promised_rsps_in_compute', autospec=True)
    def test_wait_for_classification_rules_timeout_not_updated(
            self, mock_promised_rsps_in_compute, mock_actual_rsps_in_compute,
            mock_find_compute, mock_log, mock_sleep):
        """
        Checks the proper functionality of wait_for_classification_rules
        function when classification rules are not updated in a given timeout
        """

        log_calls = [call("Timeout but classification rules are not updated"),
                     call("RSPs in ODL Operational DataStore"
                          "for compute 'compute_name':"),
                     call("['compute|rsps']"),
                     call("RSPs in compute nodes:"),
                     call("[]")]

        mock_compute = Mock()
        mock_compute.ssh_client = 'mock_ssh_client'
        mock_find_compute.return_value = mock_compute
        mock_actual_rsps_in_compute.return_value = []
        mock_promised_rsps_in_compute.return_value = ['compute|rsps']

        odl_utils.wait_for_classification_rules('ovs_logger',
                                                'compute_nodes',
                                                'odl_ip',
                                                'odl_port',
                                                'compute_name',
                                                'neutron_ports',
                                                timeout=2)
        mock_find_compute.assert_called_once_with('compute_name',
                                                  'compute_nodes')
        mock_log.error.assert_has_calls(log_calls[:1])
        mock_log.info.assert_has_calls(log_calls[1:])

    @patch('time.sleep', autospec=True)
    @patch('sfc.lib.odl_utils.logger', autospec=True)
    @patch('sfc.lib.odl_utils.find_compute', autospec=True)
    @patch('sfc.lib.odl_utils.actual_rsps_in_compute', autospec=True)
    @patch('sfc.lib.odl_utils.promised_rsps_in_compute', autospec=True)
    def test_wait_for_classification_rules_updated(
            self, mock_promised_rsps_in_compute, mock_actual_rsps_in_compute,
            mock_find_compute, mock_log, mock_sleep):
        """
        Checks the proper functionality of wait_for_classification_rules
        function when classification rules are not updated in a given timeout
        """

        log_calls = [call("RSPs in ODL Operational DataStore"
                          "for compute 'compute_name':"),
                     call("['compute|rsps']"),
                     call("RSPs in compute nodes:"),
                     call("['compute|rsps']"),
                     call("Classification rules were updated")]
        mock_compute = Mock()
        mock_compute.ssh_client = 'mock_ssh_client'
        mock_find_compute.return_value = mock_compute
        mock_actual_rsps_in_compute.return_value = ['compute|rsps']
        mock_promised_rsps_in_compute.return_value = ['compute|rsps']

        odl_utils.wait_for_classification_rules('ovs_logger',
                                                'compute_nodes',
                                                'odl_ip',
                                                'odl_port',
                                                'compute_name',
                                                'neutron_ports',
                                                timeout=2)
        mock_log.info.assert_has_calls(log_calls)

    @patch('re.search', autospec=True)
    @patch('ConfigParser.RawConfigParser', autospec=True)
    @patch('os.getcwd', autospec=True, return_value='/etc')
    @patch('os.path.join', autospec=True, return_value='/etc/ml2_conf.ini')
    def test_get_odl_ip_port(self, mock_join,
                             mock_getcwd,
                             mock_rawconfigparser,
                             mock_search):
        """
        Checks the proper functionality of get_odl_ip_port
        function
        """

        cmd_calls = [call('pwd'),
                     call('sudo cp /etc/neutron/plugins/ml2/ml2_conf.ini '
                          '/etc/'),
                     call('sudo chmod 777 /etc/ml2_conf.ini')]

        n1 = Mock()
        n2 = Mock()
        nodes = [n1, n2]
        mock_rawconfigparser.return_value.get.return_value = 'config'
        mock_search.return_value.group.return_value = 'odl_ip:odl_port'
        n1.run_cmd.side_effect = ['/etc', '', '']

        result = odl_utils.get_odl_ip_port(nodes)
        self.assertEqual(('odl_ip', 'odl_port'), result)
        n1.run_cmd.assert_has_calls(cmd_calls)
        n1.is_controller.assert_called_once_with()
        mock_getcwd.assert_called_once_with()
        mock_join.assert_called_once_with('/etc', 'ml2_conf.ini')
        n1.get_file.assert_called_once_with('/etc/ml2_conf.ini',
                                            '/etc/ml2_conf.ini')
        mock_rawconfigparser.return_value.read.assert_called_once_with(
            '/etc/ml2_conf.ini')
        mock_rawconfigparser.return_value.get.assert_called_with(
            'ml2_odl', 'url')
        mock_search.assert_called_once_with(r'[0-9]+(?:\.[0-9]+){3}\:[0-9]+',
                                            'config')

    def test_pluralize(self):
        """
        Checks the proper functionality of pluralize
        function
        """

        result = odl_utils.pluralize('service-function-path')
        self.assertEqual('service-function-paths', result)

    def test_get_module(self):
        """
        Checks the proper functionality of get_module
        function
        """

        result = odl_utils.get_module('service-function-path')
        self.assertEqual('service-function-path', result)

    @patch('sfc.lib.odl_utils.get_module',
           autospec=True, return_value='mocked_module')
    @patch('sfc.lib.odl_utils.pluralize',
           autospec=True, return_value='resources')
    def test_format_odl_resource_list_url(self, mock_plularize,
                                          mock_get_module):
        """
        Checks the proper functionality of format_odl_resource_list_url
        function
        """

        result = odl_utils.format_odl_resource_list_url('odl_ip',
                                                        'odl_port',
                                                        'resource')
        formatted_url = ('http://admin:admin@odl_ip:'
                         'odl_port/restconf/config/mocked_module:'
                         'resources')
        self.assertEqual(formatted_url, result)
        mock_plularize.assert_called_once_with('resource')
        mock_get_module.assert_called_once_with('resource')

    @patch('sfc.lib.odl_utils.format_odl_resource_list_url',
           autospec=True, return_value='list_u/r/l')
    def test_format_odl_resource_elem_url(self, mock_odl_resource_list_url):
        """
        Checks the proper functionality of format_odl_resource_elem_url
        function
        """

        result = odl_utils.format_odl_resource_elem_url('odl_ip', 'odl_port',
                                                        'resource',
                                                        'elem_name')
        formatted_url = ('list_u/r/l/resource/elem_name')
        self.assertEqual(formatted_url, result)
        mock_odl_resource_list_url.assert_called_once_with('odl_ip',
                                                           'odl_port',
                                                           'resource',
                                                           'config')

    @patch('sfc.lib.odl_utils.pluralize',
           autospec=True, return_value='resources')
    def test_odl_resource_list_names_returns_empty_list(self, mock_plularize):
        """
        Checks the proper functionality of odl_resource_list_names
        function when resources are empty
        """

        resource_json = {'resources': {}}
        result = odl_utils.odl_resource_list_names('resource', resource_json)
        self.assertEqual([], result)

    @patch('sfc.lib.odl_utils.pluralize',
           autospec=True, return_value='resources')
    def test_odl_resource_list_names(self, mock_plularize):
        """
        Checks the proper functionality of odl_resource_list_names
        function
        """

        resource_json = {'resources': {'resource': [{'name': 'resource_one'},
                                                    {'name': 'resource_two'}]}}
        result = odl_utils.odl_resource_list_names('resource', resource_json)
        self.assertEqual(['resource_one', 'resource_two'], result)

    @patch('requests.get', autospec=True)
    @patch('sfc.lib.odl_utils.format_odl_resource_list_url', autospec=True)
    def test_get_odl_resource_list(self,
                                   mock_odl_resource_list_url,
                                   mock_get):
        """
        Checks the proper functionality of get_odl_resource_list
        function
        """

        mock_odl_resource_list_url.return_value = 'u/r/l'
        mock_get.return_value.json.return_value = {'key': 'value'}

        result = odl_utils.get_odl_resource_list('odl_ip',
                                                 'odl_port',
                                                 'resource')

        self.assertEqual({'key': 'value'}, result)
        mock_odl_resource_list_url.assert_called_once_with('odl_ip',
                                                           'odl_port',
                                                           'resource',
                                                           datastore='config')
        mock_get.assert_called_once_with('u/r/l')

    @patch('requests.get', autospec=True)
    @patch('sfc.lib.odl_utils.format_odl_resource_elem_url', autospec=True)
    def test_get_odl_resource_elem(self,
                                   mock_odl_resource_elem_url,
                                   mock_get):
        """
        Checks the proper functionality of get_odl_resource_elem
        function
        """

        mock_response = Mock()
        mock_response.get.return_value = ['elem_one', 'elem_two']
        mock_get.return_value.json.return_value = mock_response
        mock_odl_resource_elem_url.return_value = 'u/r/l'

        result = odl_utils.get_odl_resource_elem(
            'odl_ip', 'odl_port', 'resource', 'elem_name')

        self.assertEqual('elem_one', result)
        mock_odl_resource_elem_url.assert_called_once_with(
            'odl_ip', 'odl_port', 'resource', 'elem_name', 'config')
        mock_get.assert_called_once_with('u/r/l')
        mock_response.get.assert_called_once_with('resource', [{}])

    @patch('requests.delete', autospec=True)
    @patch('sfc.lib.odl_utils.format_odl_resource_elem_url',
           autospec=True, return_value='u/r/l')
    def test_delete_odl_resource_elem(self,
                                      mock_odl_resource_elem_url,
                                      mock_delete):
        """
        Checks the proper functionality of delete_odl_resource_elem
        function
        """

        odl_utils.delete_odl_resource_elem('odl_ip', 'odl_port', 'resource',
                                           'elem_name')

        mock_odl_resource_elem_url('odl_ip', 'odl_port', 'resource',
                                   'elem_name', 'config')
        mock_delete.assert_called_once_with('u/r/l')

    def test_odl_acl_types_names_returns_empty_list(self):
        """
        Checks the proper functionality of odl_acl_types_names
        function when access lists are empty
        """

        acl_json = {'access-lists': {}}
        result = odl_utils.odl_acl_types_names(acl_json)
        self.assertEqual([], result)

    def test_odl_acl_types_names(self):
        """
        Checks the proper functionality of odl_acl_types_names
        function
        """

        acl_json = {'access-lists': {'acl': [{'acl-type': 'type-one',
                                              'acl-name': 'name-one'},
                                             {'acl-type': 'type-two',
                                              'acl-name': 'name-two'}]}}
        acl_types = [('type-one', 'name-one'),
                     ('type-two', 'name-two')]

        result = odl_utils.odl_acl_types_names(acl_json)
        self.assertEqual(acl_types, result)

    def test_format_odl_acl_list_url(self):
        """
        Checks the proper functionality of format_odl_acl_list_url
        function
        """

        formatted_url = ('http://admin:admin@odl_ip:odl_port/restconf/config/'
                         'ietf-access-control-list:access-lists')
        result = odl_utils.format_odl_acl_list_url('odl_ip', 'odl_port')
        self.assertEqual(formatted_url, result)

    @patch('json.dumps',
           autospec=True, return_value='{\n    "key": "value"\n}')
    def test_improve_json_layout(self, mock_dumps):
        """
        Checks the proper functionality of improve_json_layout
        function
        """

        result = odl_utils.improve_json_layout({'key': 'value'})

        self.assertEqual('{\n    "key": "value"\n}', result)
        mock_dumps.assert_called_once_with({'key': 'value'},
                                           indent=4,
                                           separators=(',', ': '))

    @patch('requests.get', autospec=True)
    @patch('sfc.lib.odl_utils.logger', autospec=True)
    @patch('sfc.lib.odl_utils.format_odl_acl_list_url',
           autospec=True, return_value='acl_list_u/r/l')
    @patch('sfc.lib.odl_utils.improve_json_layout', autospec=True)
    @patch('sfc.lib.odl_utils.format_odl_resource_list_url', autospec=True)
    def test_get_odl_items(self,
                           mock_odl_resource_list_url,
                           mock_json_layout,
                           mock_odl_acl_list_url,
                           mock_log,
                           mock_get):
        """
        Checks the proper functionality of get_odl_items
        function
        """

        log_calls = [call('Configured ACLs in ODL: r_acl_j_s_o_n'),
                     call('Configured SFs in ODL: r_sf_j_s_o_n'),
                     call('Configured SFFs in ODL: r_sff_j_s_o_n'),
                     call('Configured SFCs in ODL: r_sfc_j_s_o_n'),
                     call('Configured RSPs in ODL: r_sp_j_s_o_n')]

        resource_list_url_calls = [call('odl_ip', 'odl_port',
                                        'service-function'),
                                   call('odl_ip', 'odl_port',
                                        'service-function-forwarder'),
                                   call('odl_ip', 'odl_port',
                                        'service-function-chain'),
                                   call('odl_ip', 'odl_port',
                                        'rendered-service-path',
                                        datastore='operational')]

        resource_list_urls = ['sf_list_u/r/l', 'sff_list_u/r/l',
                              'sfc_list_u/r/l', 'rsp_list_u/r/l']

        get_calls = [call(url) for url in resource_list_urls]

        mock_odl_resource_list_url.side_effect = resource_list_urls

        mock_get.return_value.json.side_effect = ['r_acl_json', 'r_sf_json',
                                                  'r_sff_json', 'r_sfc_json',
                                                  'r_rsp_json']

        mock_json_layout.side_effect = ['r_acl_j_s_o_n', 'r_sf_j_s_o_n',
                                        'r_sff_j_s_o_n', 'r_sfc_j_s_o_n',
                                        'r_sp_j_s_o_n']

        odl_utils.get_odl_items('odl_ip', 'odl_port')

        mock_odl_acl_list_url.assert_called_once_with('odl_ip', 'odl_port')
        mock_odl_resource_list_url.assert_has_calls(resource_list_url_calls)
        mock_get.assert_has_calls(get_calls, any_order=True)
        mock_log.debug.assert_has_calls(log_calls)

    @patch('requests.get', autospec=True)
    @patch('sfc.lib.odl_utils.format_odl_acl_list_url', autospec=True)
    def test_get_odl_acl_list(self,
                              mock_acl_list_url,
                              mock_get):
        """
        Checks the proper functionality of get_odl_acl_list
        function
        """

        mock_acl_list_url.return_value = 'acl_list/url'
        mock_get.return_value.json.return_value = {'key': 'value'}
        result = odl_utils.get_odl_acl_list('odl_ip', 'odl_port')
        mock_acl_list_url.assert_called_once_with('odl_ip', 'odl_port')
        mock_get.assert_called_once_with('acl_list/url')
        self.assertEqual({'key': 'value'}, result)

    @patch('requests.delete', autospec=True)
    @patch('sfc.lib.odl_utils.format_odl_acl_list_url', autospec=True)
    def test_delete_odl_acl(self,
                            mock_acl_list_url,
                            mock_delete):
        """
        Checks the proper functionality of delete_odl_acl
        function
        """

        mock_acl_list_url.return_value = 'acl_list/url'

        odl_utils.delete_odl_acl('odl_ip', 'odl_port', 'acl_type', 'acl_name')

        mock_acl_list_url.assert_called_once_with('odl_ip', 'odl_port')
        mock_delete.assert_called_once_with(
            'acl_list/url/acl/acl_type/acl_name')

    @patch('sfc.lib.odl_utils.delete_odl_acl', autospec=True)
    def test_delete_acl(self, mock_delete_odl_acl):
        """
        Checks the proper fucntionality of delete_acl
        function
        """

        odl_utils.delete_acl('clf_name', 'odl_ip', 'odl_port')
        mock_delete_odl_acl.assert_called_once_with(
            'odl_ip',
            'odl_port',
            'ietf-access-control-list:ipv4-acl',
            'clf_name')

    @patch('sfc.lib.odl_utils.logger', autospec=True)
    def test_find_compute_raises_exception(self, mock_log):
        """
        Checks the proper functionality of find_compute
        function when compute was not found in the client
        """

        ErrorMSG = 'No compute, where the client is, was found'
        compute_node_one = Mock()
        compute_node_two = Mock()
        compute_nodes = [compute_node_one, compute_node_two]
        compute_node_one.name = 'compute_one'
        compute_node_two.name = 'compute_two'

        with self.assertRaises(Exception) as cm:
            odl_utils.find_compute('compute_client', compute_nodes)

        self.assertEqual(ErrorMSG, cm.exception.message)
        mock_log.debug.assert_called_once_with(ErrorMSG)

    @patch('sfc.lib.odl_utils.logger', autospec=True)
    def test_find_compute(self, mock_log):
        """
        Checks the proper functionality of find_compute
        function when compute was not found in the client
        """

        compute_node_one = Mock()
        compute_node_two = Mock()
        compute_nodes = [compute_node_one, compute_node_two]
        compute_node_one.name = 'compute_one'
        compute_node_two.name = 'compute_two'

        result = odl_utils.find_compute('compute_two', compute_nodes)

        self.assertEqual(compute_node_two, result)

    @patch('time.sleep', autospec=True)
    @patch('sfc.lib.odl_utils.logger', autospec=True)
    @patch('sfc.lib.odl_utils.get_active_rsps_on_ports', autospec=True)
    def test_check_vnffg_deletion_returns_false_rsps_still_active(
            self, mock_active_rsps_on_ports,
            mock_log, mock_sleep):
        """
        Checks the proper functionality of check_vnffg_deletion
        function to verify that it returns false on the given condition
        """

        log_calls = [call('RSPs are still active in the MD-SAL')]
        mock_active_rsps_on_ports.return_value = True
        result = odl_utils.check_vnffg_deletion('odl_ip', 'odl_port',
                                                'ovs_logger', 'neutron_ports',
                                                'compute_client_name',
                                                'compute_nodes', retries=1)
        self.assertFalse(result)
        mock_active_rsps_on_ports.assert_called_once_with('odl_ip', 'odl_port',
                                                          'neutron_ports')
        mock_sleep.assert_called_once_with(3)
        mock_log.debug.assert_has_calls(log_calls)

    @patch('time.sleep', autospec=True)
    @patch('sfc.lib.odl_utils.logger', autospec=True)
    @patch('sfc.lib.odl_utils.find_compute', autospec=True)
    @patch('sfc.lib.odl_utils.actual_rsps_in_compute', autospec=True)
    @patch('sfc.lib.odl_utils.get_active_rsps_on_ports', autospec=True)
    def test_check_vnffg_deletion_returns_false_error_getting_compute(
            self, mock_active_rsps_on_ports, mock_actual_rsps,
            mock_find_compute, mock_log, mock_sleep):
        """
        Checks the proper functionality of check_vnffg_deletion
        function to verify that it returns false on the given condition
        """

        log_calls = [call('There was an error getting the compute: ErrorMSG')]
        mock_compute = Mock()
        mock_compute.ssh_client = 'mock_ssh_client'
        mock_find_compute.side_effect = [Exception('ErrorMSG'), mock_compute]
        mock_active_rsps_on_ports.side_effect = [True, False]
        result = odl_utils.check_vnffg_deletion('odl_ip', 'odl_port',
                                                'ovs_logger', 'neutron_ports',
                                                'compute_client_name',
                                                'compute_nodes', retries=2)
        self.assertFalse(result)
        mock_sleep.assert_called_once_with(3)
        mock_find_compute.assert_called_once_with('compute_client_name',
                                                  'compute_nodes')
        mock_log.debug.assert_has_calls(log_calls)

    @patch('time.sleep', autospec=True)
    @patch('sfc.lib.odl_utils.logger', autospec=True)
    @patch('sfc.lib.odl_utils.find_compute', autospec=True)
    @patch('sfc.lib.odl_utils.actual_rsps_in_compute', autospec=True)
    @patch('sfc.lib.odl_utils.get_active_rsps_on_ports', autospec=True)
    def test_check_vnffg_deletion_returns_false_classification_flow_in_compute(
            self, mock_active_rsps_on_ports, mock_actual_rsps,
            mock_find_compute, mock_log, mock_sleep):
        """
        Checks the proper functionality of check_vnffg_deletion
        function to verify that it returns false on the given condition
        """

        log_calls = [call('Classification flows still in the compute')]
        mock_compute = Mock()
        mock_compute.ssh_client = 'mock_ssh_client'
        mock_find_compute.return_value = mock_compute
        mock_actual_rsps.side_effect = [True, True]
        mock_active_rsps_on_ports.side_effect = [True, False]
        result = odl_utils.check_vnffg_deletion('odl_ip', 'odl_port',
                                                'ovs_logger', 'neutron_ports',
                                                'compute_client_name',
                                                'compute_nodes', retries=2)
        self.assertFalse(result)
        mock_actual_rsps.assert_called_with('ovs_logger', 'mock_ssh_client')
        mock_sleep.assert_called_with(3)
        mock_find_compute.assert_called_once_with('compute_client_name',
                                                  'compute_nodes')
        assert mock_sleep.call_count == 3
        mock_log.debug.assert_has_calls(log_calls)

    @patch('time.sleep', autospec=True)
    @patch('sfc.lib.odl_utils.logger', autospec=True)
    @patch('sfc.lib.odl_utils.find_compute', autospec=True)
    @patch('sfc.lib.odl_utils.actual_rsps_in_compute', autospec=True)
    @patch('sfc.lib.odl_utils.get_active_rsps_on_ports', autospec=True)
    def test_check_vnffg_deletion_returns_true(self,
                                               mock_active_rsps_on_ports,
                                               mock_actual_rsps,
                                               mock_find_compute,
                                               mock_log, mock_sleep):
        """
        Checks the proper functionality of check_vnffg_deletion
        function to verify that it returns true
        """

        mock_compute = Mock()
        mock_compute.ssh_client = 'mock_ssh_client'
        mock_active_rsps_on_ports.side_effect = [True, False]

        mock_actual_rsps.side_effect = [True, False]

        mock_find_compute.return_value = mock_compute

        result = odl_utils.check_vnffg_deletion('odl_ip', 'odl_port',
                                                'ovs_logger', 'neutron_ports',
                                                'compute_client_name',
                                                'compute_nodes', retries=2)
        self.assertTrue(result)
        mock_find_compute.assert_called_once_with('compute_client_name',
                                                  'compute_nodes')
        assert mock_sleep.call_count == 2
        mock_log.assert_not_called()
