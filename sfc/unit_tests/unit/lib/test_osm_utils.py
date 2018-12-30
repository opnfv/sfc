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
from mock import patch

import sfc.lib.osm_utils as osm_utils

__author__ = "Harshavardhan Reddy <venkataharshavardhan_ven@srmuniv.edu.in>"


class SfcOsmUtilsTesting(unittest.TestCase):

    def setUp(self):
        self.patcher = patch.object(osm_utils.client, 'Client')
        self.osm_client = self.patcher.start()

    def tearDown(self):
        self.patcher.stop()

    @patch('os.getenv', autospec=True, return_value=None)
    @patch('sfc.lib.osm_utils.logger', autospec=True)
    def test_get_osm_host_returns_default(self, mock_log, mock_os_getenv):
        """
        Checks the proper functionality of get_osm_host function
        when OSM_HOSTNAME is not found in environment variables
        """

        result = osm_utils.get_osm_host()
        self.assertEqual(result, osm_utils.DEFAULT_OSM_HOSTNAME)
        mock_os_getenv.assert_called_once_with('OSM_HOSTNAME')
        mock_log.info.assert_not_called()

    @patch('os.getenv', autospec=True)
    @patch('sfc.lib.osm_utils.logger', autospec=True)
    def test_get_osm_host_returns_hostname(self, mock_log, mock_os_getenv):
        """
        Checks the proper functionality of get_osm_host function
        when OSM_HOSTNAME is found in environment variables
        """

        osm_hostname = '1.2.3.4'
        mock_os_getenv.return_value = osm_hostname
        log_calls = [call("OSM_HOSTNAME is set in env as {}"
                          .format(osm_hostname))]
        result = osm_utils.get_osm_host()
        self.assertEqual(result, osm_hostname)
        mock_os_getenv.assert_called_once_with('OSM_HOSTNAME')
        mock_log.info.assert_has_calls(log_calls)

    @patch('sfc.lib.osm_utils.get_osm_host', autospec=True)
    def test_get_osm_client(self, mock_get_osm_host):
        """
        Checks the proper functionality of get_osm_client function
        """

        osm_hostname = '1.2.3.4'
        mock_get_osm_host.return_value = osm_hostname
        result = osm_utils.get_osm_client()
        assert result is self.osm_client.return_value
        self.osm_client.assert_called_once_with(host=osm_hostname,
                                                sol005=True)

    @patch('os.getenv', autospec=True)
    @patch('sfc.lib.osm_utils.logger', autospec=True)
    def test_vim_register_returns_none(self, mock_log, mock_os_getenv):
        """
        Checks the proper functionality of vim_create function
        when it raises an Exception
        """

        mock_vim_name = 'test-vim'
        ErrorMSG = "Failed to create VIM: {}".format(mock_vim_name)
        self.osm_client.vim.create.side_effect = Exception(ErrorMSG)

        mock_env_variables = {
            'OS_USERNAME': 'mock_username',
            'OS_PASSWORD': 'mock_password',
            'OS_AUTH_URL': 'mock_auth_url',
            'OS_TENANT_NAME': 'mock_tenant_name'
        }

        mock_vim = {
            'vim-username': mock_env_variables['OS_USERNAME'],
            'vim-password': mock_env_variables['OS_PASSWORD'],
            'vim-url': mock_env_variables['OS_AUTH_URL'],
            'vim-tenant-name': mock_env_variables['OS_TENANT_NAME'],
            'vim-type': 'openstack',
            'description': 'openstack-site',
            'config': None
        }

        mock_os_getenv.side_effect = [mock_env_variables['OS_USERNAME'],
                                      mock_env_variables['OS_PASSWORD'],
                                      mock_env_variables['OS_AUTH_URL'],
                                      mock_env_variables['OS_TENANT_NAME']]

        log_calls = [call("Error [create_vim(osm_client, {}, {}, {}, {})]: {}"
                          .format(mock_vim_name, mock_vim, None, None,
                                  ErrorMSG))]

        result = osm_utils.vim_register(self.osm_client, 'test-vim')
        assert result is None
        self.osm_client.vim.create.assert_called_once_with(
            'test-vim', mock_vim, sdn_controller=None, sdn_port_mapping=None)
        mock_log.error.assert_has_calls(log_calls)

    @patch('os.getenv', autospec=True)
    @patch('sfc.lib.osm_utils.logger', autospec=True)
    def test_vim_register(self, mock_log, mock_os_getenv):
        """
        Checks the proper functionality of vim_create function
        """

        mock_vim_name = 'test-vim'
        mock_env_variables = {
            'OS_USERNAME': 'mock_username',
            'OS_PASSWORD': 'mock_password',
            'OS_AUTH_URL': 'mock_auth_url',
            'OS_TENANT_NAME': 'mock_tenant_name'
        }

        mock_vim = {
            'vim-username': mock_env_variables['OS_USERNAME'],
            'vim-password': mock_env_variables['OS_PASSWORD'],
            'vim-url': mock_env_variables['OS_AUTH_URL'],
            'vim-tenant-name': mock_env_variables['OS_TENANT_NAME'],
            'vim-type': 'openstack',
            'description': 'openstack-site',
            'config': None
        }

        mock_os_getenv.side_effect = [mock_env_variables['OS_USERNAME'],
                                      mock_env_variables['OS_PASSWORD'],
                                      mock_env_variables['OS_AUTH_URL'],
                                      mock_env_variables['OS_TENANT_NAME']]

        result = osm_utils.vim_register(self.osm_client, mock_vim_name)
        assert result is self.osm_client.vim.create.return_value
        self.osm_client.vim.create.assert_called_once_with(
            mock_vim_name, mock_vim, sdn_controller=None,
            sdn_port_mapping=None)
        mock_log.error.assert_not_called()

    @patch('sfc.lib.osm_utils.logger', autospec=True)
    def test_vim_list_returns_none(self, mock_log):
        """
        Checks the proper functionality of vim_list function
        when it raises an Exception
        """

        ErrorMSG = "Failed to list VIMs"
        self.osm_client.vim.list.side_effect = Exception(ErrorMSG)
        log_calls = [call("Error [vim_list(osm_client, {}, {})]: {}"
                          .format(None, False, ErrorMSG))]
        result = osm_utils.vim_list(self.osm_client)
        assert result is None
        self.osm_client.vim.list.assert_called_once_with(filter=None)
        mock_log.error.assert_has_calls(log_calls)

    @patch('sfc.lib.osm_utils.logger', autospec=True)
    def test_vim_list(self, mock_log):
        """
        Checks the proper functionality of vim_list function
        """

        mock_vim_uuid = 'vim-abyz'
        self.osm_client.vim.list.return_value = [{'uuid': mock_vim_uuid}]
        result = osm_utils.vim_list(self.osm_client)
        self.assertEqual(result, [mock_vim_uuid])
        self.osm_client.vim.list.assert_called_once_with(filter=None)
        mock_log.error.assert_not_called()

    @patch('sfc.lib.osm_utils.logger', autospec=True)
    def test_vim_delete_returns_none(self, mock_log):
        """
        Checks the proper functionality of vim_delete function
        when it raises an Exception
        """

        mock_vim_name = 'test-vim'
        ErrorMSG = "Failed to delete VIM: {}".format(mock_vim_name)
        self.osm_client.vim.delete.side_effect = Exception(ErrorMSG)
        log_calls = [call("Error [vim_delete(osm_client, {}, {})]: {}"
                          .format(mock_vim_name, False, ErrorMSG))]
        result = osm_utils.vim_delete(self.osm_client, mock_vim_name)
        assert result is None
        self.osm_client.vim.delete.assert_called_once_with(mock_vim_name,
                                                           force=False)
        mock_log.error.assert_has_calls(log_calls)

    @patch('sfc.lib.osm_utils.logger', autospec=True)
    def test_vim_delete(self, mock_log):
        """
        Checks the proper functionality of vim_delete function
        """

        mock_vim_name = 'test-vim'
        result = osm_utils.vim_delete(self.osm_client, mock_vim_name)
        assert result is self.osm_client.vim.delete.return_value
        self.osm_client.vim.delete.assert_called_once_with(mock_vim_name,
                                                           force=False)
        mock_log.error.assert_not_called()

    @patch('sfc.lib.osm_utils.logger', autospec=True)
    def test_vnfd_create_returns_none(self, mock_log):
        """
        Checks the proper functionality of vnfd_create function
        when it raises an Exception
        """

        mock_vnfd_name = 'test-vnfd'
        mock_vnfd_file = 'test-vnfd.yaml'
        ErrorMSG = "Failed to create VNFD: {}".format(mock_vnfd_name)
        self.osm_client.vnfd.create.side_effect = Exception(ErrorMSG)
        log_calls = [call("Error [vnfd_create(osm_client, {}, {})]: {}"
                          .format(mock_vnfd_file, None, ErrorMSG))]
        result = osm_utils.vnfd_create(self.osm_client,
                                       mock_vnfd_name,
                                       mock_vnfd_file)
        assert result is None
        self.osm_client.vnfd.create.assert_called_once_with(mock_vnfd_file,
                                                            overwrite=None)
        mock_log.error.assert_has_calls(log_calls)

    @patch('sfc.lib.osm_utils.logger', autospec=True)
    def test_vnfd_create(self, mock_log):
        """
        Checks the proper functionality of vnfd_create function
        """

        mock_vnfd_name = 'test-vnfd'
        mock_vnfd_file = 'test-vnfd.yaml'
        log_calls = [call("Creating the VNFD... {}".format(mock_vnfd_name))]
        result = osm_utils.vnfd_create(self.osm_client,
                                       mock_vnfd_name,
                                       mock_vnfd_file)
        self.osm_client.vnfd.create.assert_called_once_with(mock_vnfd_file,
                                                            overwrite=None)
        assert result is self.osm_client.vnfd.create.return_value
        mock_log.info.assert_has_calls(log_calls)

    @patch('sfc.lib.osm_utils.logger', autospec=True)
    def test_vnfd_list_returns_none(self, mock_log):
        """
        Checks the proper functionality of vnfd_list function
        when it raises an Exception due to wrong value for nf_type
        """

        nf_type = 'mock_nf'
        ErrorMSG = ("wrong value for 'nf_type' argument, allowed "
                    "values: vnf, pnf, hnf")
        log_calls = [call("Error [vnfd_list(osm_client, {}, {}, {})]: {}"
                          .format(nf_type, None, False, ErrorMSG))]
        result = osm_utils.vnfd_list(self.osm_client, nf_type=nf_type)
        assert result is None
        self.osm_client.vnfd.list.assert_not_called()
        mock_log.error.assert_has_calls(log_calls)

    @patch('sfc.lib.osm_utils.logger', autospec=True)
    def test_vnfd_list_one(self, mock_log):
        """
        Checks the proper functionality of vnfd_list function
        when given nf_type is vnf and _filter is None
        """

        mock_vnfd_id = 'test-x-chain-vnfd'
        _nf_type = 'vnf'
        self.osm_client.vnfd.list.return_value = [{'id': mock_vnfd_id}]
        result = osm_utils.vnfd_list(self.osm_client, nf_type=_nf_type)
        self.assertEqual(result, [mock_vnfd_id])
        self.osm_client.vnfd.list.assert_called_once_with(
            filter="_admin.type={}d".format(_nf_type))
        mock_log.error.assert_not_called()

    @patch('sfc.lib.osm_utils.logger', autospec=True)
    def test_vnfd_list_two(self, mock_log):
        """
        Checks the proper functionality of vnfd_list function
        when given nf_type is pnf
        """

        mock_vnfd_id = 'test-x-chain-pnfd'
        _nf_type = 'pnf'
        _filter = 'x-chain'
        self.osm_client.vnfd.list.return_value = [{'id': mock_vnfd_id}]
        result = osm_utils.vnfd_list(self.osm_client, nf_type=_nf_type,
                                     _filter=_filter)
        self.assertEqual(result, [mock_vnfd_id])
        self.osm_client.vnfd.list.assert_called_once_with(
            filter="_admin.type={}d&{}".format(_nf_type, _filter))
        mock_log.error.assert_not_called()

    @patch('sfc.lib.osm_utils.logger', autospec=True)
    def test_vnfd_list_three(self, mock_log):
        """
        Checks the proper functionality of vnfd_list function
        when given nf_type is hnf
        """

        mock_vnfd_id = 'test-x-chain-hnfd'
        _nf_type = 'hnf'
        _filter = 'x-chain'
        self.osm_client.vnfd.list.return_value = [{'id': mock_vnfd_id}]
        result = osm_utils.vnfd_list(self.osm_client, nf_type=_nf_type,
                                     _filter=_filter)
        self.assertEqual(result, [mock_vnfd_id])
        self.osm_client.vnfd.list.assert_called_once_with(
            filter="_admin.type={}d&{}".format(_nf_type, _filter))
        mock_log.error.assert_not_called()

    @patch('sfc.lib.osm_utils.logger', autospec=True)
    def test_vnfd_delete_returns_none(self, mock_log):
        """
        Checks the proper functionality of vnfd_delete function
        when it raises an Exception
        """

        mock_vnfd_name = 'test-vnfd'
        ErrorMSG = "Failed to delete VNFD: {}".format(mock_vnfd_name)
        self.osm_client.vnfd.delete.side_effect = Exception(ErrorMSG)
        log_calls = [call("Error [vnfd_delete(osm_client, {}, {})]: {}"
                          .format(mock_vnfd_name, False, ErrorMSG))]
        result = osm_utils.vnfd_delete(self.osm_client, mock_vnfd_name)
        assert result is None
        self.osm_client.vnfd.delete.assert_called_once_with(mock_vnfd_name,
                                                            force=False)
        mock_log.error.assert_has_calls(log_calls)

    @patch('sfc.lib.osm_utils.logger', autospec=True)
    def test_vnfd_delete(self, mock_log):
        """
        Checks the proper functionality of vnfd_delete function
        """

        mock_vnfd_name = 'test-vnfd'
        result = osm_utils.vnfd_delete(self.osm_client, mock_vnfd_name)
        self.osm_client.vnfd.delete.assert_called_once_with(mock_vnfd_name,
                                                            force=False)
        assert result is self.osm_client.vnfd.delete.return_value
        mock_log.error.assert_not_called()

    @patch('sfc.lib.osm_utils.logger', autospec=True)
    def test_nsd_create_returns_none(self, mock_log):
        """
        Checks the proper functionality of nsd_create function
        when it raises an Exception
        """

        mock_nsd_name = 'test-nsd'
        mock_nsd_file = 'test-nsd.yaml'
        ErrorMSG = "Failed to create NSD: {}".format(mock_nsd_name)
        log_calls = [call("Error [nsd_create(osm_client, {}, {})]: {}"
                          .format(mock_nsd_file, None, ErrorMSG))]
        self.osm_client.nsd.create.side_effect = Exception(ErrorMSG)
        result = osm_utils.nsd_create(self.osm_client,
                                      mock_nsd_name,
                                      mock_nsd_file)
        assert result is None
        self.osm_client.nsd.create.assert_called_once_with(mock_nsd_file,
                                                           overwrite=None)
        mock_log.error.assert_has_calls(log_calls)

    @patch('sfc.lib.osm_utils.logger', autospec=True)
    def test_nsd_create(self, mock_log):
        """
        Checks the proper functionality of nsd_create function
        """

        mock_nsd_name = 'test-nsd'
        mock_nsd_file = 'test-nsd.yaml'
        log_calls = [call("Creating the NSD... {}".format(mock_nsd_name))]
        result = osm_utils.nsd_create(self.osm_client,
                                      mock_nsd_name,
                                      mock_nsd_file)
        assert result is self.osm_client.nsd.create.return_value
        self.osm_client.nsd.create.assert_called_once_with(mock_nsd_file,
                                                           overwrite=None)
        mock_log.info.assert_has_calls(log_calls)

    @patch('sfc.lib.osm_utils.logger', autospec=True)
    def test_nsd_list_returns_none(self, mock_log):
        """
        Checks the proper functionality of nsd_list function
        when it raises an Exception
        """

        ErrorMSG = "Failed to list NSDs"
        log_calls = [call("Error [nsd_list(osm_client, {})]: {}"
                          .format(None, ErrorMSG))]
        self.osm_client.nsd.list.side_effect = Exception(ErrorMSG)
        result = osm_utils.nsd_list(self.osm_client)
        assert result is None
        self.osm_client.nsd.list.assert_called_once_with(filter=None)
        mock_log.error.assert_has_calls(log_calls)

    @patch('sfc.lib.osm_utils.logger', autospec=True)
    def test_nsd_list(self, mock_log):
        """
        Checks the proper functionality of nsd_list function
        """

        mock_nsd_id = 'nsd-abyz'
        self.osm_client.nsd.list.return_value = [{'_id': mock_nsd_id}]
        result = osm_utils.nsd_list(self.osm_client)
        self.assertEqual(result, [mock_nsd_id])
        self.osm_client.nsd.list.assert_called_once_with(filter=None)
        mock_log.error.assert_not_called()

    @patch('sfc.lib.osm_utils.logger', autospec=True)
    def test_nsd_delete_returns_none(self, mock_log):
        """
        Checks the proper functionality of nsd_delete function
        when it raises an Exception
        """

        mock_nsd_name = 'test-nsd'
        ErrorMSG = "Failed to delete {}".format(mock_nsd_name)
        self.osm_client.nsd.delete.side_effect = Exception(ErrorMSG)
        log_calls = [call("Error [nsd_delete(osm_client, {}, {})]: {}"
                          .format(mock_nsd_name, False, ErrorMSG))]
        result = osm_utils.nsd_delete(self.osm_client, mock_nsd_name)
        assert result is None
        self.osm_client.nsd.delete.assert_called_once_with(mock_nsd_name,
                                                           force=False)
        mock_log.error.assert_has_calls(log_calls)

    @patch('sfc.lib.osm_utils.logger', autospec=True)
    def test_nsd_delete(self, mock_log):
        """
        Checks the proper functionality of nsd_delete function
        """

        mock_nsd_name = 'test-nsd'
        result = osm_utils.nsd_delete(self.osm_client, mock_nsd_name)
        assert result is self.osm_client.nsd.delete.return_value
        self.osm_client.nsd.delete.assert_called_once_with(mock_nsd_name,
                                                           force=False)
        mock_log.error.assert_not_called()

    @patch('sfc.lib.osm_utils.logger', autospec=True)
    def test_vnf_list_returns_none(self, mock_log):
        """
        Checks the proper functionality of vnf_list function
        when it raises an Exception
        """

        ErrorMSG = "Failed to list VNF instances"
        self.osm_client.vnf.list.side_effect = Exception(ErrorMSG)
        log_calls = [call("Error [vnf_list(osm_client, {}, {})]: {}"
                          .format(None, None, ErrorMSG))]
        result = osm_utils.vnf_list(self.osm_client)
        assert result is None
        self.osm_client.vnf.list.assert_called_once_with(ns=None, filter=None)
        mock_log.error.assert_has_calls(log_calls)

    @patch('sfc.lib.osm_utils.logger', autospec=True)
    def test_vnf_list(self, mock_log):
        """
        Checks the proper functionality of vnf_list function
        """

        mock_vnf_list = 'vnf-abyz'
        self.osm_client.vnf.list.return_value = [{'id': mock_vnf_list}]
        result = osm_utils.vnf_list(self.osm_client)
        self.assertEqual(result, [mock_vnf_list])
        self.osm_client.vnf.list.assert_called_once_with(ns=None, filter=None)
        mock_log.error.assert_not_called()

    @patch('sfc.lib.osm_utils.logger', autospec=True)
    @patch('sfc.lib.osm_utils.vnf_list', autospec=True)
    def test_vnf_ip_returns_none(self, mock_vnf_list, mock_log):
        """
        Checks the proper functionality of get_vnf_ip function
        when ip-address for vnf is not found
        """
        mock_vnf_id = 'vnf-abyz'
        mock_vnf_data = [{'id': 'vnf-abcd', 'ip-address': 'x.y.z.x'},
                         {'id': 'vnf-abef', 'ip-address': 'x.x.x.x'}]
        mock_vnf_list.return_value = mock_vnf_data
        result = osm_utils.vnf_ip(self.osm_client, mock_vnf_id)
        assert result is None
        mock_log.error.assert_not_called()

    @patch('sfc.lib.osm_utils.logger', autospec=True)
    @patch('sfc.lib.osm_utils.vnf_list', autospec=True)
    def test_vnf_ip_raises_exception(self, mock_vnf_list, mock_log):
        """
        Checks the proper functionality of get_vnf_ip function
        when vnf_list function raises an exception
        """
        mock_vnf_id = 'vnf-abyz'
        ErrorMSG = "Couldn't reach OSM HOST"
        log_calls = [call("Error [get_vnf_ip(osm_client, {})]: {}"
                          .format(mock_vnf_id, ErrorMSG))]
        mock_vnf_list.side_effect = Exception(ErrorMSG)
        result = osm_utils.vnf_ip(self.osm_client, mock_vnf_id)
        assert result is None
        mock_log.error.assert_has_calls(log_calls)

    @patch('sfc.lib.osm_utils.logger', autospec=True)
    @patch('sfc.lib.osm_utils.vnf_list', autospec=True)
    def test_vnf_ip(self, mock_vnf_list, mock_log):
        """
        Checks the proper functionality of get_vnf_ip function
        """
        mock_vnf_id = 'vnf-abyz'
        mock_vnf_data = [{'id': 'vnf-abcd', 'ip-address': '1.2.3.4.'},
                         {'id': 'vnf-abyz', 'ip-address': '5.6.7.8'}]
        mock_vnf_list.return_value = mock_vnf_data
        result = osm_utils.vnf_ip(self.osm_client, mock_vnf_id)
        self.assertEqual(result, '5.6.7.8')
        mock_log.error.assert_not_called()

    @patch('sfc.lib.osm_utils.logger', autospec=True)
    def test_ns_create_returns_none_one(self, mock_log):
        """
        Checks the proper functionality of ns_create function
        when it raises Exception due to incompatible options
        """

        mock_nsd_name = 'test-nsd'
        mock_ns_name = 'test-ns'
        mock_vim_account = 'test-vim'
        mock_ssh_keys = 'ssh-rsa abcd'
        mock_config = 'test-config'
        mock_config_file = 'test-config-file'
        ErrorMSG = "'config' option is incompatable with 'config_file' option"
        log_calls = [call("Error [ns_create(osm_client, {}, {}, {}, {}, {})]: "
                          "{}".format(mock_ns_name, mock_nsd_name,
                                      mock_vim_account, mock_ssh_keys,
                                      mock_config, ErrorMSG))]
        result = osm_utils.ns_create(self.osm_client, mock_ns_name,
                                     mock_nsd_name, mock_vim_account,
                                     config=mock_config,
                                     config_file=mock_config_file,
                                     ssh_keys=mock_ssh_keys)
        assert result is None
        self.osm_client.ns.create.assert_not_called()
        mock_log.error.assert_has_calls(log_calls)

    @patch('__builtin__.open', autospec=True)
    @patch('sfc.lib.osm_utils.logger', autospec=True)
    def test_ns_create_returns_none_two(self, mock_log, mock_open):
        """
        Checks the proper functionality of ns_create function
        when it raises Exception due to improper configuration
        """

        mock_nsd_name = 'test-nsd'
        mock_ns_name = 'test-ns'
        mock_vim_account = 'test-vim'
        mock_ssh_keys = 'ssh-rsa abcd'
        mock_config_file = 'test-config-file'
        open_handler = mock_open.return_value.__enter__.return_value
        open_handler.read.return_value = mock_config_file
        ErrorMSG = "Invalid keys present in config file"
        self.osm_client.ns.create.side_effect = Exception(ErrorMSG)
        log_calls = [call("Error [ns_create(osm_client, {}, {}, {}, {}, {})]: "
                          "{}".format(mock_ns_name, mock_nsd_name,
                                      mock_vim_account, mock_ssh_keys,
                                      mock_config_file, ErrorMSG))]
        result = osm_utils.ns_create(self.osm_client, mock_ns_name,
                                     mock_nsd_name, mock_vim_account,
                                     config=None,
                                     config_file=mock_config_file,
                                     ssh_keys=mock_ssh_keys)
        assert result is None
        open_handler.read.assert_called_once_with()
        self.osm_client.ns.create.assert_called_once_with(
            mock_nsd_name, mock_ns_name, mock_vim_account,
            config=mock_config_file, ssh_keys=mock_ssh_keys)
        mock_log.error.assert_has_calls(log_calls)

    @patch('__builtin__.open', autospec=True)
    @patch('sfc.lib.osm_utils.logger', autospec=True)
    @patch('sfc.lib.osm_utils.wait_for_ns_to_be_ready', autospec=True)
    def test_ns_create(self, mock_ready, mock_log, mock_open):
        """
        Checks the proper functionality of ns_create function
        """

        mock_nsd_name = 'test-nsd'
        mock_ns_name = 'test-ns'
        mock_vim_account = 'test-vim'
        mock_ssh_keys = 'ssh-rsa abcd'
        mock_config_file = 'test-config-file'
        open_handler = mock_open.return_value.__enter__.return_value
        open_handler.read.return_value = mock_config_file
        result = osm_utils.ns_create(self.osm_client, mock_ns_name,
                                     mock_nsd_name, mock_vim_account,
                                     config=None,
                                     config_file=mock_config_file,
                                     ssh_keys=mock_ssh_keys)
        assert result is self.osm_client.ns.create.return_value
        open_handler.read.assert_called_once_with()
        self.osm_client.ns.create.assert_called_once_with(
            mock_nsd_name, mock_ns_name, mock_vim_account,
            config=mock_config_file, ssh_keys=mock_ssh_keys)
        mock_log.error.assert_not_called()
        mock_ready.assert_called_once_with(self.osm_client, result)

    @patch('sfc.lib.osm_utils.sleep', autospec=True)
    @patch('sfc.lib.osm_utils.logger', autospec=True)
    @patch('sfc.lib.osm_utils.ns_show', autospec=True, return_value=[])
    def test_wait_for_ns_to_be_ready_returns_none(self,
                                                  mock_ns_show,
                                                  mock_log,
                                                  mock_sleep):
        """
        Checks the proper functionality of wait_for_ns_to_be_ready function
        when ns_list reutrns None
        """

        mock_ns_id = 'ns-abyz'
        log_calls = [call("Wait for the NS instance to be ready...")]
        osm_utils.wait_for_ns_to_be_ready(self.osm_client, mock_ns_id)
        mock_log.info.assert_has_calls(log_calls)
        mock_log.error.assert_not_called()
        mock_sleep.assert_not_called()

    @patch('sfc.lib.osm_utils.sleep', autospec=True)
    @patch('sfc.lib.osm_utils.logger', autospec=True)
    @patch('sfc.lib.osm_utils.ns_show', autospec=True)
    def test_wait_for_ns_to_be_ready_raises_exception(self,
                                                      mock_ns_show,
                                                      mock_log,
                                                      mock_sleep):
        """
        Checks the proper functionality of wait_for_ns_to_be_ready function
        when it raises an Exception
        """

        mock_ns_id = 'ns-abyz'
        ErrorMSG = "ERROR in creating ns-abyz at RO"
        mock_ns_show.side_effect = [{'id': 'ns-abyz',
                                     'detailed-status': "Getting ready"},
                                    {'id': 'nsd-abyz',
                                     'detailed-status': ErrorMSG}]
        log_calls = [call("Wait for the NS instance to be ready..."),
                     call("Error [wait_for_ns_to_be_ready(osm_client, {})]:"
                          " {}".format(mock_ns_id, ErrorMSG))]
        osm_utils.wait_for_ns_to_be_ready(self.osm_client, mock_ns_id)
        mock_log.info.assert_has_calls(log_calls[:1])
        mock_log.error.assert_has_calls(log_calls[1:])
        mock_sleep.assert_called_once_with(30)

    @patch('sfc.lib.osm_utils.sleep', autospec=True)
    @patch('sfc.lib.osm_utils.logger', autospec=True)
    @patch('sfc.lib.osm_utils.ns_show', autospec=True)
    def test_wait_for_ns_to_be_ready(self, mock_ns_show, mock_log, mock_sleep):
        """
        Checks the proper functionality of wait_for_ns_to_be_ready function
        """

        mock_ns_id = 'ns-abyz'
        mock_ns_show.side_effect = [{'id': 'ns-abyz',
                                     'detailed-status': 'Getting ready'},
                                    {'id': 'ns-abyz',
                                     'detailed-status': 'done'}]
        log_calls = [call("Wait for the NS instance to be ready..."),
                     call("Ready")]
        osm_utils.wait_for_ns_to_be_ready(self.osm_client, mock_ns_id)
        mock_log.info.assert_has_calls(log_calls)
        mock_sleep.assert_called_once_with(30)

    @patch('sfc.lib.osm_utils.logger', autospec=True)
    def test_ns_list_returns_none(self, mock_log):
        """
        Checks the proper functionality of ns_list function
        when it raises an Exception
        """

        ErrorMSG = "Failed to list NS instances"
        self.osm_client.ns.list.side_effect = Exception(ErrorMSG)
        log_calls = [call("Error [ns_list(osm_client, {}, {})]: {}"
                          .format(None, False, ErrorMSG))]
        result = osm_utils.ns_list(self.osm_client)
        self.osm_client.ns.list.assert_called_once_with(filter=None)
        assert result is None
        mock_log.error.assert_has_calls(log_calls)

    @patch('sfc.lib.osm_utils.logger', autospec=True)
    def test_ns_list(self, mock_log):
        """
        Checks the proper functionality of ns_list function
        """

        mock_ns = 'ns-abyz'
        self.osm_client.ns.list.return_value = [{'id': mock_ns}]
        result = osm_utils.ns_list(self.osm_client)
        self.osm_client.ns.list.assert_called_once_with(filter=None)
        self.assertEqual(result, [mock_ns])
        mock_log.error.assert_not_called()

    @patch('sfc.lib.osm_utils.logger', autospec=True)
    @patch('sfc.lib.osm_utils.ns_list', autospec=True)
    def test_ns_show(self, mock_ns_list, mock_log):
        """
        Checks the proper functionality of ns_show function
        """

        mock_ns_id = 'ns-abyz'
        mock_ns_data = [{'id': 'ns-abcd', 'vnfs': ['vnf-a',
                                                   'vnf-b',
                                                   'vnf-c']},
                        {'id': mock_ns_id, 'vnfs': ['vnf-d',
                                                    'vnf-e',
                                                    'vnf-f']}]
        mock_ns_list.return_value = mock_ns_data
        result = osm_utils.ns_show(self.osm_client, mock_ns_id)
        self.assertEqual(result, mock_ns_data[1])
        mock_ns_list.assert_called_once_with(self.osm_client, verbose=True)
        mock_log.assert_not_called()

    @patch('sfc.lib.osm_utils.logger', autospec=True)
    @patch('sfc.lib.osm_utils.ns_list', autospec=True)
    def test_ns_show_returns_none(self, mock_ns_list, mock_log):
        """
        Checks the proper functionality of ns_show function
        """

        mock_ns_id = 'ns-abyz'
        mock_ns_data = [{'id': 'ns-abcz', 'vnfs': ['vnf-a',
                                                   'vnf-b',
                                                   'vnf-c']},
                        {'id': 'ns-defz', 'vnfs': ['vnf-d',
                                                   'vnf-e',
                                                   'vnf-f']}]
        log_calls = [call("No such network service found!")]
        mock_ns_list.return_value = mock_ns_data
        result = osm_utils.ns_show(self.osm_client, mock_ns_id)
        assert result is None
        mock_ns_list.assert_called_once_with(self.osm_client, verbose=True)
        mock_log.error.assert_has_calls(log_calls)

    @patch('sfc.lib.osm_utils.logger', autospec=True)
    def test_ns_delete_raises_exception(self, mock_log):
        """
        Checks the proper functionality of ns_delete function
        when it raises an Exception
        """

        mock_ns_id = 'ns-abyz'
        ErrorMSG = "Failed to delete NS instance: {}".format(mock_ns_id)
        self.osm_client.ns.delete.side_effect = Exception(ErrorMSG)
        log_calls = [call("Error [ns_delete(osm_client, {}, {})]: {}"
                          .format(mock_ns_id, False, ErrorMSG))]
        osm_utils.ns_delete(self.osm_client, mock_ns_id)
        self.osm_client.ns.delete.assert_called_once_with(
            mock_ns_id, force=False)
        mock_log.error.assert_has_calls(log_calls)

    @patch('sfc.lib.osm_utils.wait_for_ns_to_be_deleted', autospec=True)
    @patch('sfc.lib.osm_utils.logger', autospec=True)
    def test_ns_delete(self, mock_log, mock_deleted):
        """
        Checks the proper functionality of ns_delete function
        """

        mock_ns_id = 'ns-abyz'
        osm_utils.ns_delete(self.osm_client, mock_ns_id)
        self.osm_client.ns.delete.assert_called_once_with(
            mock_ns_id, force=False)
        mock_deleted.assert_called_once_with(self.osm_client, mock_ns_id)
        mock_log.error.assert_not_called()

    @patch('sfc.lib.osm_utils.sleep', autospec=True)
    @patch('sfc.lib.osm_utils.logger', autospec=True)
    @patch('sfc.lib.osm_utils.ns_show', autospec=True)
    def test_wait_for_ns_to_be_deleted(self,
                                       mock_ns_show,
                                       mock_log,
                                       mock_sleep):
        """
        Checks the proper functionality of wait_for_ns_to_be_deleted function
        """

        mock_ns_id = 'ns-abyz'
        mock_ns_data = [{'id': 'ns-abyz', 'detailed-status': 'terminating'},
                        {'id': 'ns-abyz', 'detailed-status': "ERROR unable"
                                                             "to terminate"},
                        None]
        mock_ns_show.side_effect = mock_ns_data
        log_calls = [call("force deleting {}".format(mock_ns_id)),
                     call('Deleted!')]
        osm_utils.wait_for_ns_to_be_deleted(self.osm_client, mock_ns_id)
        mock_log.info.assert_has_calls(log_calls)
        self.assertEqual(mock_ns_show.call_count, 3)
        self.assertEqual(mock_sleep.call_count, 2)

    @patch('sfc.lib.osm_utils.logger', autospec=True)
    def test_sdnc_register_returns_none(self, mock_log):
        """
        Checks the proper functionality of sdnc_create function
        when it raises an Exception
        """

        mock_sdnc = {
            'name': 'mock_name',
            'type': 'mock_type',
            'ip': 'mock_ip',
            'port': '10',
            'dpid': 'mock_dpid',
            'user': 'mock_user',
            'password': 'mock_password'
        }
        ErrorMSG = "Failed to create to SDN controller: {}".format(
            mock_sdnc['name'])
        self.osm_client.sdnc.create.side_effect = Exception(ErrorMSG)
        log_calls = [call("Error [sdnc_register(osm_client, {})]: {}"
                          .format(mock_sdnc['name'], ErrorMSG))]
        result = osm_utils.sdnc_register(self.osm_client,
                                         mock_sdnc['name'],
                                         mock_sdnc['type'],
                                         mock_sdnc['ip'],
                                         mock_sdnc['port'],
                                         mock_sdnc['dpid'],
                                         mock_sdnc['user'],
                                         mock_sdnc['password'])
        assert result is None
        mock_sdnc['port'] = 10
        self.osm_client.sdnc.create.assert_called_once_with(
            mock_sdnc['name'], mock_sdnc)
        mock_log.error.assert_has_calls(log_calls)

    @patch('sfc.lib.osm_utils.logger', autospec=True)
    def test_sdnc_register(self, mock_log):
        """
        Checks the proper functionality of sdnc_create function
        """

        mock_sdnc = {
            'name': 'mock_name',
            'type': 'mock_type',
            'ip': 'mock_ip',
            'port': '10',
            'dpid': 'mock_dpid',
            'user': 'mock_user',
            'password': 'mock_password'
        }
        result = osm_utils.sdnc_register(self.osm_client,
                                         mock_sdnc['name'],
                                         mock_sdnc['type'],
                                         mock_sdnc['ip'],
                                         mock_sdnc['port'],
                                         mock_sdnc['dpid'],
                                         mock_sdnc['user'],
                                         mock_sdnc['password'])
        assert result is self.osm_client.sdnc.create.return_value
        mock_sdnc['port'] = 10
        self.osm_client.sdnc.create.assert_called_once_with(
            mock_sdnc['name'], mock_sdnc)
        mock_log.error.assert_not_called()

    @patch('sfc.lib.osm_utils.logger', autospec=True)
    def test_sdnc_list_returns_none(self, mock_log):
        """
        Checks the proper functionality of sdnc_list function
        when it raises an Exception
        """

        ErrorMSG = "Failed to list SDN controllers"
        self.osm_client.sdnc.list.side_effect = Exception(ErrorMSG)
        log_calls = [call("Error [sdnc_list(osm_client, {}, {})]: {}"
                          .format(None, False, ErrorMSG))]
        result = osm_utils.sdnc_list(self.osm_client)
        assert result is None
        self.osm_client.sdnc.list.assert_called_once_with(filter=None)
        mock_log.error.assert_has_calls(log_calls)

    @patch('sfc.lib.osm_utils.logger', autospec=True)
    def test_sdnc_list(self, mock_log):
        """
        Checks the proper functionality of sdnc_list function
        """

        mock_sdnc_name = "test-sdnc"
        self.osm_client.sdnc.list.return_value = [{'id': mock_sdnc_name}]
        result = osm_utils.sdnc_list(self.osm_client)
        self.assertEqual(result, [mock_sdnc_name])
        self.osm_client.sdnc.list.assert_called_once_with(filter=None)
        mock_log.error.assert_not_called()

    @patch('sfc.lib.osm_utils.logger', autospec=True)
    def test_sdnc_delete_returns_none(self, mock_log):
        """
        Checks the proper functionality of sdnc_delete function
        when it raises an Exception
        """

        mock_sdnc_name = 'test-sdnc'
        ErrorMSG = "Failed to delete SDN controller: {}".format(mock_sdnc_name)
        self.osm_client.sdnc.delete.side_effect = Exception(ErrorMSG)
        log_calls = [call("Error [sdnc_delete(osm_client, {}, {})]: {}"
                          .format(mock_sdnc_name, False, ErrorMSG))]
        result = osm_utils.sdnc_delete(self.osm_client, mock_sdnc_name)
        assert result is None
        self.osm_client.sdnc.delete.assert_called_once_with(mock_sdnc_name,
                                                            force=False)
        mock_log.error.assert_has_calls(log_calls)

    @patch('sfc.lib.osm_utils.logger', autospec=True)
    def test_sdnc_delete(self, mock_log):
        """
        Checks the proper functionality of sdnc_list function
        """

        mock_sdnc_name = "test-sdnc"
        result = osm_utils.sdnc_delete(self.osm_client, mock_sdnc_name)
        assert result is self.osm_client.sdnc.delete.return_value
        self.osm_client.sdnc.delete.assert_called_once_with(mock_sdnc_name,
                                                            force=False)
        mock_log.error.assert_not_called()
