#!/usr/bin/env python

###############################################################################
# Copyright (c) 2018 Intracom Telecom and others.
#
# All rights reserved. This program and the accompanying materials
# are made available under the terms of the Apache License, Version 2.0
# which accompanies this distribution, and is available at
# http://www.apache.org/licenses/LICENSE-2.0
###############################################################################

import unittest
import sfc.lib.cleanup as cleanup

from mock import patch
from mock import call
from mock import Mock
from mock import DEFAULT

__author__ = "Dimitrios Markou <mardim@intracom-telecom.com>"


class SfcCleanupTesting(unittest.TestCase):

    def setUp(self):
        self.odl_ip = '10.10.10.10'
        self.odl_port = '8081'
        self.patcher = patch('sfc.lib.openstack_utils.get_tacker_client')
        self.mock_tacker_client = self.patcher.start()
        self.mock_tacker_client.return_value = 'tacker_client_obj'

    def tearDown(self):
        self.patcher.stop()

    @patch('sfc.lib.cleanup.logger.info')
    @patch('sfc.lib.odl_utils.delete_odl_resource_elem')
    @patch('sfc.lib.odl_utils.odl_resource_list_names')
    @patch('sfc.lib.odl_utils.get_odl_resource_list')
    def test_delete_odl_resource(self, mock_resource_list,
                                 mock_resource_list_name,
                                 mock_del_resource_elem,
                                 mock_log):
        """
        Checks if the functions which belong to the odl_utils
        library are getting called.
        """

        resource = 'mock_resource'
        log_calls = [call("Removing ODL resource: mock_resource/elem_one"),
                     call("Removing ODL resource: mock_resource/elem_two")]

        del_calls = [call(self.odl_ip, self.odl_port, resource, 'elem_one'),
                     call(self.odl_ip, self.odl_port, resource, 'elem_two')]

        mock_resource_list_name.return_value = ['elem_one', 'elem_two']
        mock_resource_list.return_value = ['rsrc_one',
                                           'rsrc_two',
                                           'rsrc_three']

        cleanup.delete_odl_resources(self.odl_ip, self.odl_port, resource)

        mock_resource_list.assert_called_once_with(self.odl_ip,
                                                   self.odl_port,
                                                   resource)
        mock_resource_list_name.assert_called_once_with(
                resource, ['rsrc_one', 'rsrc_two', 'rsrc_three'])
        mock_del_resource_elem.assert_has_calls(del_calls)
        mock_log.assert_has_calls(log_calls)

    @patch('sfc.lib.odl_utils.get_odl_acl_list')
    @patch('sfc.lib.odl_utils.odl_acl_types_names')
    @patch('sfc.lib.odl_utils.delete_odl_acl')
    def test_delete_odl_ietf_access_lists(self,
                                          mock_del_acl,
                                          mock_acl_types,
                                          mock_get_acls):
        """
        Ckecks the proper functionality of the delete_odl_ietf_access_lists
        function
        """

        mock_acl_type_name_list = [('acl_type_one', 'name_one'),
                                   ('acl_type_two', 'name_two')]
        mock_get_acls.return_value = ['acl_one', 'acl_two']
        mock_acl_types.return_value = mock_acl_type_name_list
        del_calls = [call(self.odl_ip, self.odl_port, key, value)
                     for key, value in mock_acl_type_name_list]

        cleanup.delete_odl_ietf_access_lists(self.odl_ip, self.odl_port)

        mock_get_acls.assert_called_once_with(self.odl_ip, self.odl_port)
        mock_acl_types.assert_called_once_with(['acl_one', 'acl_two'])
        mock_del_acl.assert_has_calls(del_calls)

    @patch('sfc.lib.openstack_utils.list_vnfds', return_value=None)
    def test_delete_vnfds_returned_list_is_none(self, mock_list_vnfds):
        """
        Check the proper functionality of the delete_vnfds
        function when the returned vnfds list is None
        """

        self.assertIsNone(cleanup.delete_vnfds())
        mock_list_vnfds.assert_called_once_with('tacker_client_obj')

    @patch('sfc.lib.cleanup.logger.info')
    @patch('sfc.lib.openstack_utils.delete_vnfd')
    @patch('sfc.lib.openstack_utils.list_vnfds')
    def test_delete_vnfds_not_empty_list(self,
                                         mock_list_vnfds,
                                         mock_del_vnfd,
                                         mock_log):
        """
        Check the proper functionality of the delete_vnfds
        function when the returned vnfds list is not empty
        """

        mock_list_vnfds.return_value = ['vnfd_one', 'vnfd_two']
        log_calls = [call("Removing vnfd: vnfd_one"),
                     call("Removing vnfd: vnfd_two")]

        del_calls = [call('tacker_client_obj', vnfd_id='vnfd_one'),
                     call('tacker_client_obj', vnfd_id='vnfd_two')]

        cleanup.delete_vnfds()
        mock_list_vnfds.assert_called_once_with('tacker_client_obj')
        mock_log.assert_has_calls(log_calls)
        mock_del_vnfd.assert_has_calls(del_calls)

    @patch('sfc.lib.openstack_utils.list_vnfs', return_value=None)
    def test_delete_vnfs_returned_list_is_none(self, mock_list_vnfs):
        """
        Check the proper functionality of the delete_vnfs
        function when the returned vnfs list is None
        """

        self.assertIsNone(cleanup.delete_vnfs())
        mock_list_vnfs.assert_called_once_with('tacker_client_obj')

    @patch('sfc.lib.cleanup.logger.info')
    @patch('sfc.lib.openstack_utils.delete_vnf')
    @patch('sfc.lib.openstack_utils.list_vnfs')
    def test_delete_vnfs_not_empty_list(self,
                                        mock_list_vnfs,
                                        mock_del_vnf,
                                        mock_log):
        """
        Check the proper functionality of the delete_vnfs
        function when the returned vnfs list is not empty
        """

        mock_list_vnfs.return_value = ['vnf_one', 'vnf_two']
        log_calls = [call("Removing vnf: vnf_one"),
                     call("Removing vnf: vnf_two")]

        del_calls = [call('tacker_client_obj', vnf_id='vnf_one'),
                     call('tacker_client_obj', vnf_id='vnf_two')]

        cleanup.delete_vnfs()
        mock_list_vnfs.assert_called_once_with('tacker_client_obj')
        mock_log.assert_has_calls(log_calls)
        mock_del_vnf.assert_has_calls(del_calls)

    @patch('sfc.lib.openstack_utils.list_vnffgs', return_value=None)
    def test_delete_vnffgs_returned_list_is_none(self, mock_list_vnffgs):
        """
        Check the proper functionality of the delete_vnffgs
        function when the returned vnffgs list is None
        """

        self.assertIsNone(cleanup.delete_vnffgs())
        mock_list_vnffgs.assert_called_once_with('tacker_client_obj')

    @patch('sfc.lib.cleanup.logger.info')
    @patch('sfc.lib.openstack_utils.delete_vnffg')
    @patch('sfc.lib.openstack_utils.list_vnffgs')
    def test_delete_vnffgs_not_empty_list(self,
                                          mock_list_vnffgs,
                                          mock_del_vnffg,
                                          mock_log):
        """
        Check the proper functionality of the delete_vnffgs
        function when the returned vnffgs list is not empty
        """

        mock_list_vnffgs.return_value = ['vnffg_one', 'vnffg_two']
        log_calls = [call("Removing vnffg: vnffg_two"),
                     call("Removing vnffg: vnffg_one")]

        del_calls = [call('tacker_client_obj', vnffg_id='vnffg_two'),
                     call('tacker_client_obj', vnffg_id='vnffg_one')]

        cleanup.delete_vnffgs()
        mock_list_vnffgs.assert_called_once_with('tacker_client_obj')
        mock_log.assert_has_calls(log_calls)
        mock_del_vnffg.assert_has_calls(del_calls)

    @patch('sfc.lib.openstack_utils.list_vnffgds', return_value=None)
    def test_delete_vnffgds_returned_list_is_none(self, mock_list_vnffgds):
        """
        Check the proper functionality of the delete_vnffgds
        function when the returned vnffgds list is None
        """

        self.assertIsNone(cleanup.delete_vnffgds())
        mock_list_vnffgds.assert_called_once_with('tacker_client_obj')

    @patch('sfc.lib.cleanup.logger.info')
    @patch('sfc.lib.openstack_utils.delete_vnffgd')
    @patch('sfc.lib.openstack_utils.list_vnffgds')
    def test_delete_vnffgds_not_empty_list(self,
                                           mock_list_vnffgds,
                                           mock_del_vnffgd,
                                           mock_log):
        """
        Check the proper functionality of the delete_vnffgds
        function when the returned vnffgds list is not empty
        """

        mock_list_vnffgds.return_value = ['vnffgd_one', 'vnffgd_two']
        log_calls = [call("Removing vnffgd: vnffgd_one"),
                     call("Removing vnffgd: vnffgd_two")]

        del_calls = [call('tacker_client_obj', vnffgd_id='vnffgd_one'),
                     call('tacker_client_obj', vnffgd_id='vnffgd_two')]

        cleanup.delete_vnffgds()
        mock_list_vnffgds.assert_called_once_with('tacker_client_obj')
        mock_log.assert_has_calls(log_calls)
        mock_del_vnffgd.assert_has_calls(del_calls)

    @patch('sfc.lib.openstack_utils.list_vims', return_value=None)
    def test_delete_vims_returned_list_is_none(self, mock_list_vims):
        """
        Check the proper functionality of the delete_vims
        function when the returned vims list is None
        """

        self.assertIsNone(cleanup.delete_vims())
        mock_list_vims.assert_called_once_with('tacker_client_obj')

    @patch('sfc.lib.cleanup.logger.info')
    @patch('sfc.lib.openstack_utils.delete_vim')
    @patch('sfc.lib.openstack_utils.list_vims')
    def test_delete_vims_not_empty_list(self,
                                        mock_list_vims,
                                        mock_del_vim,
                                        mock_log):
        """
        Check the proper functionality of the delete_vims
        function when the returned vims list is not empty
        """

        mock_list_vims.return_value = ['vim_one', 'vim_two']
        log_calls = [call("Removing vim: vim_one"),
                     call("Removing vim: vim_two")]

        del_calls = [call('tacker_client_obj', vim_id='vim_one'),
                     call('tacker_client_obj', vim_id='vim_two')]

        cleanup.delete_vims()
        mock_list_vims.assert_called_once_with('tacker_client_obj')
        mock_log.assert_has_calls(log_calls)
        mock_del_vim.assert_has_calls(del_calls)

    @patch('sfc.lib.cleanup.logger.error')
    def test_delete_openstack_objects_exception(self, mock_log):

        """
        Check the proper functionality of the delete_openstack_objects
        function when exception occurs.
        """

        mock_creator_obj_one = Mock()
        mock_creator_obj_two = Mock()
        exception_one = Exception('First Boom!')
        exception_two = Exception('Second Boom!')
        attrs_list = [{'clean.side_effect': exception_one},
                      {'clean.side_effect': exception_two}]

        mock_creator_obj_one.configure_mock(**attrs_list[0])
        mock_creator_obj_two.configure_mock(**attrs_list[1])

        mock_creator_objs_list = [mock_creator_obj_one, mock_creator_obj_two]

        log_calls = [call('Unexpected error cleaning - %s', exception_two),
                     call('Unexpected error cleaning - %s', exception_one)]

        cleanup.delete_openstack_objects(mock_creator_objs_list)

        mock_log.assert_has_calls(log_calls)

    @patch('sfc.lib.openstack_utils.OpenStackSFC', autospec=True)
    def test_delete_untracked_security_groups(self,
                                              mock_obj):
        instance = mock_obj.return_value
        cleanup.delete_untracked_security_groups()
        instance.delete_all_security_groups.assert_called_once()

    @patch('sfc.lib.cleanup.delete_odl_resources')
    @patch('sfc.lib.cleanup.delete_odl_ietf_access_lists')
    def test_cleanup_odl(self,
                         mock_del_odl_ietf,
                         mock_del_odl_res):
        resources = ['service-function-forwarder',
                     'service-function-chain',
                     'service-function-path',
                     'service-function']

        odl_res_calls = [call(self.odl_ip, self.odl_port, item)
                         for item in resources]

        cleanup.cleanup_odl(self.odl_ip, self.odl_port)

        mock_del_odl_res.assert_has_calls(odl_res_calls)
        mock_del_odl_ietf.assert_called_once_with(self.odl_ip, self.odl_port)

    @patch('time.sleep')
    @patch('sfc.lib.cleanup.delete_openstack_objects')
    @patch('sfc.lib.cleanup.cleanup_odl')
    def test_cleanup(self,
                     mock_cleanup_odl,
                     mock_del_os_obj,
                     mock_time):

        mock_dict = {'delete_vnffgs': DEFAULT,
                     'delete_vnffgds': DEFAULT,
                     'delete_vnfs': DEFAULT,
                     'delete_vnfds': DEFAULT,
                     'delete_vims': DEFAULT,
                     'delete_untracked_security_groups': DEFAULT}
        with patch.multiple('sfc.lib.cleanup',
                            **mock_dict) as mock_values:

            cleanup.cleanup(['creator_one', 'creator_two'],
                            self.odl_ip,
                            self.odl_port)

        for key in mock_values:
            mock_values[key].assert_called_once()
        mock_cleanup_odl.assert_called_once_with(self.odl_ip,
                                                 self.odl_port)
        mock_del_os_obj.assert_called_once_with(['creator_one', 'creator_two'])
        mock_time.assert_called_once_with(20)

    @patch('time.sleep')
    @patch('sfc.lib.cleanup.cleanup_odl')
    def test_cleanup_from_bash(self,
                               mock_cleanup_odl,
                               mock_time):

        mock_dict = {'delete_vnffgs': DEFAULT,
                     'delete_vnffgds': DEFAULT,
                     'delete_vnfs': DEFAULT,
                     'delete_vnfds': DEFAULT,
                     'delete_vims': DEFAULT}
        with patch.multiple('sfc.lib.cleanup',
                            **mock_dict) as mock_values:

            cleanup.cleanup_from_bash(self.odl_ip,
                                      self.odl_port)

        for key in mock_values:
            mock_values[key].assert_called_once()
        mock_cleanup_odl.assert_called_once_with(self.odl_ip,
                                                 self.odl_port)
        mock_time.assert_called_once_with(20)
