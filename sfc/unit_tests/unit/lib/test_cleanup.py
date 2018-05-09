#!/usr/bin/env python

###############################################################################
## Copyright (c) 2018 Intracom Telecom and others.
##
## All rights reserved. This program and the accompanying materials
## are made available under the terms of the Apache License, Version 2.0
## which accompanies this distribution, and is available at
## http://www.apache.org/licenses/LICENSE-2.0
###############################################################################

import unittest
import sfc.lib.cleanup as cleanup

from mock import patch
from mock import call

__author__ = "Dimitrios Markou <mardim@intracom-telecom.com>"

class SfcCleanupTesting(unittest.TestCase):

    def setUp(self):
        self.odl_ip = '10.10.10.10'
        self.odl_port = '8081'

    @patch('sfc.lib.odl_utils.delete_odl_resource_elem')
    @patch('sfc.lib.odl_utils.odl_resource_list_names',
            return_value=['elem_one', 'elem_two'])
    @patch('sfc.lib.odl_utils.get_odl_resource_list',
            return_value=['rsrc_one', 'rsrc_two', 'rsrc_three'])
    def test_delete_odl_resource(self, mock_resource_list,
                                 mock_resource_list_name,
                                 mock_del_resource_elem):
        """
        Checks if the functions which are belong to the odl_utils
        library are getting called.
        """

        resource = 'mock_resource'

        calls = [call(self.odl_ip, self.odl_port, resource, 'elem_one'),
                 call(self.odl_ip, self.odl_port, resource, 'elem_two')]

        cleanup.delete_odl_resources(self.odl_ip, self.odl_port, resource)

        mock_resource_list.assert_called_once_with(self.odl_ip,
                                                   self.odl_port,
                                                   resource)

        mock_resource_list_name.assert_called_once_with(
                resource, ['rsrc_one', 'rsrc_two', 'rsrc_three'])

        mock_del_resource_elem.assert_has_calls(calls)






