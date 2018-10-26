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

from mock import Mock
from mock import call
from mock import patch

import sfc.lib.test_utils as test_utils

__author__ = "Harshavardhan Reddy <venkataharshavardhan_ven@srmuniv.edu.in>"


class SfcTestUtilsTesting(unittest.TestCase):

    def setUp(self):
        self.ip = '10.10.10.10'

    @patch('subprocess.PIPE', autospec=True)
    @patch('subprocess.Popen', autospec=True)
    @patch('sfc.lib.test_utils.logger', autospec=True)
    def test_run_cmd(self,
                     mock_log,
                     mock_popen,
                     mock_pipe):
        """
        Checks the proper functionality of run_cmd
        function
        """

        cmd = 'mock_command'
        log_calls = [call('Running [mock_command] returns: [0] ' +
                          '- STDOUT: "output" - STDERR: "output"')]

        pipe_mock = Mock()
        attrs = {'communicate.return_value': ('output', 'error'),
                 'returncode': 0}
        pipe_mock.configure_mock(**attrs)
        mock_popen.return_value = pipe_mock
        result = test_utils.run_cmd(cmd)
        self.assertTupleEqual(result, (0, 'output', 'error'))
        mock_popen.assert_called_once_with(cmd,
                                           shell=True,
                                           stdout=mock_pipe,
                                           stderr=mock_pipe)
        mock_popen.return_value.communicate.assert_called_once_with()
        mock_log.debug.assert_has_calls(log_calls)

    @patch('sfc.lib.test_utils.run_cmd', autospec=True)
    def test_run_cmd_remote(self, mock_run_cmd):
        """
        Checks the proper functionality of the run_cmd_remote
        function
        """

        cmd = 'mock_command'
        mock_rc = 'sshpass -p opnfv ssh -q -o UserKnownHostsFile=/dev/null' + \
                  ' -o StrictHostKeyChecking=no -o ConnectTimeout=50 ' + \
                  ' root@10.10.10.10 mock_command'
        test_utils.run_cmd_remote(self.ip, cmd)
        mock_run_cmd.assert_called_once_with(mock_rc)

    @patch('shutil.copyfileobj')
    @patch('urllib.urlopen', autospec=True)
    @patch('__builtin__.open', autospec=True)
    def test_download_url_with_exception(self,
                                         mock_open,
                                         mock_urlopen,
                                         mock_copyfileobj):
            """
            Checks the proper functionality of download_url
            function when an exception is raised
            """

            dest_path = 'mocked_/dest_/path'
            url = 'mocked_/url'
            mock_urlopen.side_effect = Exception('HttpError')
            self.assertFalse(test_utils.download_url(url, dest_path))
            mock_urlopen.assert_called_once_with(url)
            mock_open.assert_not_called()
            mock_copyfileobj.assert_not_called()

    @patch('urllib.urlopen', autospec=True)
    @patch('__builtin__.open', autospec=True)
    @patch('shutil.copyfileobj', autospec=True)
    def test_download_url_without_exception(self,
                                            mock_copyfileobj,
                                            mock_open,
                                            mock_urlopen):
        """
        Checks the proper functionality of download_url
        function when any exception isn't raised
        """

        response = '<mocked_response>'
        dest_path = 'mocked_/dest_/path'
        url = 'mocked_/url'
        open_handler = mock_open.return_value.__enter__.return_value
        mock_urlopen.return_value = response
        self.assertTrue(test_utils.download_url(url, dest_path))
        mock_urlopen.assert_called_once_with(url)
        mock_open.assert_called_once_with('mocked_/dest_/path/url', 'wb')
        mock_copyfileobj.assert_called_once_with(response, open_handler)

    @patch('sfc.lib.test_utils.logger', autospec=True)
    @patch('sfc.lib.test_utils.download_url', autospec=True)
    @patch('os.path.isfile', autospec=True, return_value=False)
    @patch('os.path.dirname', autospec=True, return_value='mocked_')
    @patch('os.path.basename', autospec=True, return_value='image_path')
    def test_download_image_file_not_found(self,
                                           mock_basename,
                                           mock_dirname,
                                           mock_isfile,
                                           mock_download_url,
                                           mock_log):
        """
        Checks the proper functionality of download_image
        function when the image file was not found locally
        """

        url = 'mocked_/url'
        image_path = 'mocked_/image_path'
        log_calls = [call('Downloading image')]
        test_utils.download_image(url, image_path)
        mock_log.info.assert_has_calls(log_calls)
        mock_basename.assert_called_once_with(image_path)
        mock_dirname.assert_called_once_with(image_path)
        mock_isfile.assert_called_once_with(image_path)
        mock_download_url.assert_called_once_with('mocked_/url/image_path',
                                                  'mocked_')

    @patch('sfc.lib.test_utils.download_url')
    @patch('sfc.lib.test_utils.logger', autospec=True)
    @patch('os.path.isfile', autospec=True, return_value=True)
    @patch('os.path.dirname', autospec=True, return_value='mocked_')
    @patch('os.path.basename', autospec=True, return_value='image_path')
    def test_download_image_file_found(self,
                                       mock_basename,
                                       mock_dirname,
                                       mock_isfile,
                                       mock_log,
                                       mock_download_url):
        """
        Checks the proper functionality of download_image
        function when the image file was found locally
        """

        url = 'mocked_/url'
        image_path = 'mocked_/image_path'
        log_calls = [call('Using old image')]
        test_utils.download_image(url, image_path)
        mock_log.info.assert_has_calls(log_calls)
        mock_basename.assert_called_once_with(image_path)
        mock_dirname.assert_called_once_with(image_path)
        mock_isfile.assert_called_once_with(image_path)
        mock_download_url.assert_not_called()

    @patch('sfc.lib.test_utils.run_cmd', autospec=True)
    def test_ping_gets_error(self, mock_run_cmd):
        """
        Checks the proper functionality of ping
        function when run_cmd returns non-zero returncode
        """

        mock_cmd = 'ping -c1 -w1 %s' % self.ip
        mock_run_cmd.return_value = (1, '', '')
        self.assertFalse(test_utils.ping(self.ip, 1))
        mock_run_cmd.assert_called_once_with(mock_cmd)

    @patch('sfc.lib.test_utils.run_cmd', autospec=True)
    def test_ping_gets_no_error(self, mock_run_cmd):
        """
        Checks the proper functionality of ping
        function when run_cmd returns zero as returncode
        """

        mock_cmd = 'ping -c1 -w1 %s' % self.ip
        mock_run_cmd.return_value = (0, '', '')
        self.assertTrue(test_utils.ping(self.ip, 1))
        mock_run_cmd.assert_called_once_with(mock_cmd)

    @patch('time.sleep', autospec=True)
    @patch('sfc.lib.test_utils.logger', autospec=True)
    @patch('sfc.lib.test_utils.run_cmd_remote', autospec=True)
    def test_start_http_server_returned_false_failed_to_start(
            self, mock_run_cmd_remote, mock_log, mock_sleep):
        """
        Checks the proper functionality of start_http_server
        function when http_server is failed to start
        """

        cmd = "\'python -m SimpleHTTPServer 80 " + \
              "> /dev/null 2>&1 &\'"

        rcr_calls = [call(self.ip, cmd),
                     call(self.ip, 'ps aux | grep SimpleHTTPServer')]
        log_calls = [call('Failed to start http server')]

        mock_run_cmd_remote.side_effect = [('', '', ''),
                                           ('', '', '')]

        result = test_utils.start_http_server(self.ip, 1)
        self.assertFalse(result)
        mock_run_cmd_remote.assert_has_calls(rcr_calls)
        mock_sleep.assert_called_once_with(3)
        mock_log.error.assert_has_calls(log_calls)
        mock_log.info.assert_not_called()
        mock_log.debug.assert_not_called()

    @patch('time.sleep', autospec=True)
    @patch('sfc.lib.test_utils.logger', autospec=True)
    @patch('sfc.lib.test_utils.run_cmd_remote', autospec=True)
    def test_start_http_server_returned_false_port_is_down(
            self, mock_run_cmd_remote, mock_log, mock_sleep):
        """
        Checks the proper functionality of start_http_server
        function when port 80 is down
        """

        cmd = "\'python -m SimpleHTTPServer 80 " + \
              "> /dev/null 2>&1 &\'"

        rcr_calls = [call(self.ip, cmd),
                     call(self.ip, 'ps aux | grep SimpleHTTPServer'),
                     call(self.ip, 'netstat -pntl | grep :80')]

        log_calls = [call('output'),
                     call('Port 80 is not up yet')]

        mock_run_cmd_remote.side_effect = [('', '', ''),
                                           ('', 'output', ''),
                                           ('', '', '')]

        result = test_utils.start_http_server(self.ip, 1)
        self.assertFalse(result)
        mock_run_cmd_remote.assert_has_calls(rcr_calls)
        mock_sleep.assert_called_with(5)
        mock_log.info.assert_has_calls(log_calls[:1])
        mock_log.debug.assert_has_calls(log_calls[1:])

    @patch('time.sleep', autospec=True)
    @patch('sfc.lib.test_utils.logger', autospec=True)
    @patch('sfc.lib.test_utils.run_cmd_remote', autospec=True)
    def test_start_http_server_returned_true(self,
                                             mock_run_cmd_remote,
                                             mock_log,
                                             mock_sleep):
        """
        Checks the proper functionality of start_http_server
        function when the port 80 is up
        """

        cmd = "\'python -m SimpleHTTPServer 80 " + \
              "> /dev/null 2>&1 &\'"

        rcr_calls = [call(self.ip, cmd),
                     call(self.ip, 'ps aux | grep SimpleHTTPServer'),
                     call(self.ip, 'netstat -pntl | grep :80')]

        log_calls = [call('output')]

        mock_run_cmd_remote.side_effect = [('', '', ''),
                                           ('', 'output', ''),
                                           ('', 'output', '')]

        self.assertTrue(test_utils.start_http_server(self.ip, 1))
        mock_run_cmd_remote.assert_has_calls(rcr_calls)
        mock_sleep.assert_called_once_with(3)
        mock_log.info.assert_has_calls(log_calls)
        mock_log.debug.assert_not_called()

    @patch('time.sleep', autospec=True)
    @patch('sfc.lib.test_utils.logger', autospec=True)
    @patch('sfc.lib.test_utils.run_cmd_remote', autospec=True)
    def test_start_vxlan_tool_returned_false(self,
                                             mock_run_cmd_remote,
                                             mock_log,
                                             mock_sleep):
        """
        Checks the proper functionality of start_vxlan_tool
        function when no output is returned on ps command
        """

        mock_run_cmd_remote.side_effect = [('', 'output', ''),
                                           ('', '', '')]

        mock_rc = 'nohup python /root/vxlan_tool.py --do ' + \
                  'forward --interface eth0   > /dev/null 2>&1 &'

        rcr_calls = [call(self.ip, mock_rc),
                     call(self.ip, 'ps aux | grep vxlan_tool')]

        log_calls = [call('Failed to start the vxlan tool')]

        self.assertFalse(test_utils.start_vxlan_tool(self.ip))
        mock_sleep.assert_called_once_with(3)
        mock_run_cmd_remote.assert_has_calls(rcr_calls)
        mock_log.error.assert_has_calls(log_calls)

    @patch('time.sleep', autospec=True)
    @patch('sfc.lib.test_utils.logger', autospec=True)
    @patch('sfc.lib.test_utils.run_cmd_remote', autospec=True)
    def test_start_vxlan_tool_returned_output(self,
                                              mock_run_cmd_remote,
                                              mock_log,
                                              mock_sleep):
        """
        Checks the proper functionality of start_vxlan_tool
        function when output is returned on ps command
        """

        mock_run_cmd_remote.side_effect = [('', 'output', ''),
                                           ('', 'output', '')]

        mock_rc = 'nohup python /root/vxlan_tool.py --do ' + \
                  'forward --interface eth0   > /dev/null 2>&1 &'

        rcr_calls = [call(self.ip, mock_rc),
                     call(self.ip, 'ps aux | grep vxlan_tool')]

        self.assertIsNotNone(test_utils.start_vxlan_tool(self.ip))
        mock_sleep.assert_called_once_with(3)
        mock_run_cmd_remote.assert_has_calls(rcr_calls)
        mock_log.error.assert_not_called()

    @patch('sfc.lib.test_utils.run_cmd_remote', autospec=True)
    def test_stop_vxlan_tool(self, mock_run_cmd_remote):
        """
        Checks the proper functionality of stop_vxlan_tool
        function
        """

        mock_rc = 'pkill -f vxlan_tool.py'
        test_utils.stop_vxlan_tool(self.ip)
        mock_run_cmd_remote.assert_called_once_with(self.ip, mock_rc)

    @patch('sfc.lib.test_utils.logger', autospec=True)
    @patch('sfc.lib.test_utils.run_cmd_remote', autospec=True)
    def test_netcat(self,
                    mock_run_cmd_remote,
                    mock_log):
        """
        Checks the proper functionality of netcat
        function
        """

        dest_ip = 'mock_destination_ip'
        c = 'nc -z  -w 5 %s 1234' % dest_ip
        log_calls = [call('Running [%s] from [%s] returns [0]' % (c, self.ip))]
        mock_run_cmd_remote.return_value = (0, '', '')
        result = test_utils.netcat(self.ip, dest_ip, 1234)
        self.assertEqual(result, 0)
        mock_log.info.assert_has_calls(log_calls)

    @patch('sfc.lib.test_utils.netcat', autospec=True)
    def test_is_ssh_blocked_returned_false(self, mock_netcat):
        """
        Checks the proper funcitonality of is_ssh_blocked
        function when the returncode is zero
        """

        dest_ip = 'mock_destination_ip'
        nc_calls = [call('10.10.10.10',
                         'mock_destination_ip',
                         destination_port='22',
                         source_port=None)]

        mock_netcat.return_value = 0
        self.assertFalse(test_utils.is_ssh_blocked(self.ip, dest_ip))
        mock_netcat.assert_has_calls(nc_calls)

    @patch('sfc.lib.test_utils.netcat', autospec=True)
    def test_is_ssh_blocked_returned_true(self, mock_netcat):
        """
        Checks the proper funcitonality of is_ssh_blocked
        function when the returncode is non-zero integer
        """

        dest_ip = 'mock_destination_ip'
        nc_calls = [call('10.10.10.10',
                         'mock_destination_ip',
                         destination_port='22',
                         source_port=None)]

        mock_netcat.return_value = 1
        self.assertTrue(test_utils.is_ssh_blocked(self.ip, dest_ip))
        mock_netcat.assert_has_calls(nc_calls)

    @patch('sfc.lib.test_utils.netcat', autospec=True)
    def test_is_http_blocked_returned_false(self, mock_netcat):
        """
        Checks the proper funcitonality of is_http_blocked
        function when the returncode is zero
        """

        dest_ip = 'mock_destination_ip'
        nc_calls = [call('10.10.10.10',
                         'mock_destination_ip',
                         destination_port='80',
                         source_port=None)]

        mock_netcat.return_value = 0
        self.assertFalse(test_utils.is_http_blocked(self.ip, dest_ip))
        mock_netcat.assert_has_calls(nc_calls)

    @patch('sfc.lib.test_utils.netcat', autospec=True)
    def test_is_http_blocked_returned_true(self, mock_netcat):
        """
        Checks the proper funcitonality of is_http_blocked
        function when the returncode is non-zero integer
        """

        dest_ip = 'mock_destination_ip'
        nc_calls = [call('10.10.10.10',
                         'mock_destination_ip',
                         destination_port='80',
                         source_port=None)]

        mock_netcat.return_value = 1
        self.assertTrue(test_utils.is_http_blocked(self.ip, dest_ip))
        mock_netcat.assert_has_calls(nc_calls)

    @patch('time.strftime', autospec=True)
    @patch('opnfv.utils.ovs_logger.OVSLogger', autospec=True)
    def test_capture_ovs_logs(self,
                              mock_ovs_log,
                              mock_strftime):
        """
        Checks the proper functionality of capture_ovs_logs
        function
        """

        log_calls = [call('controller_clients',
                          'compute_clients',
                          'error',
                          'date_time')]

        mock_strftime.return_value = 'date_time'
        test_utils.capture_ovs_logs(mock_ovs_log,
                                    'controller_clients',
                                    'compute_clients',
                                    'error')

        mock_strftime.assert_called_once_with('%Y%m%d-%H%M%S')
        mock_ovs_log.dump_ovs_logs.assert_has_calls(log_calls)

    def test_get_ssh_clients(self):
        """
        Checks the proper functionality of get_ssh_clients
        fucntion
        """

        mock_node_obj_one = Mock()
        mock_node_obj_two = Mock()
        mock_node_obj_one.ssh_client = 'ssh_client_one'
        mock_node_obj_two.ssh_client = 'ssh_client_two'
        nodes = [mock_node_obj_one, mock_node_obj_two]
        result = test_utils.get_ssh_clients(nodes)
        self.assertEqual(result, ['ssh_client_one', 'ssh_client_two'])

    @patch('time.sleep', autospec=True)
    @patch('sfc.lib.test_utils.logger', autospec=True)
    @patch('sfc.lib.test_utils.run_cmd_remote', autospec=True)
    def test_check_ssh_returned_false(self,
                                      mock_run_cmd_remote,
                                      mock_log,
                                      mock_sleep):
        """
        Checks the proper functionality of check_ssh
        fucntion when few VNFs can't establish SSH connectivity
        """

        ips = ["ip_address-1",
               "ip_address-2"]

        rcr_calls = [call(ips[0], 'exit'),
                     call(ips[1], 'exit')]

        log_calls = [call('Checking SSH connectivity ' +
                          'to the SFs with ips %s' % str(ips))]

        mock_run_cmd_remote.side_effect = [(1, '', ''),
                                           (0, '', '')]

        self.assertFalse(test_utils.check_ssh(ips, retries=1))
        mock_run_cmd_remote.assert_has_calls(rcr_calls)
        mock_log.info.assert_has_calls(log_calls)
        mock_sleep.assert_called_once_with(3)

    @patch('time.sleep', autospec=True)
    @patch('sfc.lib.test_utils.logger', autospec=True)
    @patch('sfc.lib.test_utils.run_cmd_remote', autospec=True)
    def test_check_ssh_returned_true(self,
                                     mock_run_cmd_remote,
                                     mock_log,
                                     mock_sleep):
        """
        Checks the proper functionality of check_ssh
        fucntion when all VNFs can establish SSH connectivity
        """

        ips = ["ip_address-1",
               "ip_address-2"]

        rcr_calls = [call(ips[0], 'exit'),
                     call(ips[1], 'exit')]

        log_calls = [call('Checking SSH connectivity to ' +
                          'the SFs with ips %s' % str(ips)),
                     call('SSH connectivity to the SFs established')]

        mock_run_cmd_remote.side_effect = [(0, '', ''),
                                           (0, '', '')]

        self.assertTrue(test_utils.check_ssh(ips, retries=1))
        mock_run_cmd_remote.assert_has_calls(rcr_calls)
        mock_log.info.assert_has_calls(log_calls)
        mock_sleep.assert_not_called()

    def test_fill_installer_dict(self):
        """
        Checks the proper functionality of fill_installer_dict
        function
        """

        installer_type = 'mock_installer'
        installer_yaml_fields = {
            'user': 'defaults.installer.mock_installer.user',
            'password': 'defaults.installer.mock_installer.password',
            'cluster': 'defaults.installer.mock_installer.cluster',
            'pkey_file': 'defaults.installer.mock_installer.pkey_file'
        }
        result = test_utils.fill_installer_dict(installer_type)
        self.assertDictEqual(result, installer_yaml_fields)
