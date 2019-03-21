#!/usr/bin/python
#
# Copyright (c) 2016 All rights reserved
# This program and the accompanying materials
# are made available under the terms of the Apache License, Version 2.0
# which accompanies this distribution, and is available at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
import os
import subprocess
import time
import shutil
import urllib
import logging

logger = logging.getLogger(__name__)
SSH_OPTIONS = '-q -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no'
FUNCTEST_RESULTS_DIR = os.path.join("home", "opnfv",
                                    "functest", "results", "odl-sfc")


def run_cmd(cmd):
    """
    Run given command locally
    Return a tuple with the return code, stdout, and stderr of the command
    """
    pipe = subprocess.Popen(cmd,
                            shell=True,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)

    stdout, stderr = [stream.strip() for stream in pipe.communicate()]
    output = ' - STDOUT: "%s"' % stdout if len(stdout) > 0 else ''
    error = ' - STDERR: "%s"' % stdout if len(stderr) > 0 else ''
    logger.debug("Running [{command}] returns: [{rc}]{output}{error}".format(
                 command=cmd,
                 rc=pipe.returncode,
                 output=output,
                 error=error))

    return pipe.returncode, stdout, stderr


def run_cmd_remote(ip, cmd, username="root", passwd="opnfv"):
    """run given command on Remote Machine, Can be VM"""
    ssh_opt_append = "%s -o ConnectTimeout=50 " % SSH_OPTIONS
    ssh_cmd = "sshpass -p %s ssh %s %s@%s %s" % (
        passwd, ssh_opt_append, username, ip, cmd)
    return run_cmd(ssh_cmd)


def download_url(url, dest_path):
    """
    Download a file to a destination path given a URL
    """
    name = url.rsplit('/')[-1]
    dest = dest_path + "/" + name
    try:
        response = urllib.urlopen(url)
    except Exception:
        return False

    with open(dest, 'wb') as lfile:
        shutil.copyfileobj(response, lfile)
    return True


def download_image(url, image_path):
    image_filename = os.path.basename(image_path)
    image_url = "%s/%s" % (url, image_filename)
    image_dir = os.path.dirname(image_path)
    if not os.path.isfile(image_path):
        logger.info("Downloading image")
        download_url(image_url, image_dir)
    else:
        logger.info("Using old image")


def ping(remote, retries=100, retry_timeout=1):
    cmd = 'ping -c1 -w{timeout} {remote}'.format(
          timeout=retry_timeout,
          remote=remote)

    while retries > 0:
        rc, _, _ = run_cmd(cmd)
        if rc == 0:
            return True

        retries -= 1

    return False


def start_http_server(ip, iterations_check=10):
    """
    Start http server on a given machine. Wait until the process exists
    and until the port is up
    """
    cmd = "\'python -m SimpleHTTPServer 80"
    cmd = cmd + " > /dev/null 2>&1 &\'"
    run_cmd_remote(ip, cmd)

    # Wait for the process to start before checking
    time.sleep(3)
    _, output, _ = run_cmd_remote(ip, "ps aux | grep SimpleHTTPServer")
    if not output:
        logger.error("Failed to start http server")
        return False
    logger.info(output)

    while iterations_check > 0:
        _, output, _ = run_cmd_remote(ip, "netstat -pntl | grep :80")
        if output:
            return True
        else:
            logger.debug("Port 80 is not up yet")
            iterations_check -= 1
            time.sleep(5)

    logger.error("Failed to start http server")
    return False


def start_vxlan_tool(remote_ip, interface="eth0", output=None, block=None):
    """
    Starts vxlan_tool on a remote host.
    vxlan_tool.py converts a regular Service Function into a NSH-aware SF
    when the "--do forward" option is used, it decrements the NSI appropiately.
    'output' allows to specify an interface through which to forward if
    different than the input interface.
    'block' parameter allows to specify a port where packets will be dropped.
    """
    command = "nohup python /root/vxlan_tool.py"
    options = "{do} {interface} {output_option} {block_option}".format(
        do="--do forward",
        interface="--interface {}".format(interface),
        output_option="--output {}".format(output) if output else "",
        block_option="--block {}".format(block) if block is not None else "")
    output_redirection = "> /dev/null 2>&1"

    full_command = "{command} {options} {output_redirection} &".format(
        command=command,
        options=options,
        output_redirection=output_redirection)

    output_execution = run_cmd_remote(remote_ip, full_command)

    # Wait for the process to start before checking
    time.sleep(3)
    _, output, _ = run_cmd_remote(remote_ip, "ps aux | grep vxlan_tool")
    if not output:
        logger.error("Failed to start the vxlan tool")
        return False

    return output_execution


def stop_vxlan_tool(remote_ip):
    """ Stops vxlan_tool on a remote host"""
    command = "pkill -f vxlan_tool.py"
    return run_cmd_remote(remote_ip, command)


def netcat(source_ip, destination_ip, destination_port, source_port=None,
           timeout=5):
    """
    SSH into source_ip, and check the connectivity from there to destination_ip
    on the specified port, using the netcat command.
    Returns 0 on successful execution, != 0 on failure
    """
    source_port_option = '' if source_port is None else '-p %s' % source_port
    cmd = "nc -z {option} -w {timeout} {ip} {port}".format(
          option=source_port_option,
          timeout=timeout,
          ip=destination_ip,
          port=destination_port)
    rc, _, _ = run_cmd_remote(source_ip, cmd)
    logger.info("Running [%s] from [%s] returns [%s]" % (cmd, source_ip, rc))
    return rc


def is_ssh_blocked(source_ip, destination_ip, source_port=None):
    rc = netcat(
        source_ip,
        destination_ip,
        destination_port="22",
        source_port=source_port)
    return rc != 0


def is_http_blocked(source_ip, destination_ip, source_port=None):
    rc = netcat(
        source_ip,
        destination_ip,
        destination_port="80",
        source_port=source_port)
    return rc != 0


def capture_ovs_logs(ovs_logger, controller_clients, compute_clients, error):
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    ovs_logger.dump_ovs_logs(controller_clients,
                             compute_clients,
                             related_error=error,
                             timestamp=timestamp)


def get_ssh_clients(nodes):
    return [n.ssh_client for n in nodes]


def check_ssh(ips, retries=100):
    """Check SSH connectivity to VNFs"""
    check = [False for ip in ips]
    logger.info("Checking SSH connectivity to the SFs with ips %s" % str(ips))
    while retries and not all(check):
        for index, ip in enumerate(ips):
            rc, _, _ = run_cmd_remote(ip, "exit")
            check[index] = True if rc == 0 else False

        if all(check):
            logger.info("SSH connectivity to the SFs established")
            return True

        time.sleep(3)
        retries -= 1

    return False


def fill_installer_dict(installer_type):
    default_string = "defaults.installer.{}.".format(installer_type)
    installer_yaml_fields = {
                            "user": default_string+"user",
                            "password": default_string+"password",
                            "cluster": default_string+"cluster",
                            "pkey_file": default_string+"pkey_file"
                        }
    return installer_yaml_fields
