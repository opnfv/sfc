#!/usr/bin/env python

# Copyright 2015, Ericsson AB
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
FUEL inventory script for Ansible

References:
  http://docs.ansible.com/intro_dynamic_inventory.html
  http://docs.ansible.com/developing_inventory.html
  https://github.com/stackforge/python-fuelclient
  https://github.com/martineg/ansible-fuel-inventory
"""

# Standard libraries
import argparse
import collections
import json
import os
import sys
import re

# 3rd party libraries
from fuelclient.objects import Environment
from fuelclient import fuelclient_settings

def cname(fname):
   """
   Converts the name read from fuel to a valid ansible inventory name
   """
   return re.sub('[^0-9a-zA-Z]+', '-', fname)

def get_fuel_environment():
    """
    As FUEL can have multiple environments configured we expect environment
    identifier is set as FUEL_ENV_ID environment variable otherwise the first
    operational environment is used.
    """
    env_id = os.environ.get('FUEL_ENV_ID')
    envs = [Environment(int(env_id))] if env_id else Environment.get_all()
    operational_envs = [e for e in envs if e.status == 'operational']
    # TODO: if FUEL_ENV_ID does not exist we get an HTTP error message
    if not operational_envs:
        sys.stderr.write("ERROR: environment is not operational\n")
        sys.exit(1)
    return operational_envs[0]


def parse_args():
    """
    Argument parser implementing Ansible dynamic inventory script requirements.
    """
    parser = argparse.ArgumentParser(description="FUEL inventory script")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--list', action='store_true')
    group.add_argument('--host')
    return parser.parse_args()


def get_fuel_node_details(node):
    """
    Fuelclient specific node details
    """
    return {
        'ansible_ssh_host': node.data['ip'],
        'fuel_data': node.data,
        'fuel_disks': node.get_attribute('disks'),
        'fuel_interfaces': node.get_attribute('interfaces')
    }


def get_host_details(env, host):
    """
    Host specific variables if --host <host> parameter is used.
    """
    for node in env.get_all_nodes():
        node_name = cname(node.data['name'])
        if host == node_name:
            return get_fuel_node_details(node)


def list_running_hosts(env):
    """
    Use new style inventory script (_meta) available from 1.3 as it has
    performance improvement not running inventory script for each node.
    """
    inventory = collections.defaultdict(
        lambda: {'hosts': []},
        all={
            'vars': {
                'fuel_network': env.get_network_data(),
                'fuel_generated': env.connection.get_request(
                    "clusters/{id}/generated".format(id=env.id)),
                'fuel_master_ip': get_fuel_ip()
            }
        },
        _meta={'hostvars': {}}
    )
    for node in env.get_all_nodes():
        node_name = cname(node.data['name'])
        inventory['_meta']['hostvars'][node_name] = get_fuel_node_details(node)
        for role in node.data['roles']:
            inventory[role]['hosts'].append(node_name)
    return inventory


def get_fuel_ip():
    conf = fuelclient_settings.get_settings()
    return conf.SERVER_ADDRESS


def main():
    """
    Main entry point
    """
    args = parse_args()
    env = get_fuel_environment()
    if args.list:
        inventory = list_running_hosts(env)
    else:
        inventory = get_host_details(env, args.host)
    json.dump(inventory, sys.stdout)


if __name__ == '__main__':
    main()
