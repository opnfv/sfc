###############################################################################
# Copyright (c) 2018 Venkata Harshavardhan Reddy Allu and others.
#
# All rights reserved. This program and the accompanying materials
# are made available under the terms of the Apache License, Version 2.0
# which accompanies this distribution, and is available at
# http://www.apache.org/licenses/LICENSE-2.0
###############################################################################

import os
import logging

from time import sleep
from osmclient import client

logger = logging.getLogger(__name__)
DEFAULT_OSM_HOSTNAME = '192.168.122.2'


def get_osm_host():
    hostname = os.getenv('OSM_HOSTNAME')
    if hostname is not None:
        logger.info("OSM_HOSTNAME is set in env as {}".format(hostname))
        return hostname
    return DEFAULT_OSM_HOSTNAME


def get_osm_client():
    return client.Client(host=get_osm_host(), sol005=True)


def vim_register(osm_client,
                 name,
                 account_type='openstack',
                 config=None,
                 description='openstack-site',
                 sdn_controller=None,
                 sdn_port_mapping=None):
    """
    Create a new VIM account
    """
    logger.info("Registering the VIM... {}".format(name))
    vim = {}
    vim['vim-username'] = os.getenv('OS_USERNAME')
    vim['vim-password'] = os.getenv('OS_PASSWORD')
    vim['vim-url'] = os.getenv('OS_AUTH_URL')
    vim['vim-tenant-name'] = os.getenv('OS_TENANT_NAME')
    vim['vim-type'] = account_type
    vim['description'] = description
    vim['config'] = config
    try:
        return osm_client.vim.create(name, vim,
                                     sdn_controller=sdn_controller,
                                     sdn_port_mapping=sdn_port_mapping)
    except Exception as e:
        logger.error("Error [create_vim(osm_client, {}, {}, {}, {})]: {}"
                     .format(name, vim, sdn_controller, sdn_port_mapping, e))
        return None


def vim_list(osm_client, _filter=None, verbose=False):
    """
    list all VIM accounts
    """
    try:
        vims = osm_client.vim.list(filter=_filter)
        if not verbose:
            vims = [vim['uuid'] for vim in vims]
        return vims
    except Exception as e:
        logger.error("Error [vim_list(osm_client, {}, {})]: {}"
                     .format(_filter, verbose, e))
        return None


def vim_delete(osm_client, name, force=False):
    """
    deletes a VIM account by its name or ID
    """
    logger.info("Deleting the VIM account... {}".format(name))
    try:
        return osm_client.vim.delete(name, force=force)
    except Exception as e:
        logger.error("Error [vim_delete(osm_client, {}, {})]: {}"
                     .format(name, force, e))
        return None


def vnfd_create(osm_client, name, filename, overwrite=None):
    """
    creates a new VNFD from the yaml file or tar.gz file
    """
    logger.info("Creating the VNFD... {}".format(name))
    try:
        return osm_client.vnfd.create(filename, overwrite=overwrite)
    except Exception as e:
        logger.error("Error [vnfd_create(osm_client, {}, {})]: {}"
                     .format(filename, overwrite, e))
        return None


def vnfd_list(osm_client, nf_type=None, _filter=None, verbose=False):
    """
    list all VNFD in the system
    """
    try:
        if nf_type:
            if nf_type == "vnf":
                nf_filter = "_admin.type=vnfd"
            elif nf_type == "pnf":
                nf_filter = "_admin.type=pnfd"
            elif nf_type == "hnf":
                nf_filter = "_admin.type=hnfd"
            else:
                raise Exception("wrong value for 'nf_type' argument, allowed "
                                "values: vnf, pnf, hnf")
            if _filter:
                _filter = '{}&{}'.format(nf_filter, _filter)
            else:
                _filter = nf_filter
        vnfds = osm_client.vnfd.list(filter=_filter)
        if not verbose:
            vnfds = [vnfd['id'] for vnfd in vnfds]
        return vnfds
    except Exception as e:
        logger.error("Error [vnfd_list(osm_client, {}, {}, {})]: {}"
                     .format(nf_type, _filter, verbose, e))
        return None


def vnfd_delete(osm_client, name, force=False):
    """
    deletes a VNFD by its name or ID
    """
    logger.info("Deleting the VNFD... {}".format(name))
    try:
        return osm_client.vnfd.delete(name, force=force)
    except Exception as e:
        logger.error("Error [vnfd_delete(osm_client, {}, {})]: {}"
                     .format(name, force, e))
        return None


def nsd_create(osm_client, name, filename, overwrite=None):
    """
    creates a new NSD from the yaml file or tar.gz file
    """
    logger.info("Creating the NSD... {}".format(name))
    try:
        return osm_client.nsd.create(filename, overwrite=overwrite)
    except Exception as e:
        logger.error("Error [nsd_create(osm_client, {}, {})]: {}"
                     .format(filename, overwrite, e))
        return None


def nsd_list(osm_client, _filter=None, verbose=False):
    """
    list all NSD in the system
    """
    try:
        nsds = osm_client.nsd.list(filter=_filter)
        if not verbose:
            nsds = [nsd['_id'] for nsd in nsds]
        return nsds
    except Exception as e:
        logger.error("Error [nsd_list(osm_client, {})]: {}"
                     .format(_filter, e))
        return None


def nsd_delete(osm_client, name, force=False):
    """
    deletes a NSD by its name or ID
    """
    logger.info("Deleting the NSD... {}".format(name))
    try:
        return osm_client.nsd.delete(name, force=force)
    except Exception as e:
        logger.error("Error [nsd_delete(osm_client, {}, {})]: {}"
                     .format(name, force, e))
        return None


def vnf_list(osm_client, ns=None, _filter=None, verbose=False):
    """
    list all NF instances
    """
    try:
        vnfs = osm_client.vnf.list(ns=ns, filter=_filter)
        if not verbose:
            vnfs = [vnf['id'] for vnf in vnfs]
        return vnfs
    except Exception as e:
        logger.error("Error [vnf_list(osm_client, {}, {})]: {}"
                     .format(ns, _filter, e))
        return None


def get_vnf_ip(osm_client, vnf_id):
    """
    Return the ip of given vnf
    """
    try:
        vnfs = vnf_list(osm_client)
        for vnf in vnfs:
            if vnf['id'] == vnf_id:
                return vnf['ip-address']
    except Exception as e:
        logger.error("Error [get_vnf_ip(osm_client, {})]: {}"
                     .format(vnf_id, e))
    return None


def ns_create(osm_client,
              ns_name,
              nsd_name,
              vim_account,
              config=None,
              config_file=None,
              ssh_keys=None):
    """
    creates a new Network Service instance
    """
    logger.info("Creating the NS instance... {}".format(ns_name))
    try:
        if config_file:
            if config:
                raise Exception("'config' option is incompatable "
                                "with 'config_file' option")
            with open(config_file, 'r') as cf:
                config = cf.read()
        ns_id = osm_client.ns.create(nsd_name,
                                     ns_name,
                                     vim_account,
                                     config=config,
                                     ssh_keys=ssh_keys)
        wait_for_ns_to_be_ready(osm_client, ns_id)
        return ns_id
    except Exception as e:
        logger.error("Error [ns_create(osm_client, {}, {}, {}, {}, {})]: {}"
                     .format(ns_name, nsd_name, vim_account,
                             ssh_keys, config, e))
        return None


def wait_for_ns_to_be_ready(osm_client, ns_id):
    """
    Wait for the NS instances to be ready
    """
    logger.info("Wait for tne NS instance to be ready...")
    try:
        while True:
            nss = ns_list(osm_client)
            if nss:
                for nsi in nss:
                    if nsi['id'] == ns_id:
                        if nsi['detailed-status'] == 'done':
                            logger.info("Ready")
                            return
                        elif 'ERROR' in nsi['detailed-status']:
                            raise Exception(nsi('detailed-status'))
                sleep(30)
            else:
                logger.error("No network service found!")
                return
    except Exception as e:
        logger.error("Error [wait_for_ns_to_be_ready(osm_client, {})]: {}"
                     .format(ns_id, e))


def ns_list(osm_client, _filter=None, verbose=False):
    """
    list all NS instances
    """
    try:
        nss = osm_client.ns.list(filter=_filter)
        if not verbose:
            nss = [ns['id'] for ns in nss]
        return nss
    except Exception as e:
        logger.error("Error [ns_list(osm_client, {}, {})]: {}"
                     .format(_filter, verbose, e))
        return None


def ns_delete(osm_client, name, force=False):
    """
    deletes a NS instance
    """
    logger.info("Deleting the NS instance... {}".format(name))
    try:
        osm_client.ns.delete(name, force=force)
    except Exception as e:
        logger.error("Error [ns_delete(osm_client, {}, {})]: {}"
                     .format(name, force, e))


def wait_for_ns_to_be_deleted(osm_client, ns_id):
    """
    Wait for the NS instance to be deleted
    """
    logger.info("Wait for the NS instance to be deleted...")
    try:
        while True:
            nss = ns_list(osm_client)
            nss_verbose = ns_list(osm_client, verbose=True)
            if nss:
                if ns_id in nss:
                    for nsi in nss_verbose:
                        if ns_id == nsi['id']:
                            if 'ERROR' in nsi['detailed-status']:
                                osm_client.ns.delete(ns_id, force=True)
                            else:
                                sleep(30)
                else:
                    logger.info('Deleted!')
                    return
            else:
                return
    except Exception as e:
        logger.error("Error [wait_for_ns_to_be_deleted(osm_client, {})]: {}"
                     .format(ns_id, e))


def sdnc_register(osm_client,
                  name,
                  _type,
                  ip_address,
                  port,
                  switch_dpid,
                  user,
                  password):
    """
    Create a new SDN controller account
    """
    logger.info("Registering the SDN controller... {}".format(name))
    try:
        sdnc = {}
        sdnc['name'] = name
        sdnc['type'] = _type
        sdnc['ip'] = ip_address
        sdnc['port'] = int(port)
        sdnc['dpid'] = switch_dpid
        sdnc['user'] = user
        sdnc['password'] = password
        return osm_client.sdnc.create(name, sdnc)
    except Exception as e:
        logger.error("Error [sdnc_register(osm_client, {})]: {}"
                     .format(name, e))
        return None


def sdnc_list(osm_client, _filter=None, verbose=False):
    """
    list all SDN controllers
    """
    try:
        sdncs = osm_client.sdnc.list(filter=_filter)
        if not verbose:
            sdncs = [sdnc['id'] for sdnc in sdncs]
        return sdncs
    except Exception as e:
        logger.error("Error [sdnc_list(osm_client, {}, {})]: {}"
                     .format(_filter, verbose, e))
        return None


def sdnc_delete(osm_client, name, force=False):
    """
    deletes an SDN controller by its name or ID
    """
    logger.info("Deleting the SDN controller... {}".format(name))
    try:
        return osm_client.sdnc.delete(name, force=force)
    except Exception as e:
        logger.error("Error [sdnc_delete(osm_client, {}, {})]: {}"
                     .format(name, force, e))
        return None
