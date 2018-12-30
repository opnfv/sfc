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

from osmclient import client

logger = logging.getLogger(__name__)
DEFAULT_OSM_HOSTNAME = '127.0.0.1'

####################
# OSM API
####################


def get_osm_host():
    hostname = os.getenv('OSM_HOSTNAME')
    if hostname is not None:
        logger.info("OSM_HOSTNAME is set in env as {}".format(hostname))
        return hostname
    return DEFAULT_OSM_HOSTNAME


def get_osm_client():
    return client.Client(host=get_osm_host(), sol005=True)


####################
# VIM Operations
####################


def vim_create(osm_client,
               name,
               account_type='openstack',
               config='{insecure: true}',
               description='openstack-site',
               sdn_controller=None,
               sdn_port_mapping=None):
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
    try:
        return osm_client.vim.delete(name, force=force)
    except Exception as e:
        logger.error("Error [vim_delete(osm_client, {}, {})]: {}"
                     .format(name, force, e))
        return None


####################
# VNFD Operations
####################


def vnfd_create(osm_client, filename, overwrite=None):
    try:
        return osm_client.vnfd.create(filename, overwrite=overwrite)
    except Exception as e:
        logger.error("Error [vnfd_create(osm_client, {}, {})]: {}"
                     .format(filename, overwrite, e))
        return None


def vnfd_list(osm_client, nf_type=None, _filter=None, verbose=False):
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
                _filter = '{}&{}'.format(nf_filter, filter)
            else:
                _filter = nf_filter
        vnfds = osm_client.vnfd.list(filter=_filter)
        if not verbose:
            vnfds = [vnfd['id'] for vnfd in vnfds]
        return vnfds
    except Exception as e:
        logger.error("Error [vnfd_list(osm_client, {}, {}, {})]: {}"
                     .format(nf_type, filter, verbose, e))
        return None


def vnfd_delete(osm_client, name, force=False):
    try:
        return osm_client.vnfd.delete(name, force=force)
    except Exception as e:
        logger.error("Error [vnfd_delete(osm_client, {}, {})]: {}"
                     .format(name, force, e))
        return None


####################
# NSD Operations
####################


def nsd_create(osm_client, filename, overwrite=None):
    try:
        return osm_client.nsd.create(filename, overwrite=overwrite)
    except Exception as e:
        logger.error("Error [nsd_create(osm_client, {}, {})]: {}"
                     .format(filename, overwrite, e))
        return None


def nsd_list(osm_client, _filter=None, verbose=False):
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
    try:
        return osm_client.nsd.delete(name, force=force)
    except Exception as e:
        logger.error("Error [nsd_delete(osm_client, {}, {})]: {}"
                     .format(name, force, e))
        return None


####################
# VNF Operations
####################


def vnf_list(osm_client, ns=None, _filter=None, verbose=False):
    try:
        vnfs = osm_client.vnf.list(ns=ns, filter=_filter)
        if not verbose:
            vnfs = [vnf['id'] for vnf in vnfs]
        return vnfs
    except Exception as e:
        logger.error("Error [vnf_list(osm_client, {}, {})]: {}"
                     .format(ns, filter, e))
        return None


####################
# NS Operations
####################


def ns_create(osm_client,
              nsd_name,
              ns_name,
              vim_account,
              ssh_keys=None,
              config=None,
              config_file=None):
    try:
        if config_file:
            if config:
                raise Exception("'config' option is incompatable "
                                "with 'config_file' option")
            with open(config_file, 'r') as cf:
                config = cf.read()
        return osm_client.ns.create(nsd_name,
                                    ns_name,
                                    vim_account,
                                    config=config,
                                    ssh_keys=ssh_keys)
    except Exception as e:
        logger.error("Error [ns_create(osm_client, {}, {}, {}, {}, {})]: {}"
                     .format(nsd_name, ns_name, vim_account,
                             ssh_keys, config, e))
        return None


def ns_list(osm_client, _filter=None, verbose=False):
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
    try:
        return osm_client.ns.delete(name, force=force)
    except Exception as e:
        logger.error("Error [ns_delete(osm_client, {}, {})]: {}"
                     .format(name, force, e))
        return None


####################
# SDN Controller Operations
####################


def sdnc_create(osm_client,
                name,
                type,
                ip_address,
                port,
                switch_dpid,
                user,
                password):
    try:
        sdnc = {}
        sdnc['name'] = name
        sdnc['type'] = type
        sdnc['ip'] = ip_address
        sdnc['port'] = int(port)
        sdnc['dpid'] = switch_dpid
        sdnc['user'] = user
        sdnc['password'] = password
        return osm_client.sdnc.create(name, sdnc)
    except Exception as e:
        logger.error("Error [sdnc_create(osm_client, {})]: {}".format(sdnc, e))
        return None


def sdnc_list(osm_client, _filter=None, verbose=False):
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
    try:
        return osm_client.sdnc.delete(name, force=force)
    except Exception as e:
        logger.error("Error [sdnc_delete(osm_client, {}, {})]: {}"
                     .format(name, force, e))
        return None
