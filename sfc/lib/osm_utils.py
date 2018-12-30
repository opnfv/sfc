import os
import logging

from osmclient import client

logger = logging.getLogger(__name__)
DEFAULT_OSM_HOSTNAME = '127.0.0.1'


def get_osm_host():
    hostname = os.getenv('OSM_HOSTNAME')
    if hostname is not None:
        logger.info("OSM_HOSTNAME is set in env as {}".format(hostname))
        return hostname
    return DEFAULT_OSM_HOSTNAME


def get_osm_client():
    return client.Client(host=get_osm_host(), sol005=True)


def create_vim(osm_client,
               name,
               vim,
               sdn_controller=None,
               sdn_port_mapping=None):
    logger.info("Creating the vim...")
    try:
        if sdn_controller or sdn_port_mapping:
            osm_client.vim.create(name, vim, sdn_controller, sdn_port_mapping)
        else:
            osm_client.vim.create(name, vim)
    except Exception as e:
        logger.error("Error [create_vim(osm_client, {}, {}, {}, {})]: {}"
                     .format(name, vim, sdn_controller, sdn_port_mapping, e))


def register_vim(osm_client,
                 name,
                 account_type='openstack',
                 config='{insecure: true}',
                 description='',
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

    create_vim(osm_client, name, vim, sdn_controller, sdn_port_mapping)


def create_vnfd(osm_client):
    pass


def create_nsd(osm_client):
    pass


def create_ns(osm_client):
    pass
