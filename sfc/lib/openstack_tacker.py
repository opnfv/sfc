import logging
import os
import time
import json

from tackerclient.tacker import client as tackerclient
from functest.utils import openstack_utils as os_utils


logger = logging.getLogger(__name__)

DEFAULT_TACKER_API_VERSION = '1.0'


def get_tacker_client_version():
    api_version = os.getenv('OS_TACKER_API_VERSION')
    if api_version is not None:
        logger.info("OS_TACKER_API_VERSION is set in env as '%s'", api_version)
        return api_version
    return DEFAULT_TACKER_API_VERSION


def get_tacker_client(other_creds={}):
    sess = os_utils.get_session(other_creds)
    return tackerclient.Client(get_tacker_client_version(), session=sess)


def get_id_from_name(tacker_client, resource_type, resource_name):
    try:
        req_params = {'fields': 'id', 'name': resource_name}
        endpoint = '/{0}s'.format(resource_type)
        resp = tacker_client.get(endpoint, params=req_params)
        endpoint = endpoint.replace('-', '_')
        return resp[endpoint[1:]][0]['id']
    except Exception, e:
        logger.error("Error [get_id_from_name(tacker_client, "
                     "resource_type, resource_name)]: %s" % e)
        return None


def get_vnfd_id(tacker_client, vnfd_name):
    return get_id_from_name(tacker_client, 'vnfd', vnfd_name)

def get_vim_id(tacker_client,vim_name):
    return get_id_from_name(tacker_client, 'vim', vim_name)

def get_vnf_id(tacker_client, vnf_name, timeout=5):
    vnf_id = None
    while vnf_id is None and timeout >= 0:
        vnf_id = get_id_from_name(tacker_client, 'vnf', vnf_name)
        if vnf_id is None:
            logger.info("Could not retrieve ID for vnf with name [%s]."
                        " Retrying." % vnf_name)
            time.sleep(1)
            timeout -= 1
    return vnf_id


def list_vnfds(tacker_client, verbose=False):
    try:
        vnfds = tacker_client.list_vnfds(retrieve_all=True)
        if not verbose:
            vnfds = [vnfd['id'] for vnfd in vnfds['vnfds']]
        return vnfds
    except Exception, e:
        logger.error("Error [list_vnfds(tacker_client)]: %s" % e)
        return None


def create_vnfd(tacker_client, tosca_file=None, vnfd_name=None):
    try:
        vnfd_body = {}
        if tosca_file is not None:
            with open(tosca_file) as tosca_fd:
                vnfd_body = tosca_fd.read()
            logger.info('VNFD template:\n{0}'.format(vnfd_body))
        return tacker_client.create_vnfd(
            body={"vnfd": {"attributes": {"vnfd": vnfd_body},"name": vnfd_name}})
    except Exception, e:
        logger.error("Error [create_vnfd(tacker_client, '%s')]: %s"
                     % (tosca_file, e))
        return None


def delete_vnfd(tacker_client, vnfd_id=None, vnfd_name=None):
    try:
        vnfd = vnfd_id
        if vnfd is None:
            if vnfd_name is None:
                raise Exception('You need to provide VNFD id or VNFD name')
            vnfd = get_vnfd_id(tacker_client, vnfd_name)
        return tacker_client.delete_vnfd(vnfd)
    except Exception, e:
        logger.error("Error [delete_vnfd(tacker_client, '%s', '%s')]: %s"
                     % (vnfd_id, vnfd_name, e))
        return None


def list_vnfs(tacker_client, verbose=False):
    try:
        vnfs = tacker_client.list_vnfs(retrieve_all=True)
        if not verbose:
            vnfs = [vnf['id'] for vnf in vnfs['vnfs']]
        return vnfs
    except Exception, e:
        logger.error("Error [list_vnfs(tacker_client)]: %s" % e)
        return None


def create_vnf(tacker_client, vnf_name, vnfd_id=None,
               vnfd_name=None, param_file=None):
    try:
        vnf_body = {
            'vnf': {
                'attributes': {},
                'name': vnf_name
            }
        }
        if param_file is not None:
            params = None
            with open(param_file) as f:
                params = f.read()
            vnf_body['vnf']['attributes']['param_values'] = params
        if vnfd_id is not None:
            vnf_body['vnf']['vnfd_id'] = vnfd_id
        else:
            if vnfd_name is None:
                raise Exception('vnfd id or vnfd name is required')
            vnf_body['vnf']['vnfd_id'] = get_vnfd_id(tacker_client, vnfd_name)
        vnf_body['vnf']['vim_id'] = get_vim_id(tacker_client, 'test-vim')
        return tacker_client.create_vnf(body=vnf_body)
    except Exception, e:
        logger.error("error [create_vnf(tacker_client,"
                     " '%s', '%s', '%s')]: %s"
                     % (vnf_name, vnfd_id, vnfd_name, e))
        return None


def get_vnf(tacker_client, vnf_id=None, vnf_name=None):
    try:
        if vnf_id is None and vnf_name is None:
            raise Exception('You must specify vnf_id or vnf_name')

        _id = get_vnf_id(tacker_client, vnf_name) if vnf_id is None else vnf_id

        if _id is not None:
            all_vnfs = list_vnfs(tacker_client, verbose=True)['vnfs']
            return next((vnf for vnf in all_vnfs if vnf['id'] == _id), None)
        else:
            raise Exception('Could not retrieve ID from name [%s]' % vnf_name)

    except Exception, e:
        logger.error("Could not retrieve VNF [vnf_id=%s, vnf_name=%s] - %s"
                     % (vnf_id, vnf_name, e))
        return None


def wait_for_vnf(tacker_client, vnf_id=None, vnf_name=None, timeout=80):
    try:
        vnf = get_vnf(tacker_client, vnf_id, vnf_name)
        if vnf is None:
            raise Exception("Could not retrieve VNF - id='%s', name='%s'"
                            % vnf_id, vnf_name)
        logger.info('Waiting for vnf {0}'.format(str(vnf)))
        while vnf['status'] != 'ACTIVE' and timeout >= 0:
            if vnf['status'] == 'ERROR':
                raise Exception('Error when booting vnf %s' % vnf['id'])
            elif vnf['status'] == 'PENDING_CREATE':
                time.sleep(3)
                timeout -= 3
            vnf = get_vnf(tacker_client, vnf_id, vnf_name)

        if (timeout < 0):
            raise Exception('Timeout when booting vnf %s' % vnf['id'])

        return vnf['id']
    except Exception, e:
        logger.error("error [wait_for_vnf(tacker_client, '%s', '%s')]: %s"
                     % (vnf_id, vnf_name, e))
        return None


def delete_vnf(tacker_client, vnf_id=None, vnf_name=None):
    try:
        vnf = vnf_id
        if vnf is None:
            if vnf_name is None:
                raise Exception('You need to provide a VNF id or name')
            vnf = get_vnf_id(tacker_client, vnf_name)
        return tacker_client.delete_vnf(vnf)
    except Exception, e:
        logger.error("Error [delete_vnf(tacker_client, '%s', '%s')]: %s"
                     % (vnf_id, vnf_name, e))
        return None

def create_vim(tacker_client,vim_file=None):
    try:
        vim_body = {}
        if vim_file is not None:
            with open(vim_file) as vim_fd:
                vim_body = json.load(vim_fd)
            logger.info('VIM template:\n{0}'.format(vim_body))    
        return tacker_client.create_vim(
            body= vim_body)
    except Exception, e:
        logger.error("Error [create_vim(tacker_client, '%s')]: %s"
                     % (vim_file, e))
        return None

