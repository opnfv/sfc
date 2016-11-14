#!/usr/bin/env python

__author__ = "Brady Johnson"
__copyright__ = "Copyright(c) 2015, Ericsson, Inc."
__license__ = "Apache License version 2.0"
__version__ = "0.1"
__email__ = "brady.allen.johnson@ericsson.com"
__status__ = "beta"
import pdb
import os
import time
import requests
import json
import argparse

PUT = 'PUT'
GET = 'GET'
POST = 'POST'


class Context(object):
    """
    Context class to hold the configuration as specified on the command line
    """

    def __init__(self):
        self.rest_path_prefix = 'sampleConfig'
        self.rest_path_sf = 'RestConf-SFs-HttpPut.json'
        self.rest_path_sf_sel = 'RestConf-SFselect-HttpPut.json'
        self.rest_path_sfc = 'RestConf-SFCs-HttpPut.json'
        self.rest_path_sff = 'RestConf-SFFs-HttpPut.json'
        self.rest_path_sfp = 'RestConf-SFPs-HttpPut.json'
        self.rest_path_acl = 'RestConf-ACLs-HttpPut.json'
        self.rest_path_rsp = 'RestConf-RSP-HttpPost.json'

        self.rest_url_sf = 'config/service-function:service-functions/'
        self.rest_url_sf_sel = ('config/service-function-scheduler-type:'
                                'service-function-scheduler-types/')
        self.rest_url_sfc = (
            'config/service-function-chain:service-function-chains/')
        self.rest_url_sff = (
            'config/service-function-forwarder:service-function-forwarders/')
        self.rest_url_sfp = (
            'config/service-function-path:service-function-paths/')
        self.rest_url_rsp = (
            'operational/rendered-service-path:rendered-service-paths/')
        self.rest_url_rsp_rpc = (
            'operations/rendered-service-path:create-rendered-path')
        self.rest_url_acl = ('config/ietf-acl:access-lists/')

        self.http_headers = {
            'Content-Type': 'application/json', 'Cache-Control': 'no-cache'}
        self.http_server = 'localhost'
        self.url_base = ''
        self.http_port = '8181'
        self.interractive = True
        self.user = 'admin'
        self.pw = 'admin'
        self.batch_sf = False
        self.batch_sf_sel = False
        self.batch_sfc = False
        self.batch_sff = False
        self.batch_sfp = False
        self.batch_acl = False
        self.batch_rsp = False
        self.batch_query = False

    def set_path_prefix_paths(self, path_prefix):
        self.rest_path_prefix = path_prefix
        self.rest_path_sf = os.path.join(
            self.rest_path_prefix, self.rest_path_sf)
        self.rest_path_sf_sel = os.path.join(
            self.rest_path_prefix, self.rest_path_sf_sel)
        self.rest_path_sfc = os.path.join(
            self.rest_path_prefix, self.rest_path_sfc)
        self.rest_path_sff = os.path.join(
            self.rest_path_prefix, self.rest_path_sff)
        self.rest_path_sfp = os.path.join(
            self.rest_path_prefix, self.rest_path_sfp)
        self.rest_path_acl = os.path.join(
            self.rest_path_prefix, self.rest_path_acl)
        self.rest_path_rsp = os.path.join(
            self.rest_path_prefix, self.rest_path_rsp)


def get_cmd_line(context):
    """
    Create a command-line parser, parse the command line args, and process
    them.
    Populate the Context object with the processed command-line args.
    """

    opts = argparse.ArgumentParser()

    # Batch or Interractive mode
    opts.add_argument('--interractive', '-i',
                      dest='interractive',
                      action='store_true',
                      help='Interractive mode, default')
    opts.add_argument('--batch', '-b',
                      dest='batch',
                      action='store_true',
                      help='Batch mode, overrides interractive mode')

    # Where to send the messages
    opts.add_argument('--http-server', '-s',
                      default=context.http_server,
                      dest='http_server',
                      help='HTTP server address')
    opts.add_argument('--http-port',
                      default=context.http_port,
                      dest='http_port',
                      help='HTTP server port')

    # Batch mode, which message(s) to send
    opts.add_argument('--send-sf', '-1',
                      dest='send_sf',
                      action='store_true',
                      help='Send an SF REST JSON PUT message')
    opts.add_argument('--send-sf-sel',
                      dest='send_sf_sel',
                      action='store_true',
                      help='Send an SF Selection REST JSON PUT message')
    opts.add_argument('--send-sfc', '-2',
                      dest='send_sfc',
                      action='store_true',
                      help='Send an SFC REST JSON PUT message')
    opts.add_argument('--send-sff', '-3',
                      dest='send_sff',
                      action='store_true',
                      help='Send an SFF REST JSON PUT message')
    opts.add_argument('--send-sfp', '-4',
                      dest='send_sfp',
                      action='store_true',
                      help='Send an SFP REST JSON PUT message')
    opts.add_argument('--send-acl', '-5',
                      dest='send_acl',
                      action='store_true',
                      help='Send an ACL REST JSON PUT message')
    opts.add_argument('--send-rsp', '-6',
                      dest='send_rsp',
                      action='store_true',
                      help='Send an RSP REST JSON POST RPC message')
    opts.add_argument('--send-all', '-7',
                      dest='send_all',
                      action='store_true',
                      help=('Send all (SF, SFF, SFC, SFP, RSP, ACL) '
                            'REST JSON messages'))
    opts.add_argument('--query-sfc', '-q',
                      dest='query_sfc',
                      action='store_true',
                      help='Query all SFC objects')

    # Paths to the rest JSON files
    opts.add_argument('--rest-path-prefix', '-prefix',
                      default=context.rest_path_prefix,
                      dest='rest_path_prefix',
                      help='Path prefix where the REST JSON files are located')
    opts.add_argument('--rest-path-sf-sel',
                      default=context.rest_path_sf_sel,
                      dest='rest_path_sf_sel',
                      help=('Name of the SF Selection REST JSON file, '
                            'relative to configured prefix'))
    opts.add_argument('--rest-path-sf', '-n',
                      default=context.rest_path_sf,
                      dest='rest_path_sf',
                      help=('Name of the SF REST JSON file, relative to '
                            'configured prefix'))
    opts.add_argument('--rest-path-sfc', '-c',
                      default=context.rest_path_sfc,
                      dest='rest_path_sfc',
                      help=('Name of the SFC REST JSON file, relative to '
                            'configured prefix'))
    opts.add_argument('--rest-path-sff', '-f',
                      default=context.rest_path_sff,
                      dest='rest_path_sff',
                      help=('Name of the SFF REST JSON file, relative '
                            'to configured  prefix'))
    opts.add_argument('--rest-path-sfp', '-p',
                      default=context.rest_path_sfp,
                      dest='rest_path_sfp',
                      help=('Name of the SFP REST JSON file, relative '
                            'to configured prefix'))
    opts.add_argument('--rest-path-rsp', '-r',
                      default=context.rest_path_rsp,
                      dest='rest_path_rsp',
                      help=('Name of the RSP REST JSON file, relative '
                            'to configured prefix'))
    opts.add_argument('--rest-path-acl', '-a',
                      default=context.rest_path_acl,
                      dest='rest_path_acl',
                      help=('Name of the ACL REST JSON file, relative '
                            'to configured prefix'))

    args = opts.parse_args()

    context.http_server = args.http_server
    context.http_port = args.http_port
    context.url_base = 'http://%s:%s/restconf/' % (
        context.http_server, context.http_port)

    context.rest_path_prefix = args.rest_path_prefix
    context.rest_path_sf = args.rest_path_sf
    context.rest_path_sf_sel = args.rest_path_sf_sel
    context.rest_path_sfc = args.rest_path_sfc
    context.rest_path_sff = args.rest_path_sff
    context.rest_path_sfp = args.rest_path_sfp
    context.rest_path_acl = args.rest_path_acl
    context.rest_path_rsp = args.rest_path_rsp
    context.set_path_prefix_paths(context.rest_path_prefix)

    for path in [context.rest_path_sf,
                 context.rest_path_sfc,
                 context.rest_path_sff,
                 context.rest_path_sfp]:
        print '\tUsing REST file: %s' % path

    if args.batch:
        context.interractive = False
        if args.send_all:
            context.batch_sf = True
            context.batch_sf_sel = True
            context.batch_sfc = True
            context.batch_sff = True
            context.batch_sfp = True
            context.batch_rsp = True
            # TODO deactivated for now
            # context.batch_acl      =  True
        else:
            context.batch_sf = args.send_sf
            context.batch_sf_sel = args.send_sf_sel
            context.batch_sfc = args.send_sfc
            context.batch_sff = args.send_sff
            context.batch_sfp = args.send_sfp
            context.batch_rsp = args.send_rsp
            # TODO deactivated for now
            # context.batch_acl      =  args.send_acl
            context.batch_query = args.query_sfc

    return True


def send_rest(context, operation, rest_url, rest_file=None):
    """
    Send an HTTP REST message
    Keyword arguments:
    context -- specifies the destination IP/Port and user/pw
    operation -- specifies if the HTTP OP is one of: GET, PUT, or POST
    rest_url -- the operation URL
    rest_file -- for PUT and POST operations, specifies where the JSON
    input is found
    """

    complete_url = '%s%s' % (context.url_base, rest_url)

    if rest_file:
        if not os.path.exists(rest_file):
            print 'REST file [%s] does not exists' % rest_file
            return False

    try:
        if operation == GET:
            r = requests.get(url=complete_url,
                             headers=context.http_headers,
                             auth=(context.user, context.pw))

            print '\nHTTP GET %s\nresult: %s' % (rest_url, r.status_code)
            # if len(r.text) > 1:
            if r.status_code >= 200 and r.status_code <= 299:
                print json.dumps(json.loads(r.text),
                                 indent=4,
                                 separators=(',', ': '))

        elif operation == PUT:
            if not rest_file:
                print 'ERROR trying to PUT with empty REST file'
                return False

            r = requests.put(url=complete_url,
                             auth=(context.user, context.pw),
                             data=json.dumps(json.load(open(rest_file, 'r'))),
                             headers=context.http_headers)
            print '\nHTTP PUT %s\nresult: %s' % (rest_url, r.status_code)

        elif operation == POST:
            if not rest_file:
                print 'ERROR trying to POST with empty REST file'
                return False

            post_list = json.load(open(rest_file, 'r'))
            if len(post_list) > 1:
                # This allows for multiple RSPs to be sent from one JSON file
                for entry in post_list:
                    r = requests.post(url=complete_url,
                                      auth=(context.user, context.pw),
                                      data=json.dumps(entry),
                                      headers=context.http_headers)
                    print '\nHTTP POST %s\nresult: %s' % (rest_url,
                                                          r.status_code)
            else:
                r = requests.post(url=complete_url,
                                  auth=(context.user, context.pw),
                                  data=json.dumps(post_list),
                                  headers=context.http_headers)
                print '\nHTTP POST %s\nresult: %s' % (rest_url,
                                                      r.status_code)
        else:
            print 'ERROR: Invalid Operation: %s' % (operation)

    except requests.exceptions.ConnectionError as ce:
        print 'ERROR connecting: %s' % (ce)
        return False
    except Exception as e:
        print 'ERROR Exception: %s' % (e)
        return False
    except:
        print 'ERROR unkown exception raised'
        return False

    return True


def validate_rest(context):
    """
    For each JSON input file in context, validate the JSON syntax.
    No validation checking is made on parameter names or types.
    """

    print ''
    for path in [context.rest_path_sf,
                 context.rest_path_sfc,
                 context.rest_path_sff,
                 context.rest_path_sfp,
                 context.rest_path_rsp,
                 context.rest_path_sf_sel]:
        if os.path.exists(path):
            print 'Validating JSON file: %s' % path
            try:
                json.load(open(path, 'r'))
            except ValueError as ve:
                print '\tValidation error [%s]' % ve
                return False

    return True


def batch(context):
    """
    Launch the application in batch mode and perform
    the operations as specified in the Context object.
    """

    # The order of these if's is important
    # If send-all was set, then each of these needs to be sent, in order
    if context.batch_sf_sel:
        send_rest(
            context, PUT, context.rest_url_sf_sel, context.rest_path_sf_sel)
    if context.batch_sf:
        send_rest(context, PUT, context.rest_url_sf, context.rest_path_sf)
    if context.batch_sff:
        send_rest(context, PUT, context.rest_url_sff, context.rest_path_sff)
    if context.batch_sfc:
        send_rest(context, PUT, context.rest_url_sfc, context.rest_path_sfc)
    if context.batch_sfp:
        send_rest(context, PUT, context.rest_url_sfp, context.rest_path_sfp)
    if context.batch_rsp:
        send_rest(
            context, POST, context.rest_url_rsp_rpc, context.rest_path_rsp)
    if context.batch_acl:
        send_rest(context, PUT, context.rest_url_acl, context.rest_path_acl)

    if context.batch_query:
        send_rest(context, GET, context.rest_url_sf_sel)
        send_rest(context, GET, context.rest_url_sf)
        send_rest(context, GET, context.rest_url_sff)
        send_rest(context, GET, context.rest_url_sfc)
        send_rest(context, GET, context.rest_url_sfp)
        send_rest(context, GET, context.rest_url_rsp)
        # TODO deactivated for now
        # send_rest(context, GET, context.rest_url_acl)


def CLI(context):
    """
    Run a simple Command Line Interface.
    The Context object is used for sending rest messages
    """

    option = '1'
    while option != '0':
        print '\n\nChoose Option to perform:'
        print ' 0) Quit'
        print ' 1) Send SF  REST'
        print ' 2) Send SFC REST'
        print ' 3) Send SFF REST'
        print ' 4) Send SFP REST'
        print ' 5) Send RSP REST'
        print ' 6) Send ACL REST'
        print ' 7) Send all ordered: (SFsel, SF, SFF, SFC, SFP, RSP)'
        print ' 8) Query all: (SFsel, SF, SFF, SFC, SFP, RSP)'
        print(' 9) Change config file path, currently [%s]' % (
            context.rest_path_prefix))
        print '10) Validate config files JSON syntax'

        option = raw_input('=> ')

        if option == '1':
            send_rest(context, PUT, context.rest_url_sf, context.rest_path_sf)
        elif option == '2':
            send_rest(
                context, PUT, context.rest_url_sfc, context.rest_path_sfc)
        elif option == '3':
            send_rest(
                context, PUT, context.rest_url_sff, context.rest_path_sff)
        elif option == '4':
            send_rest(
                context, PUT, context.rest_url_sfp, context.rest_path_sfp)
        elif option == '5':
            send_rest(
                context, POST, context.rest_url_rsp_rpc, context.rest_path_rsp)
        elif option == '6':
            send_rest(
                context, PUT, context.rest_url_acl, context.rest_path_acl)
        elif option == '7':
            pdb.set_trace()
            send_rest(
                context, PUT, context.rest_url_sf_sel,
                context.rest_path_sf_sel)
            send_rest(context, PUT, context.rest_url_sf, context.rest_path_sf)
            send_rest(
                context, PUT, context.rest_url_sff, context.rest_path_sff)
            send_rest(
                context, PUT, context.rest_url_sfc, context.rest_path_sfc)
            send_rest(
                context, PUT, context.rest_url_sfp, context.rest_path_sfp)
            time.sleep(1)
            send_rest(
                context, POST, context.rest_url_rsp_rpc, context.rest_path_rsp)
            # TODO ACL deactivated for now
            # Need to wait until the SFC creates the RSP internally
            # before sending the ACL
            # print 'Sleeping 2 seconds while RSP being created'
            # time.sleep(2);
            # send_rest(context, PUT, context.rest_url_acl,
            # context.rest_path_acl)
        elif option == '8':
            send_rest(context, GET, context.rest_url_sf_sel)
            send_rest(context, GET, context.rest_url_sf)
            send_rest(context, GET, context.rest_url_sff)
            send_rest(context, GET, context.rest_url_sfc)
            send_rest(context, GET, context.rest_url_sfp)
            send_rest(context, GET, context.rest_url_rsp)
            send_rest(context, GET, context.rest_url_acl)
        elif option == '9':
            path_prefix = raw_input('Enter path => ')
            if not os.path.exists(path_prefix):
                print 'ERROR: path does not exist: [%s]' % (path_prefix)
            else:
                context.set_path_prefix_paths(path_prefix)
        elif option == '10':
            validate_rest(context)
        elif option != '0':
            print 'ERROR: Invalid option %s' % (option)


def main():
    """
    Main entry point into the VnfMgrSim application.
    Command line arguments are expected.
    Example invocations:
    To display application command-line help:
        vnfmgr_odl.py --help
    To start the application in interractive mode:
        vnfmgr_odl.py -prefix <input json dir>
    To start the application in batch mode and send an SF JSON REST message:
        vnfmgr_odl.py -b -prefix <input json dir> --send-sf
    """

    context = Context()
    if not get_cmd_line(context):
        return 1

    if context.interractive:
        CLI(context)
    else:
        batch(context)

    return 0

if __name__ == '__main__':
    main()
