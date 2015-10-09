#################################################################
#								#
# Copyright 2015 Ericsson AB					#
# All Rights Reserved						#
#								#
#	Author: Manuel Buil <Manuel.Buil@ericsson.com>		#
#	Version: 0.1						#
#								#
#################################################################

import pdb

from novaclient.v2 import client as nova
from novaclient import exceptions as novaexceptions
from keystoneclient.v2_0 import client as keystone
from glanceclient import client as glance


class OpenStack_API:
    def __init__(self, authurl, tenantName, tenantUser, tenantPass):
        self.authurl=authurl
        self.tenantName=tenantName
        self.tenantUser=tenantUser
        self.tenantPass=tenantPass

    def get_token(self):
        # Establish connection to Openstack controller
        osconn = keystone.Client(username=self.tenantUser, password=self.tenantPass, tenant_name=self.tenantName, auth_url=self.authurl)
        token = osconn.auth_token
        return token

    def get_endpoint(self,service_type, endpoint_type):
        # Establish connection to Openstack controller
        osconn = keystone.Client(username=self.tenantUser, password=self.tenantPass, tenant_name=self.tenantName, auth_url=self.authurl)
        endpoint = osconn.service_catalog.url_for(service_type=service_type, endpoint_type=endpoint_type)
        return endpoint
	
    def find_image(self,SF_type):
    # Find in glance the image that matches the SF we want to deploy
        token = self.get_token()
        endpoint = self.get_endpoint('image','publicURL')
        osconn = glance.Client('1',endpoint=endpoint,token=token)
        image_list = osconn.images.list()
        for item in image_list:
            try:
                image_type = item.properties.get('image_type', None)
                image_id=None
                if (image_type == SF_type):
                    image_id = item.id
                    break
            except:
                print("Errrorr")
			
        #Search image which matches the SF type
        return image_id

    def create_vm(self, name, image, flavor, nics=None):
        # Establish connection to Openstack controller
        osconn = nova.Client(self.tenantUser, self.tenantPass, self.tenantName, self.authurl, service_type="compute")
        try:
            if nics is None:
                vm = osconn.servers.create(name,image,flavor)
            else:
                vm = osconn.servers.create(name,image,flavor,nics)
        except:
            print("Something wrong happened while creating the VM")
            vm = None
        return vm
