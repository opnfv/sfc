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
from vnfmgr_os.vnfmgr_os import OpenStack_API
import vnfmgr_odl.vnfmgr_odl as odlscript
import time
import json

if __name__ == "__main__":
    #OpenStack environment information	
    authurl = "http://localhost:5000/v2.0"
    adminTenantName = 'admin'
    adminTenantUser = 'admin'
    adminTenantPass = 'abc123'
    tenantName = adminTenantName
    tenantUser = adminTenantUser
    tenantPass = adminTenantPass

    openstack = OpenStack_API(authurl, tenantName, tenantUser, tenantPass)

    # 1 - Get the SF type
    # Provide the file with the SFC configuration
    file_json = "vnfmgr_odl/sample_config/RestConf-SFCs-HttpPut.json"
    # Read the config files which refer to SF
    json_data=open(file_json).read()
    data = json.loads(json_data)
    pdb.set_trace()

    # Grab the SF type
    chains = data['service-function-chains']['service-function-chain']
    for chain in chains:
        SFs = chain['sfc-service-function']
        for SF in SFs:
            sf_type = SF['type']
            name = SF['name']
            #2 - Search the image in glance with that SF type
            image = openstack.find_image(sf_type)
            if image == None:
                print("There is no image with that sf_name")
                exit(1)
                # 3 - Boot the VM without network
                flavor = 1
                print("About to deploy")
                vm = openstack.create_vm(name,image,flavor)
                if vm == None:
                    print("Problems to deploy the VM")
                    exit(1)
	
	#Make the call to ODL to deploy SFC
    context = odlscript.Context()
    context.set_path_prefix_paths("vnfmgr_odl/sample_config")
    pdb.set_trace()
    odlscript.send_rest(context, "PUT", context.rest_url_sf_sel,  context.rest_path_sf_sel)
    odlscript.send_rest(context, "PUT", context.rest_url_sf,  context.rest_path_sf)
    odlscript.send_rest(context, "PUT", context.rest_url_sff, context.rest_path_sff)
    odlscript.send_rest(context, "PUT", context.rest_url_sfc, context.rest_path_sfc)
    odlscript.send_rest(context, "PUT", context.rest_url_sfp, context.rest_path_sfp)
    time.sleep(1);
    odlscript.send_rest(context, "POST", context.rest_url_rsp_rpc, context.rest_path_rsp)


	#TO DO
	# Check if the SF_VM already exists before creating it
	# Network of the VM
