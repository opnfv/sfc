#!/bin/bash
BASEDIR=`dirname $0`

#import VNF descriptor
tacker vnfd-create --vnfd-file ${BASEDIR}/vnfd-templates/test-vnfd1.yaml
tacker vnfd-create --vnfd-file ${BASEDIR}/vnfd-templates/test-vnfd2.yaml

#create instances of the imported VNF
tacker vnf-create --name testVNF1 --vnfd-name test-vnfd1
tacker vnf-create --name testVNF2 --vnfd-name test-vnfd2

key=true
while $key;do
        sleep 3
        active=`tacker vnf-list | grep -E 'PENDING|ERROR'`
        echo -e "checking if SFs are up:  $active"
        if [ -z "$active" ]; then
                key=false
        fi
done

#create service chain
tacker sfc-create --name red --chain testVNF1,testVNF2

#create classifier
tacker sfc-classifier-create --name red_http --chain red --match source_port=0,dest_port=80,protocol=6

tacker sfc-list
tacker sfc-classifier-list
