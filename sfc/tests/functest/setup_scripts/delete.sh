# Remember to source the env variables $creds before
FILE=$(readlink -f $0)
FILE_PATH=$(dirname $FILE)
cd $FILE_PATH
python ../../../lib/cleanup.py $1 $2
openstack server delete client
openstack server delete server
for line in $(openstack floating ip list);do openstack floating ip delete $line;done
