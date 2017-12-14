# Remember to source the env variables $creds before
FILE=$(readlink -f $0)
FILE_PATH=$(dirname $FILE)
cd $FILE_PATH
python ../../../lib/cleanup.py $1 $2
nova delete client
nova delete server
for line in $(neutron floatingip-list | cut -d" " -f2);do neutron floatingip-delete $line;done
