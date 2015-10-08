## Preface
This is the initial, proof-of-concept version of SFC installation on OPNFV. However it works one may feel a little uncovinient it's setup procedure.
Installing SFC on OPNFV is about
* Installing the required features into the *OPNFV* shipped stock *OpenDaylight*
* Orchestrating *OpenStack* for SFC/vnf use
* Installing VnfMGR
## SFC installation/deployment architecture
The SFC installation/deployment happens on *Fuel Master (vm)* by means of ansible configuration management system. The shipped playbook(s) will analyze the deployment properties and will perfom the orchestration tasks given in the shipped playbooks, resulting a right to use system.
## Workaraund for the current status
1. Install the ansible configuration management system into your fuel node, issue command sequence on fuel master:
```
cat >> /etc/yum.repos.d/auxiliary.repo  <<EOF
[extras]
name=CentOS-$releasever - Extras
mirrorlist=http://mirrorlist.centos.org/?release=$releasever&arch=$basearch&repo=extras
gpgcheck=0
protect=0
EOF

yum repolist

yum install epel-release

yum install ansible

yum install git
```
2. Clone the *deploy* directory into the fuel master:
```
mkdir sfc-deploy
cd sfc-deploy
git init
git remote add -f origin  ssh://gerrit.opnfv.org:29418/sfc
git config core.sparseCheckout true
echo "deploy" >> .git/info/sparse-checkout
git pull origin master
```
3. Install SFC onto Your OPNFV cluster
```
cd sfc-deploy
ansible-playbook site.yml
```