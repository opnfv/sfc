## Preface
 This is the initial, proof-of-concept version of SFC installation on OPNFV cluster. It works, however one may feel that the setup procedure is a little bit inconvenient.
Installing SFC on an OPNFV cluster is about
* Installing the required features into the *OPNFV* shipped stock *OpenDaylight*
* Orchestrating the bundled *OpenStack* for SFC use
* Installing VnfMGR
## SFC installation/deployment architecture
 The SFC installation/deployment happens on the *Fuel Master (vm)* by means of the ansible configuration management system. The shipped playbook(s) will analyze the deployment properties and will perfom the orchestration tasks given in the shipped playbooks, resulting in a functional system.
## Prerequisites
 Assuming You have a successfully deployed an Arno SR-1 OPNFV cluster with the Fuel OpenDayLight plugin. Deploying one is out of the scope this guide, but for starting point consult http://artifacts.opnfv.org/arno.2015.2.0/fuel/install-guide.arno.2015.2.0.pdf.
## Workaraund for the current status
1. To install the ansible configuration management system on your *Fuel Master* node, issue the following command sequence on Fuel Master:
```
cat >> /etc/yum.repos.d/auxiliary.repo  <<EOF

[extras]
name=CentOS-$releasever - Extras
mirrorlist=http://mirrorlist.centos.org/?release=$releasever&arch=$basearch&repo=extras
protect=0
EOF

yum repolist

yum install epel-release

yum install ansible

yum install git
```
2. Clone the *deploy* directory into the Fuel Master:
```
mkdir -p ${HOME}/.ssh
cat >> ${HOME}/.ssh/config <<EOF
Host gerrit.opnfv.org
    Hostname gerrit.opnfv.org
    User *your linuxfoundation id*
    IdentityFile *path/to/your/linux/foundation/rsa/key*
EOF
mkdir -p ${HOME}/sfc && cd ${HOME}/sfc
git init
git remote add -f origin  ssh://gerrit.opnfv.org:29418/sfc
git config core.sparseCheckout true
echo "deploy" >> .git/info/sparse-checkout
git pull origin master
```
## Install SFC onto Your OPNFV cluster
```
cd ${HOME}/sfc/deploy
ansible-playbook site.yml
```