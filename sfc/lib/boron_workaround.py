#!/usr/bin/python
#
# This is a hack trying to fix a bug in ODL. SFC is not compatible
# to Boron security groups


def find_value(string, lines):
    for line in lines:
        if string in line:
            value = line.split(':')[1].split('-')[0]
            return value
    return None


def fix_Boron(computes):
    cmd = ("ovs-ofctl -OOpenflow13 dump-flows br-int "
           "table=11 | grep tp_dst=80")
    for compute in computes:
        output = compute.run_cmd(cmd)
        if not output:
            continue
        lines = output.split(",")
        C1 = find_value("NXM_NX_NSH_C1", lines)
        NSP = find_value("NXM_NX_NSP", lines)
        IP = find_value("NXM_NX_TUN_IPV4_DST", lines)

        cmd_flow = ('ovs-ofctl -O Openflow13 add-flow br-int "table=11,tcp,'
                    'tp_dst=80,reg0=0x1,priority=65002 actions=learn(table=40,'
                    'idle_timeout=18000,priority=61010,delete_learned,'
                    'eth_type=0x800,nw_proto=6,tp_src=80,load:0x1->'
                    'NXM_NX_REG6[0..7]),move:NXM_NX_TUN_ID[0..31]->'
                    'NXM_NX_NSH_C2[],push_nsh,load:0x1->NXM_NX_NSH_MDTYPE[],'
                    'load:0x3->NXM_NX_NSH_NP[],load:' + C1 + '->'
                    'NXM_NX_NSH_C1[],load:' + NSP + '->NXM_NX_NSP[0..23],'
                    'load:0xff->NXM_NX_NSI[],load:' + IP + '->'
                    'NXM_NX_TUN_IPV4_DST[],load:0x387->NXM_NX_TUN_ID[0..31]'
                    ',output:7"')

        compute.run_cmd(cmd_flow)
