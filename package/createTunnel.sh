#/bin/bash

_endpoint=$1
_vpp_device_name=$2
_vpp_ip=$3
_vpp_cidr=$4

sshpass -p1234 ssh vppuser@$_endpoint -o StrictHostKeyChecking=no sh start-vpp.sh $_vpp_device_name $_vpp_ip$_vpp_cidr

if [$? -eq 141];then
    exit 0
else
fi