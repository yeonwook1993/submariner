#/bin/bash
set -e

_kind=$1
_endpoint=$2
_dst_ip=$3
_gw_ip=$4
_device_name=$5

if [ "$_device_name" == "" ]
then
    _device_name="GigabitEthernet2/0/1"
fi

if [ "$_kind" == "local" ]
then
    sshpass -p1234 ssh vppuser@$_endpoint -o StrictHostKeyChecking=no vppctl ip route add $_dst_ip via $_gw_ip $_device_name

elif [ "$_kind" == "remote" ]
then
    sshpass -p1234 ssh vppuser@$_endpoint -o StrictHostKeyChecking=no vppctl ip route add $_dst_ip via $_gw_ip $_device_name 

else
    exit 0
fi
