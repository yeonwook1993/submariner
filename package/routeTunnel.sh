#/bin/bash

_remote_route_ip=$1
_local_vpp_endpoint=$2
_remote_vpp_endpoint=$3
_endpoint=$4
_local_host_dev=$5
_local_vpp_ip=$6

sudo ip route add $_remote_route_ip via $_local_vpp_ip dev $_local_host_dev
sshpass -p1234 ssh vppuser@$_endpoint -o StrictHostKeyChecking=no sh route-tunnel.sh $_remote_route_ip $_local_vpp_endpoint $_remote_vpp_endpoint