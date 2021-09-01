#!/bin/bash

_endpoint=$1
_vpp_host_ip=$2
_vpp_ip=$3
_vpp_wg_ip=$4
_device_name=$5


sshpass -p1234 ssh vppuser@$_endpoint -o StrictHostKeyChecking=no vppctl set interface state wg0 up
sshpass -p1234 ssh vppuser@$_endpoint -o StrictHostKeyChecking=no vppctl set interface ip addr wg0 $_vpp_wg_ip
sshpass -p1234 ssh vppuser@$_endpoint -o StrictHostKeyChecking=no vppctl create tap host-if-name $_device_name host-ip4-addr $_vpp_host_ip tun
sshpass -p1234 ssh vppuser@$_endpoint -o StrictHostKeyChecking=no vppctl set interface state tun0 up
sshpass -p1234 ssh vppuser@$_endpoint -o StrictHostKeyChecking=no vppctl set interface ip addr tun0 $_vpp_ip
sshpass -p1234 ssh vppuser@$_endpoint -o StrictHostKeyChecking=no ifconfig $_device_name up
