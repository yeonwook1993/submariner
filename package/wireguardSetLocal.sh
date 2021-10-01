#!/bin/bash

_endpoint=$1
_vpp_host_ip=$2
_vpp_ip=$3
_vpp_wg_ip=$4
_device_name=$5
_index=$6

# set wg0 interface ip address & state up
sshpass -p$VPP_PASSWARD ssh $VPP_USER@$_endpoint -o StrictHostKeyChecking=no vppctl set interface state wg0 up
sshpass -p$VPP_PASSWARD ssh $VPP_USER@$_endpoint -o StrictHostKeyChecking=no vppctl set interface ip addr wg0 $_vpp_wg_ip


#if tun/tap device exist, don`t create tun/tap device
_TUN_LIST=$(sshpass -p$VPP_PASSWARD ssh $VPP_USER@$_endpoint -o StrictHostKeyChecking=no vppctl show tun | grep "ifindex ${_index}")

if [ -n "$_TUN_LIST" ]; then
    exit 1
else
    sshpass -p$VPP_PASSWARD ssh $VPP_USER@$_endpoint -o StrictHostKeyChecking=no vppctl create tap id $_index host-if-name $_device_name host-ip4-addr $_vpp_host_ip tun
    sshpass -p$VPP_PASSWARD ssh $VPP_USER@$_endpoint -o StrictHostKeyChecking=no vppctl set interface state tun$_index up
    sshpass -p$VPP_PASSWARD ssh $VPP_USER@$_endpoint -o StrictHostKeyChecking=no vppctl set interface ip addr tun$_index $_vpp_ip
    sshpass -p$VPP_PASSWARD ssh $VPP_USER@$_endpoint -o StrictHostKeyChecking=no ifconfig $_device_name up
fi