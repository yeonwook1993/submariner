#!/bin/bash

_endpoint=$1
_vpp_host_ip=$2
_vpp_ip=$3
_device_name=$4
_index=$5
#if tun/tap device exist, don`t create tun/tap device.
_TUN_LIST=$(sshpass -p$VPP_PASSWARD ssh $VPP_USER@$_endpoint -o StrictHostKeyChecking=no vppctl show tun | grep tun10)

#If Exist tun10, delete & new Create one.
if [ -n "$_TUN_LIST" ]; then
    sshpass -p$VPP_PASSWARD ssh $VPP_USER@$_endpoint -o StrictHostKeyChecking=no vppctl delete tap tun10
    sshpass -p$VPP_PASSWARD ssh $VPP_USER@$_endpoint -o StrictHostKeyChecking=no vppctl create tap id $_index host-if-name $_device_name host-ip4-addr $_vpp_host_ip tun
    sshpass -p$VPP_PASSWARD ssh $VPP_USER@$_endpoint -o StrictHostKeyChecking=no vppctl set interface state tun$_index up
    sshpass -p$VPP_PASSWARD ssh $VPP_USER@$_endpoint -o StrictHostKeyChecking=no vppctl set interface ip addr tun$_index $_vpp_ip
    sshpass -p$VPP_PASSWARD ssh $VPP_USER@$_endpoint -o StrictHostKeyChecking=no ifconfig $_device_name up
    exit 1
else
    sshpass -p$VPP_PASSWARD ssh $VPP_USER@$_endpoint -o StrictHostKeyChecking=no vppctl create tap id $_index host-if-name $_device_name host-ip4-addr $_vpp_host_ip tun
    sshpass -p$VPP_PASSWARD ssh $VPP_USER@$_endpoint -o StrictHostKeyChecking=no vppctl set interface state tun$_index up
    sshpass -p$VPP_PASSWARD ssh $VPP_USER@$_endpoint -o StrictHostKeyChecking=no vppctl set interface ip addr tun$_index $_vpp_ip
    sshpass -p$VPP_PASSWARD ssh $VPP_USER@$_endpoint -o StrictHostKeyChecking=no ifconfig $_device_name up
fi