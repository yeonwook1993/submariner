#!/bin/bash

_endpoint=$1
_public=$2
_remote_vpp_endpoint=$3
_port=$4
_persistent_keepalive=$5
_allowed_ip=$6

_EXIST=$(sshpass -p$VPP_PASSWARD ssh $VPP_USER@$_endpoint -o StrictHostKeyChecking=no vppctl show wireguard peer | grep $_remote_vpp_endpoint)

if [ -n "$_EXIST" ]; then
    _INDEX=$(sshpass -p$VPP_PASSWARD ssh $VPP_USER@$_endpoint -o StrictHostKeyChecking=no vppctl show wireguard peer | grep $_remote_vpp_endpoint | cut -c 2)
    for index in $_INDEX; do
        sshpass -p$VPP_PASSWARD ssh $VPP_USER@$_endpoint -o StrictHostKeyChecking=no vppctl wireguard peer remove ${index}
    done 
fi

sshpass -p$VPP_PASSWARD ssh $VPP_USER@$_endpoint -o StrictHostKeyChecking=no vppctl wireguard peer add wg0 public-key $_public endpoint $_remote_vpp_endpoint port $_port persistent-keepalive $_persistent_keepalive $_allowed_ip
sshpass -p$VPP_PASSWARD ssh $VPP_USER@$_endpoint -o StrictHostKeyChecking=no vppctl set interface state wg0 up