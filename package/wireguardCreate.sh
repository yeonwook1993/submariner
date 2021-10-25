#!/bin/bash

_endpoint=$1
_vpp_endpoint=$2
_private=$3
_port=$4
_wg_ip=$5

_EXIST=$(sshpass -p$VPP_PASSWARD ssh $VPP_USER@$_endpoint -o StrictHostKeyChecking=no vppctl show wireguard interface)


## Running Create Wireguard Interface when Wireguard Interface not exist.
if [ -n "$_EXIST" ]; then
    _PRIVATE=$(sshpass -p$VPP_PASSWARD ssh $VPP_USER@$_endpoint -o StrictHostKeyChecking=no vppctl show wireguard interface | cut -d " " -f5 | cut -d ":" -f2)
    if [ "${_private}" = "${_PRIVATE}" ]; then
        exit 1
    else
## If Wireguard Interface`s private key isn`t correct, delete that, and create new one.
        sshpass -p$VPP_PASSWARD ssh $VPP_USER@$_endpoint -o StrictHostKeyChecking=no vppctl wireguard delete wg0
        sshpass -p$VPP_PASSWARD ssh $VPP_USER@$_endpoint -o StrictHostKeyChecking=no vppctl wireguard create listen-port $_port private-key $_private src $_vpp_endpoint
        sshpass -p$VPP_PASSWARD ssh $VPP_USER@$_endpoint -o StrictHostKeyChecking=no vppctl set interface state wg0 up
        sshpass -p$VPP_PASSWARD ssh $VPP_USER@$_endpoint -o StrictHostKeyChecking=no vppctl set interface ip addr wg0 $_wg_ip
        exit 0
    fi
## Create Wireguard Interface.
else
    sshpass -p$VPP_PASSWARD ssh $VPP_USER@$_endpoint -o StrictHostKeyChecking=no vppctl wireguard create listen-port $_port private-key $_private src $_vpp_endpoint
    sshpass -p$VPP_PASSWARD ssh $VPP_USER@$_endpoint -o StrictHostKeyChecking=no vppctl set interface state wg0 up
    sshpass -p$VPP_PASSWARD ssh $VPP_USER@$_endpoint -o StrictHostKeyChecking=no vppctl set interface ip addr wg0 $_wg_ip
    exit 0
fi