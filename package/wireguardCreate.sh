#!/bin/bash

_endpoint=$1
_vpp_endpoint=$2
_private=$3
_port=$4

_EXIST=$(sshpass -p1234 ssh vppuser@$_endpoint -o StrictHostKeyChecking=no vppctl show wireguard interface)


## run create wireguard when wg interface not exist.
if [ -n "$_EXIST" ]; then
    _PRIVATE=$(sshpass -p1234 ssh vppuser@$_endpoint -o StrictHostKeyChecking=no vppctl show wireguard interface | cut -d " " -f5 | cut -d ":" -f2)
    if [ "${_private}" = "${_PRIVATE}" ]; then
        exit 100
    else
        sshpass -p1234 ssh vppuser@$_endpoint -o StrictHostKeyChecking=no vppctl wireguard delete wg0
        sshpass -p1234 ssh vppuser@$_endpoint -o StrictHostKeyChecking=no vppctl wireguard create listen-port $_port private-key $_private src $_vpp_endpoint
    fi

else
    sshpass -p1234 ssh vppuser@$_endpoint -o StrictHostKeyChecking=no vppctl wireguard create listen-port $_port private-key $_private src $_vpp_endpoint
    exit 0
fi