#!/bin/bash

_endpoint=$1
_public=$2
_remote_vpp_endpoint=$3
_port=$4
_persistent_keepalive=$5


sshpass -p1234 ssh vppuser@$_endpoint -o StrictHostKeyChecking=no vppctl wireguard peer add wg0 public-key $_public endpoint $_remote_vpp_endpoint allowed-ip 0.0.0.0/0 port $_port persistent-keepalive $_persistent_keepalive
sshpass -p1234 ssh vppuser@$_endpoint -o StrictHostKeyChecking=no vppctl set interface state wg0 up
exit 0