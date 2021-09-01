#!/bin/bash

_endpoint=$1
_vpp_endpoint=$2
_private=$3
_port=$4

sshpass -p1234 ssh vppuser@$_endpoint -o StrictHostKeyChecking=no vppctl wireguard create listen-port $_port private-key $_private src $_vpp_endpoint
