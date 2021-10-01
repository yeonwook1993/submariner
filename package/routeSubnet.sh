#!/bin/bash

_endpoint=$1
_dst_ip=$2
_gw_ip=$3
_device_name=$4


sshpass -p$VPP_PASSWARD ssh $VPP_USER@$_endpoint -o StrictHostKeyChecking=no vppctl ip route add $_dst_ip via $_gw_ip $_device_name