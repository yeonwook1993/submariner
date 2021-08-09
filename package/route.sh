remote_route_cidr=$1

vpp_ip=$2
host_ip=$3

retmote_vpp_ip=$4
remote_host_ip=$5

local_vtep_ip=$6
remote_vtep_ip=$7

endpoint_ip=$8

ip route add $remote_route_cidr via $vpp_ip
sshpass -p1234 ssh vppuser@$endpoint_ip -o StrictHostKeyChecking=no sh route-vpp.sh $remote_route_cidr $vpp_ip $host_ip $remote_vpp_ip $remote_host_ip $local_vtep_ip $remote_vtep_ip