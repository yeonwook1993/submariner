remoteRouteIP=$1
localVppEndpointIP=$2
localVppIP=$3
localHostIP=$4
remoteVppEndpointIP=$5
remoteVppIP=$6
remoteHostIP=$7
endpoint_ip=$8


ip route add $remoteRouteIP via $localVppIP
sshpass -p1234 ssh vppuser@$endpoint_ip -o StrictHostKeyChecking=no sh route-vpp.sh $remoteRouteIP $localVppEndpointIP $localVppIP $localHostIP $remoteVppEndpointIP $remoteVppIP $remoteHostIP