hostname=$1
vppname=$2
vppIP=$3
gatewayIP=$4
endpointIP=$5

ip link add name $vppname type veth peer name $hostname
ip link set dev $vppname up
ip link set dev $hostname up
sshpass -p1234 ssh vppuser@$endpointIP sh start-vpp.sh $hostname $vppIP $gatewayIP
