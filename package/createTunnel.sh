hostname=$1
vppname=$2
vppIP=$3
gatewayIP=$4


ip link add name $vppname type veth peer name $hostname
ip link set dev $vppname up
ip link set dev $hostname up
sshpass -p1234 ssh vppuser@$endpointIP start-vpp.sh $hostname $vppIP $gatewayIP