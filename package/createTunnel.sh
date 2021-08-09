hostIntName=$1
vppIntName=$2
hostIntCidr=$3
vppIntCidr=$4
endpointIP=$5

sudo ip link add name $hostIntName type veth peer name $vppIntName
sudo ip link set dev $hostIntName up
sudo ip link set dev $vppIntName up
sudo ip addr add $hostIntCidr dev $hostIntName
sshpass -p1234 ssh vppuser@$endpointIP -o StrictHostKeyChecking=no sh start-vpp.sh $vppIntName $vppIntCidr