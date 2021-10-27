_endpoint=$1
_vpp_endpoint=$2
_vpp_remote_endpoint=$3
_local_spi=$4
_remote_spi=$5
_local_key=$6
_remote_key=$7

sshpass -p$VPP_PASSWARD ssh $VPP_USER@$_endpoint -o StrictHostKeyChecking=no vppctl ipsec sa add 10 spi $_local_spi esp crypto-key $_local_key crypto-alg aes-cbc-128 integ-key $_local_key integ-alg sha1-96 tunnel-src $_vpp_endpoint tunnel-dst $_vpp_remote_endpoint
sshpass -p$VPP_PASSWARD ssh $VPP_USER@$_endpoint -o StrictHostKeyChecking=no vppctl ipsec sa add 20 spi $_remote_spi esp crypto-key $_remote_key crypto-alg aes-cbc-128 integ-key $_remote_key integ-alg sha1-96 tunnel-src $_vpp_remote_endpoint tunnel-dst $_vpp_endpoint

sshpass -p$VPP_PASSWARD ssh $VPP_USER@$_endpoint -o StrictHostKeyChecking=no vppctl ipsec spd add 1
sshpass -p$VPP_PASSWARD ssh $VPP_USER@$_endpoint -o StrictHostKeyChecking=no vppctl set interface ipsec spd GigabitEthernet2/0/1 1

sshpass -p$VPP_PASSWARD ssh $VPP_USER@$_endpoint -o StrictHostKeyChecking=no vppctl ipsec policy add spd 1 priority 100 inbound action bypass protocol 50
sshpass -p$VPP_PASSWARD ssh $VPP_USER@$_endpoint -o StrictHostKeyChecking=no vppctl ipsec policy add spd 1 priority 100 outbound action bypass protocol 50

sshpass -p$VPP_PASSWARD ssh $VPP_USER@$_endpoint -o StrictHostKeyChecking=no vppctl ipsec policy add spd 1 outbound  priority 10 action protect sa 10 local-ip-range 0.0.0.0 - 255.255.255.255 remote-ip-range 0.0.0.0 - 255.255.255.255
sshpass -p$VPP_PASSWARD ssh $VPP_USER@$_endpoint -o StrictHostKeyChecking=no vppctl ipsec policy add spd 1 inbound priority 10 action protect sa 20 local-ip-range 0.0.0.0 - 255.255.255.255 remote-ip-range 0.0.0.0 - 255.255.255.255
