/*
SPDX-License-Identifier: Apache-2.0

Copyright Contributors to the Submariner project.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package vpp

import (
	"crypto/sha256"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/kelseyhightower/envconfig"
	"github.com/pkg/errors"
	"github.com/submariner-io/admiral/pkg/log"
	v1 "github.com/submariner-io/submariner/pkg/apis/submariner.io/v1"
	"github.com/submariner-io/submariner/pkg/cable"
	"github.com/submariner-io/submariner/pkg/natdiscovery"
	"github.com/submariner-io/submariner/pkg/types"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"k8s.io/klog"
)

const (
	// DefaultDeviceName specifies name of Vpp network device
	PublicKey          = "publicKey"
	DefaultDeviceName  = "vpp-submariner"
	CableDriverName    = "vpp_wireguard"
	VPPWireguardPrefix = "240"
	TableID            = 150
	specEnvPrefix      = "ce_ipsec"
	KeepAliveInterval  = "25"
	VPPTunIndex        = "10"
)

func init() {
	cable.AddDriver(CableDriverName, NewDriver)
}

type specification struct {
	PSK      string `default:"default psk"`
	NATTPort int    `default:"4500"`
	VPPCidr  string `default:"24"`
}

type vpp struct {
	localEndpoint types.SubmarinerEndpoint
	localCluster  types.SubmarinerCluster
	connections   []v1.Connection
	mutex         sync.Mutex
	spec          *specification
	psk           *wgtypes.Key
}

// NewDriver creates a new VPP driver
func NewDriver(localEndpoint types.SubmarinerEndpoint, localCluster types.SubmarinerCluster) (cable.Driver, error) {
	var err error
	v := vpp{
		localEndpoint: localEndpoint,
		localCluster:  localCluster,
		spec:          new(specification),
	}
	if err := envconfig.Process(specEnvPrefix, v.spec); err != nil {
		return nil, fmt.Errorf("error processing environment config for wireguard: %v", err)
	}

	//gen public and pirvate key && set public key in BackendConfig
	var priv, pub, psk wgtypes.Key

	if psk, err = genPsk(v.spec.PSK); err != nil {
		return nil, fmt.Errorf("error generating pre-shared key: %v", err)
	}

	v.psk = &psk

	if priv, err = wgtypes.GeneratePrivateKey(); err != nil {
		return nil, fmt.Errorf("error generating private key: %v", err)
	}

	pub = priv.PublicKey()

	//set VPP env in BackendConfig for Connect each cluster.

	v.localEndpoint.Spec.BackendConfig[PublicKey] = pub.String()
	v.localEndpoint.Spec.BackendConfig["VppEndpointIP"] = localEndpoint.Spec.VppEndpointIP
	v.localEndpoint.Spec.BackendConfig["VppHostIP"] = localEndpoint.Spec.VppHostIP
	v.localEndpoint.Spec.BackendConfig["VppIP"] = localEndpoint.Spec.VppIP

	if localEndpoint.Spec.VppCidr != "" {
		v.spec.VPPCidr = localEndpoint.Spec.VppCidr
	}

	port, err := localEndpoint.Spec.GetBackendPort(v1.UDPPortConfig, int32(v.spec.NATTPort))
	if err != nil {
		return nil, errors.Wrapf(err, "error parsing %q from local endpoint", v1.UDPPortConfig)
	}
	portStr := strconv.Itoa(int(port))

	// configure the device. still not up
	//create vpp_wireguard link
	klog.V(log.DEBUG).Infof("Created VPP_WireGuard %s with publicKey %s", DefaultDeviceName, pub)

	if err = v.scriptRun("wireguardCreate.sh", v.localEndpoint.Spec.PrivateIP, v.localEndpoint.Spec.VppEndpointIP, priv.String(), portStr); err != nil {
		return nil, fmt.Errorf("error creating vpp wireguard interface: %v", err)
	}
	return &v, nil
}

func (v *vpp) Init() error {
	return nil
}

// scriptRun using VPP command
func (v *vpp) scriptRun(args ...string) error {
	cmd := exec.Command("sh", args...)
	if err := cmd.Run(); err != nil {
		if err.Error() == "exit status 1" {
			klog.V(log.DEBUG).Infof("Script was executed redundantly. Countinue the rest...")
			return nil
		} else if err.Error() == "exit status 255" {
			klog.V(log.DEBUG).Infof("Exec %s file...", args[0])
			return nil
		} else {
			return fmt.Errorf("error occur in Script File [%s]: %v", args[0], err)
		}

	}
	return nil
}

//Connect to remote cluster
func (v *vpp) ConnectToEndpoint(endpointInfo *natdiscovery.NATEndpointInfo) (string, error) {

	remoteEndpoint := &endpointInfo.Endpoint

	if v.localEndpoint.Spec.ClusterID == remoteEndpoint.Spec.ClusterID {
		klog.V(log.DEBUG).Infof("Will not connect to self")
		return "", nil
	}

	v.mutex.Lock()
	defer v.mutex.Unlock()

	//prepare arguments
	allowedIPs := parseSubnets(remoteEndpoint.Spec.Subnets)
	localAllowedIPs := v.localEndpoint.Spec.Subnets

	remoteEndpoint.Spec.VppEndpointIP = remoteEndpoint.Spec.BackendConfig["VppEndpointIP"]
	remoteEndpoint.Spec.VppHostIP = remoteEndpoint.Spec.BackendConfig["VppHostIP"]
	remoteEndpoint.Spec.VppIP = remoteEndpoint.Spec.BackendConfig["VppIP"]

	remoteVppEndpointIP := remoteEndpoint.Spec.VppEndpointIP

	port, err := remoteEndpoint.Spec.GetBackendPort(v1.UDPPortConfig, int32(v.spec.NATTPort))
	if err != nil {
		return "", errors.Wrapf(err, "error parsing %q from local endpoint", v1.UDPPortConfig)
	}
	remoteKey, err := keyFromSpec(&remoteEndpoint.Spec)
	if err != nil {
		return "", fmt.Errorf("failed to parse peer public key: %v", err)
	}
	vppWireguardIP, err := createWireguardIP(v.localEndpoint.Spec.VppIP)
	if err != nil {
		return "", fmt.Errorf("failed to create Wireguard Interface IP : %v", err)
	}

	//Connect to remote Wireguard
	err = v.scriptRun("wireguardConnect.sh", v.localEndpoint.Spec.PrivateIP, remoteKey, remoteVppEndpointIP, strconv.Itoa(int(port)), KeepAliveInterval)
	if err != nil {
		return "", fmt.Errorf("Failed to Connection wireguard: %v", err)
	}

	//Create tap device  && Set up tap,wireguard device
	err = v.scriptRun("wireguardSetLocal.sh", v.localEndpoint.Spec.PrivateIP, v.ADDCidr(v.localEndpoint.Spec.VppHostIP, v.spec.VPPCidr), v.ADDCidr(v.localEndpoint.Spec.VppIP, v.spec.VPPCidr), v.ADDCidr(vppWireguardIP, "32"), DefaultDeviceName, VPPTunIndex)
	if err != nil {
		return "", fmt.Errorf("Failed to Set local Device: %v", err)
	}

	//Routing Settings for Subnet
	klog.V(log.DEBUG).Infof("remoteEndpoint ip ... %s", remoteEndpoint.Spec.VppHostIP)
	dstRouteIP := v.createCidr(remoteEndpoint.Spec.VppHostIP)
	if dstRouteIP == nil {
		return "", fmt.Errorf("Failed to Set route IP.....")
	}
	if err = v.AddRoute(allowedIPs, net.ParseIP(v.localEndpoint.Spec.VppIP), net.ParseIP(v.localEndpoint.Spec.VppHostIP), dstRouteIP); err != nil {
		return "", fmt.Errorf("Fail to run AddRoute %v", err)
	}
	//route Subnet in Vpp
	if err = v.AddRouteVPP(remoteEndpoint.Spec.Subnets, localAllowedIPs); err != nil {
		return "", fmt.Errorf("Fail to AddRoute VPP %v", err)
	}

	v.connections = append(v.connections, v1.Connection{Endpoint: remoteEndpoint.Spec, Status: v1.Connected,
		UsingIP: endpointInfo.UseIP, UsingNAT: endpointInfo.UseNAT})

	klog.V(log.DEBUG).Infof("Done adding endpoint for cluster %s", remoteEndpoint.Spec.ClusterID)
	return endpointInfo.UseIP, nil
}

func keyFromSpec(ep *v1.EndpointSpec) (string, error) {
	s, found := ep.BackendConfig[PublicKey]
	if !found {
		return "", fmt.Errorf("endpoint is missing public key")
	}

	return s, nil
}

// parse CIDR string and skip errors
func parseSubnets(subnets []string) []net.IPNet {
	nets := make([]net.IPNet, 0, len(subnets))

	for _, sn := range subnets {
		_, cidr, err := net.ParseCIDR(sn)
		if err != nil {
			// this should not happen. Log and continue
			klog.Errorf("Failed to parse subnet %s: %v", sn, err)
			continue
		}

		nets = append(nets, *cidr)
	}

	return nets
}

func createWireguardIP(ip string) (string, error) {
	ipSlice := strings.Split(ip, ".")
	if len(ipSlice) < 4 {
		return "", fmt.Errorf("invalid ipAddr [%s]", ip)
	}
	ipSlice[0] = VPPWireguardPrefix
	wgIP := strings.Join(ipSlice, ".")
	return wgIP, nil
}

//route rule
func (v *vpp) AddRouteVPP(remoteSubnet, localSubnet []string) error {
	for i := range localSubnet {
		klog.V(log.DEBUG).Infof("%s,%s,%s,%s,%s", "routeSubnet.sh", v.localEndpoint.Spec.PrivateIP, localSubnet[i], v.localEndpoint.Spec.VppHostIP, "tun"+VPPTunIndex)
		err := v.scriptRun("routeSubnet.sh", v.localEndpoint.Spec.PrivateIP, localSubnet[i], v.localEndpoint.Spec.VppHostIP, "tun"+VPPTunIndex)
		if err != nil {
			return fmt.Errorf("Fail to local Route %v", err)
		}
	}
	return nil
}

func (v *vpp) AddRoute(ipAddressList []net.IPNet, gwIP, ip net.IP, routeIP *net.IPNet) error {
	//delete default submariner routing rule
	FlushRouteTable(150)
	link, err := netlink.LinkByName(DefaultDeviceName)
	if err != nil {
		return fmt.Errorf("unable to find vpp link.	err: %s", err)
	}
	for i := range ipAddressList {
		klog.V(log.DEBUG).Infof("dst IP... %v", &ipAddressList[i])
		route := &netlink.Route{
			LinkIndex: link.Attrs().Index,
			Dst:       &ipAddressList[i],
			Gw:        gwIP,
			Type:      netlink.NDA_DST,
			Flags:     netlink.NTF_SELF,
			Priority:  100,
			Table:     TableID,
		}

		err := netlink.RouteAdd(route)
		klog.V(log.DEBUG).Infof("ADD ROUTE...")
		if err == syscall.EEXIST {
			klog.V(log.DEBUG).Infof("REPLACE ROUTE...")
			err = netlink.RouteReplace(route)
		}

		if err != nil {
			return fmt.Errorf("unable to add the route entry %v, err: %s", route, err)
		}
	}

	route := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       routeIP,
		Src:       ip,
		Gw:        gwIP,
		Priority:  100,
		Table:     TableID,
	}
	err = netlink.RouteAdd(route)
	klog.V(log.DEBUG).Infof("ADD ROUTE %v ...%v", route, err)
	if err == syscall.EEXIST {
		klog.V(log.DEBUG).Infof("REPLACE ROUTE...")
		err = netlink.RouteReplace(route)
	}
	return nil
}

//Disconnect to remote cluster(ip link del && Delete vpp setting)
func (v *vpp) DisconnectFromEndpoint(remoteEndpoint types.SubmarinerEndpoint) error {
	klog.V(log.DEBUG).Infof("Removing endpoint %#v", remoteEndpoint)

	if v.localEndpoint.Spec.ClusterID == remoteEndpoint.Spec.ClusterID {
		klog.V(log.DEBUG).Infof("Will not disconnect self")
		return nil
	}

	v.mutex.Lock()
	defer v.mutex.Unlock()

	var ip string

	for _, connection := range v.connections {
		if connection.Endpoint.CableName == remoteEndpoint.Spec.CableName {
			ip = connection.UsingIP
		}
	}

	if ip == "" {
		klog.Errorf("Cannot disconnect remote endpoint %q - no prior connection entry found", remoteEndpoint.Spec.CableName)
		return nil
	}
	allowedIPs := parseSubnets(remoteEndpoint.Spec.Subnets)
	err := v.DelRoute(allowedIPs)
	if err != nil {
		return fmt.Errorf("failed to remove route for the CIDR %q",
			allowedIPs)
	}
	//add del route in vpp

	v.connections = removeConnectionForEndpoint(v.connections, remoteEndpoint)
	cable.RecordDisconnected(CableDriverName, &v.localEndpoint.Spec, &remoteEndpoint.Spec)

	klog.V(log.DEBUG).Infof("Done removing endpoint for cluster %s", remoteEndpoint.Spec.ClusterID)

	return nil
}

func removeConnectionForEndpoint(connections []v1.Connection, endpoint types.SubmarinerEndpoint) []v1.Connection {
	for j := range connections {
		if connections[j].Endpoint.CableName == endpoint.Spec.CableName {
			copy(connections[j:], connections[j+1:])
			return connections[:len(connections)-1]
		}
	}

	return connections
}
func (v *vpp) DelRoute(ipAddressList []net.IPNet) error {
	link, err := netlink.LinkByName(DefaultDeviceName)
	if err != nil {
		return fmt.Errorf("unable to find vpp link.	err: %s", err)
	}
	for i := range ipAddressList {
		route := &netlink.Route{
			LinkIndex: link.Attrs().Index,
			Dst:       &ipAddressList[i],
			Gw:        nil,
			Type:      netlink.NDA_DST,
			// Flags:     netlink.NTF_SELF,
			Priority: 100,
			Table:    TableID,
		}
		err := netlink.RouteDel(route)
		klog.V(log.DEBUG).Infof("DEL ROUTE...")
		if err != nil {
			return fmt.Errorf("unable to del the route entry %v, err: %s", route, err)
		}
	}
	return nil
}

//copy & paste func
func (v *vpp) GetName() string {
	return CableDriverName
}

func (v *vpp) GetConnections() ([]v1.Connection, error) {
	return v.connections, nil
}

func (v *vpp) GetActiveConnections() ([]v1.Connection, error) {
	return v.connections, nil
}

//flush default IP route
func FlushRouteTable(tableID int) error {
	return exec.Command("/sbin/ip", "r", "flush", "table", strconv.Itoa(tableID)).Run()
}

func genPsk(psk string) (wgtypes.Key, error) {
	// Convert spec PSK string to right length byte array, using sha256.Size == wgtypes.KeyLen
	pskBytes := sha256.Sum256([]byte(psk))
	return wgtypes.NewKey(pskBytes[:])
}

func (v *vpp) ADDCidr(ip string, cidr string) string {
	new_ip := ip + "/" + cidr
	return new_ip
}

func (v *vpp) createCidr(ip string) *net.IPNet {
	newip := ip + "/" + v.spec.VPPCidr
	klog.V(log.DEBUG).Infof("newip ... %s", newip)
	_, netip, err := net.ParseCIDR(newip)
	if err != nil {
		klog.V(log.DEBUG).Infof("err ... %v", err)
		return nil
	} else {
		return netip
	}
}
