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
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/submariner-io/admiral/pkg/log"
	v1 "github.com/submariner-io/submariner/pkg/apis/submariner.io/v1"
	"github.com/submariner-io/submariner/pkg/cable"
	"github.com/submariner-io/submariner/pkg/natdiscovery"
	"github.com/submariner-io/submariner/pkg/types"
	"github.com/vishvananda/netlink"
	"k8s.io/klog"
)

const (
	// DefaultDeviceName specifies name of Vpp network device
	DefaultDeviceName    = "submariner"
	VppDeviceName        = "vpp-submariner"
	CableDriverName      = "vpp"
	VPPCidr              = "/24"
	VPPVTepNetworkPrefix = "240"
	TableID              = 150
)

func init() {
	cable.AddDriver(CableDriverName, NewDriver)
}

type vpp struct {
	localEndpoint types.SubmarinerEndpoint
	localCluster  types.SubmarinerCluster
	connections   []v1.Connection
	mutex         sync.Mutex
	link          netlink.Link
}

// NewDriver creates a new VPP driver
func NewDriver(localEndpoint types.SubmarinerEndpoint, localCluster types.SubmarinerCluster) (cable.Driver, error) {
	var err error
	// create new Endpoint IP & vtepIP
	v := vpp{
		localEndpoint: localEndpoint,
		localCluster:  localCluster,
	}

	if err = v.setupVppLink(); err != nil {
		return nil, fmt.Errorf("fail to create Vpp link %v", err)
	}
	if err = v.scriptRun("createTunnel.sh", v.localEndpoint.Spec.PrivateIP, VppDeviceName, v.localEndpoint.Spec.VppIP, VPPCidr); err != nil {
		return nil, fmt.Errorf("fail to start Vpp script %v", err)
	}
	return &v, nil
}

func (v *vpp) setupVppLink() error {
	// delete existing vpp device if needed
	if link, err := netlink.LinkByName(DefaultDeviceName); err == nil {
		// delete existing device
		if err := netlink.LinkDel(link); err != nil {
			return fmt.Errorf("Failed to delete existing Vpp device: %v", err)
		}
	}
	// create the vpp device (ip link add dev $DefaultDeviceName type veth peer $VppDeviceName)
	la := netlink.NewLinkAttrs()
	la.Name = DefaultDeviceName
	link := &netlink.Veth{
		LinkAttrs: la,
		PeerName:  VppDeviceName,
	}
	if err := netlink.LinkAdd(link); err == nil {
		v.link = link
	} else {
		return fmt.Errorf("Failed to add VPP device: %v", err)
	}
	linkIP, err := netlink.ParseAddr(v.localEndpoint.Spec.VppHostIP + VPPCidr)
	if err != nil {
		return fmt.Errorf("Failed to convert IP format: %s, %v", v.localEndpoint.Spec.VppHostIP+VPPCidr, err)
	}
	//ip addr add dev $DefaultDeviceName $VppHostIP
	if err := netlink.AddrAdd(link, linkIP); err != nil {
		return fmt.Errorf("Failed to add addr : %v", err)
	}
	//ip link dev $DefaultDeviceName up && ip link dev $VppDeviceName up
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("Failed to bring up VPP device: %v", err)
	}
	return nil
}

// scriptRun using create VPP Tunnel
func (v *vpp) scriptRun(args ...string) error {
	cmd := exec.Command("sh", args...)
	if err := cmd.Run(); err != nil {
		// return fmt.Errorf("error start script: %v", err)
		return nil
	}
	return nil
}

func (v *vpp) Init() error {
	return nil
}

//Connect to remote cluster
func (v *vpp) ConnectToEndpoint(endpointInfo *natdiscovery.NATEndpointInfo) (string, error) {
	remoteEndpoint := &endpointInfo.Endpoint
	if v.localEndpoint.Spec.ClusterID == remoteEndpoint.Spec.ClusterID {
		klog.V(log.DEBUG).Infof("Will not connect to self")
		return "", nil
	}
	//parse subnet IP (Pod, Service IP)
	allowedIPs := parseSubnets(remoteEndpoint.Spec.Subnets)
	localAllowedIPs := v.localEndpoint.Spec.Subnets
	remoteIP := net.ParseIP(endpointInfo.Endpoint.Spec.VppEndpointIP)

	klog.V(log.DEBUG).Infof("Connecting cluster %s endpoint %s", remoteEndpoint.Spec.ClusterID, remoteIP)

	v.mutex.Lock()
	defer v.mutex.Unlock()

	cable.RecordConnection(CableDriverName, &v.localEndpoint.Spec, &remoteEndpoint.Spec, string(v1.Connected), true)

	remoteEndpointIP := remoteEndpoint.Spec.VppEndpointIP

	remoteHostIP := remoteEndpoint.Spec.VppHostIP

	remoteVppIP := remoteEndpoint.Spec.VppIP

	if remoteHostIP == "" {
		return endpointInfo.UseIP, fmt.Errorf("Failed to derive the VPP host IP for %s", remoteEndpointIP)
	}

	remoteRouteCidr, err := createCidr(remoteVppIP, "route", VPPCidr)

	if err != nil {
		return endpointInfo.UseIP, fmt.Errorf("Failed to make route cidr IP for %s", remoteEndpointIP)
	}

	if err != nil {
		return endpointInfo.UseIP, fmt.Errorf("Failed to add route for the CIDR %q with remote_Host_IP %q and localHostIP %q ==== error : %v",
			allowedIPs, remoteHostIP, v.localEndpoint.Spec.VppHostIP, err)
	}

	//route Tunnel
	if err = v.scriptRun("routeTunnel.sh", remoteRouteCidr, v.localEndpoint.Spec.VppEndpointIP, remoteEndpointIP, v.localEndpoint.Spec.PrivateIP, DefaultDeviceName, v.localEndpoint.Spec.VppIP); err != nil {
		return endpointInfo.UseIP, fmt.Errorf("fail to start Vpp script %v", err)
	}

	//route Subnet
	if err = v.AddRoute(allowedIPs, net.ParseIP(v.localEndpoint.Spec.VppIP), net.ParseIP(v.localEndpoint.Spec.VppHostIP)); err != nil {
		return endpointInfo.UseIP, fmt.Errorf("Fail to run AddRoute %v", err)
	}

	//route Subnet in Vpp
	if err = v.AddRouteVPP(remoteEndpoint.Spec.Subnets, localAllowedIPs, remoteEndpointIP); err != nil {
		return endpointInfo.UseIP, fmt.Errorf("Fail to AddRouteVPP %v", err)
	}
	v.connections = append(v.connections, v1.Connection{Endpoint: remoteEndpoint.Spec, Status: v1.Connected,
		UsingIP: endpointInfo.UseIP, UsingNAT: endpointInfo.UseNAT})

	klog.V(log.DEBUG).Infof("Done adding endpoint for cluster %s", remoteEndpoint.Spec.ClusterID)
	return endpointInfo.UseIP, nil
}

func (v *vpp) AddRouteVPP(remoteSubnet, localSubnet []string, remoteEndpointIP string) error {
	for i := range remoteSubnet {
		err := v.scriptRun("routeSubnet.sh", "remote", v.localEndpoint.Spec.PrivateIP, remoteSubnet[i], remoteEndpointIP)
		if err != nil {
			return fmt.Errorf("Fail to remote Route %v", err)
		}
	}
	for i := range localSubnet {
		err := v.scriptRun("routeSubnet.sh", "local", v.localEndpoint.Spec.PrivateIP, localSubnet[i], v.localEndpoint.Spec.VppHostIP, "host-"+VppDeviceName)
		if err != nil {
			return fmt.Errorf("Fail to local Route %v", err)
		}
	}
	return nil
}
func (v *vpp) AddRoute(ipAddressList []net.IPNet, gwIP, ip net.IP) error {
	//delete default submariner routing rule
	FlushRouteTable(150)
	for i := range ipAddressList {
		route := &netlink.Route{
			LinkIndex: v.link.Attrs().Index,
			Src:       ip,
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
	for i := range ipAddressList {
		route := &netlink.Route{
			LinkIndex: v.link.Attrs().Index,
			Dst:       &ipAddressList[i],
			Gw:        nil,
			Type:      netlink.NDA_DST,
			Flags:     netlink.NTF_SELF,
			Priority:  100,
			Table:     TableID,
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

// create cidr ex) default : x.x.x.x -> x.x.x.0/cidr    route : x.x.x.x -> x.x.x.x/cidr
func createCidr(ip string, kind string, cidr string) (string, error) {
	switch {
	//create x.x.x.0/x
	case "route" == kind:
		ipSlice := strings.Split(ip, ".")
		if len(ipSlice) < 4 {
			return "", fmt.Errorf("invalid ipAddr [%s]", ip)
		}
		ipSlice[3] = "0" + cidr
		routeCidr := strings.Join(ipSlice, ".")
		return routeCidr, nil

	//create x.x.x.x/x   -> use in vpp ip setting.
	case "vpp" == kind:
		ipSlice := strings.Split(ip, ".")
		if len(ipSlice) < 4 {
			return "", fmt.Errorf("invalid ipAddr [%s]", ip)
		}
		ipSlice[3] = ipSlice[3] + "/"
		ipSlice[3] = ipSlice[3] + cidr
		vppCidr := strings.Join(ipSlice, ".")
		return vppCidr, nil
	default:
		return "", fmt.Errorf("invalid input Cidr Kind [%s]", kind)
	}
}

func createVppIP(defaultIP string) (string, string, error) {

	vppHostIP, vppIP, err := createVppUseIP(defaultIP)
	if err != nil {
		return "", "", fmt.Errorf("Failed to create the vpp hostIP & vppIP for %s, %v", defaultIP, err)
	}

	return vppHostIP, vppIP, nil
}

func createVppUseIP(ip string) (string, string, error) {
	ipSlice := strings.Split(ip, ".")
	if len(ipSlice) < 4 {
		return "", "", fmt.Errorf("invalid ipAddr [%s]", ip)
	}
	ipSlice[0] = "140"
	ipSlice[2] = ipSlice[3]
	ipSlice[3] = "2"
	hostIP := strings.Join(ipSlice, ".")
	ipSlice[3] = "1"
	vppIP := strings.Join(ipSlice, ".")
	return hostIP, vppIP, nil
}

func FlushRouteTable(tableID int) error {
	// The conversion doesn't introduce a security problem
	// #nosec G204
	return exec.Command("/sbin/ip", "r", "flush", "table", strconv.Itoa(tableID)).Run()
}
