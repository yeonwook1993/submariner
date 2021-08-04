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
	"os/exec"
	"strconv"
	"strings"
	"sync"

	"github.com/submariner-io/admiral/pkg/log"
	v1 "github.com/submariner-io/submariner/pkg/apis/submariner.io/v1"
	"github.com/submariner-io/submariner/pkg/cable"
	"github.com/submariner-io/submariner/pkg/natdiscovery"
	"github.com/submariner-io/submariner/pkg/types"
	"k8s.io/klog"
)

const (
	// DefaultDeviceName specifies name of WireGuard network device
	DefaultDeviceName    = "submariner"
	CableDriverName      = "vpp"
	HostIntName          = "vpp-host"
	VppIntName           = "vpp-out"
	VPPCidr              = "24"
	VPPVTepNetworkPrefix = 240
)

func init() {
	cable.AddDriver(CableDriverName, NewDriver)
}

type specification struct {
}

type vpp struct {
	localEndpoint types.SubmarinerEndpoint
	localCluster  types.SubmarinerCluster
	connections   []v1.Connection
	mutex         sync.Mutex
	vppIface      *vppIface
}

type vppIface struct {
	newEndpoint string
	vtepIP      string
	vtepIPCidr  string
}

// NewDriver creates a new VPP driver
func NewDriver(localEndpoint types.SubmarinerEndpoint, localCluster types.SubmarinerCluster) (cable.Driver, error) {
	// create new Endpoint IP & vtepIP
	v := vpp{
		localEndpoint: localEndpoint,
		localCluster:  localCluster,
	}

	if err := v.createVPPInterface(localEndpoint); err != nil {
		return nil, fmt.Errorf("failed to setup VPP link: %v", err)
	}
	return &v, nil
}

func (v *vpp) createVPPInterface(localEndpoint types.SubmarinerEndpoint) error {
	//make args... like hostname, vtepIP, gatewayIP ...
	ip := v.localEndpoint.Spec.PrivateIP
	vtepIP, err := v.createVPPVtepIP(ip)
	if err != nil {
		return fmt.Errorf("failed to create vtepIP: %v", err)
	}
	hostname, vppname, err := v.createInterfaceName()
	if err != nil {
		return fmt.Errorf("error in createInterface: %v", err)
	}
	gateway, err := createCidr(vtepIP, "gateway", VPPCidr)
	if err != nil {
		return fmt.Errorf("error in create VPP-Gateway IP Cidr: %v", err)
	}

	//create VPP interface && exec script
	v.vppIface = &vppIface{
		newEndpoint: localEndpoint.Spec.VppIP,
		vtepIP:      vtepIP,
		vtepIPCidr:  VPPCidr,
	}

	err = startScript("createTunnel.sh", hostname, vppname, vtepIP, gateway, localEndpoint.Spec.PrivateIP)
	if err != nil {
		return fmt.Errorf("Error in start script: %v", err)
	}
	return nil
}

// startScript using create VPP Tunnel
func startScript(args ...string) error {
	cmd := exec.Command("sh", args...)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("error start script: %v", err)
	}
	return nil
}

// create veth Interface used in VPP
func (v *vpp) createInterfaceName() (string, string, error) {
	connect := len(v.connections)
	hostIntName := HostIntName + strconv.Itoa(connect)
	vppIntName := VppIntName + strconv.Itoa(connect)
	if hostIntName == "" {
		return "", "", fmt.Errorf("failed to create veth_Interface")
	}
	if vppIntName == "" {
		return "", "", fmt.Errorf("failed to create veth_Interface")
	}
	return hostIntName, VppIntName, nil
}

//create VPPVtepIP ex) 10.x.x.x -> 240.x.x.2~255
func (v *vpp) createVPPVtepIP(ip string) (string, error) {
	ipSlice := strings.Split(ip, ".")
	if len(ipSlice) < 4 {
		return "", fmt.Errorf("invalid ipAddr [%s]", ip)
	}

	ipSlice[0] = strconv.Itoa(VPPVTepNetworkPrefix)
	ipSlice[3] = strconv.Itoa(2 + len(v.connections))
	vppIP := strings.Join(ipSlice, ".")

	return vppIP, nil
}

// create cidr used for routing or gateway   ex) route: x.x.x.x/cidr -> x.x.x.0/cidr , gateway: x.x.x.x/cidr -> x.x.x.1/cidr
func createCidr(ip string, kind string, cidr string) (string, error) {
	switch {
	case "route" == kind:
		ipSlice := strings.Split(ip, ".")
		if len(ipSlice) < 4 {
			return "", fmt.Errorf("invalid ipAddr [%s]", ip)
		}
		ipSlice[3] = "0/" + cidr
		routeCidr := strings.Join(ipSlice, ".")
		return routeCidr, nil
	case "gateway" == kind:
		ipSlice := strings.Split(ip, ".")
		if len(ipSlice) < 4 {
			return "", fmt.Errorf("invalid ipAddr [%s]", ip)
		}
		ipSlice[3] = "1/" + cidr
		gatewayCidr := strings.Join(ipSlice, ".")
		return gatewayCidr, nil
	default:
		return "", fmt.Errorf("invalid Cidr kind [%s]", kind)
	}
}
func (v *vpp) Init() error {
	return nil
}

//////////////////////////
//////////////////////////
//////////////////////////
//////////////////////////
//////////////////////////
//////////////////////////
//////////////////////////
//////////////////////////
//////////////////////////
//////////////////////////
func (v *vpp) ConnectToEndpoint(endpointInfo *natdiscovery.NATEndpointInfo) (string, error) {
	return "", nil
}

//////////////////////////
//////////////////////////
//////////////////////////
//////////////////////////
//////////////////////////
//////////////////////////
//////////////////////////
//////////////////////////
//////////////////////////
//////////////////////////
//////////////////////////
//////////////////////////
func (v *vpp) GetName() string {
	return CableDriverName
}

func (v *vpp) GetConnections() ([]v1.Connection, error) {
	return v.connections, nil
}

func (v *vpp) GetActiveConnections() ([]v1.Connection, error) {
	return v.connections, nil
}

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
