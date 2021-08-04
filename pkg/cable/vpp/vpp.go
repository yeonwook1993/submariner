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
	hostIntIP   string
	vppIntIP    string
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
	hostIntIp, vppIntIp, err := v.createVPPVtepIP(ip)
	if err != nil {
		return fmt.Errorf("failed to create vtepIP: %v", err)
	}

	//create VPP interface && exec script
	v.vppIface = &vppIface{
		newEndpoint: localEndpoint.Spec.VppIP,
		vtepIPCidr:  VPPCidr,
		hostIntIP:   hostIntIp,
		vppIntIP:    vppIntIp,
	}
	klog.V(log.DEBUG).Infof("start script name : %s, hostname: %s, vppname: %s, vtepIP: %s, gateway: %s, EnpointIp: %s", "createTunnel.sh")
	err = startScript("createTunnel.sh")
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

//create VPPVtepIP VPPhostIP -> x1.x2.x3.x4/x -> vpp: 240.x4.0.1/24         host: 240.x4.0.2/24
func (v *vpp) createVPPVtepIP(ip string) (string, string, error) {
	return "", "", nil
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
		ipSlice[3] = "0/" + cidr
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
