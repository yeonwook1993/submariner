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
	VppIface             = "vpp-int"
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

func (v *vpp) Init() error {
	cable.AddDriver(CableDriverName, NewDriver)
}

// NewDriver creates a new VPP driver
func NewDriver(localEndpoint types.SubmarinerEndpoint, localCluster types.SubmarinerCluster) (cable.Driver, error) {
	// create new Endpoint IP & vtepip
	v := vpp{
		localEndpoint: localEndpoint,
		localCluster:  localCluster,
	}
	if err := v.createVPPInterface(); err != nil {
		return nil, fmt.Errorf("failed to setup VPP link: %v", err)
	}
	return &v, nil
}

func (v *vpp) createVPPInterface() error {
	ip := v.localEndpoint.Spec.PrivateIP
	vtepIP, err := v.createVPPVtepIP(ip)
	if err != nil {
		return fmt.Errorf("failed to create vtepIP for %v", ip, err)
	}
}

//create VPP ipsec IP addr
func (v *vpp) createVPPVtepIP(ipAddr string) (string, error) {
	ipSlice := strings.Split(ipAddr, ".")
	if len(ipSlice) < 4 {
		return "", fmt.Errorf("invalid ipAddr [%s]", ipAddr)
	}

	ipSlice[0] = strconv.Itoa(VPPVTepNetworkPrefix)
	vppIP := strings.Join(ipSlice, ".")

	return vppIP, nil
}

//transfer ip to cidr
func (v *vpp) makeCidr(ipAddr string, cidr string) (string, error) {
	ipSlice := strings.Split(ipAddr, ".")
	if len(ipSlice) < 4 {
		return "", fmt.Errorf("in valid ip Addr [%s]", ipAddr)
	}
	ipSlice[3] = "0"
	ipCidr := strings.Join(ipSlice, ".") + "/" + cidr
	return ipCidr, nil
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
