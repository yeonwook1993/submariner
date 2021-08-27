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
package tunnel

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/submariner-io/admiral/pkg/log"
	"github.com/submariner-io/admiral/pkg/watcher"
	v1 "github.com/submariner-io/submariner/pkg/apis/submariner.io/v1"
	"github.com/submariner-io/submariner/pkg/cableengine"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/klog"
)

type controller struct {
	engine cableengine.Engine
}

func StartController(engine cableengine.Engine, namespace string, config *watcher.Config, stopCh <-chan struct{}) error {
	klog.Info("Starting the tunnel controller")

	c := &controller{engine: engine}

	config.ResourceConfigs = []watcher.ResourceConfig{
		{
			Name:         "Tunnel Controller",
			ResourceType: &v1.Endpoint{},
			Handler: watcher.EventHandlerFuncs{
				OnCreateFunc: c.handleCreatedOrUpdatedEndpoint,
				OnUpdateFunc: c.handleCreatedOrUpdatedEndpoint,
				OnDeleteFunc: c.handleRemovedEndpoint,
			},
			SourceNamespace: namespace,
		},
	}

	if config.ResyncPeriod == 0 {
		config.ResyncPeriod = time.Second * 30
	}

	endpointWatcher, err := watcher.New(config)
	if err != nil {
		return err
	}

	err = endpointWatcher.Start(stopCh)
	if err != nil {
		return err
	}

	return nil
}

func (c *controller) handleCreatedOrUpdatedEndpoint(obj runtime.Object, numRequeues int) bool {
	endpoint := obj.(*v1.Endpoint)

	// temporary select VPP IP
	VppEndpointIP, err := createVPPEndpoint(endpoint.Spec.PrivateIP)
	if err != nil {
		klog.Fatalf("Error create VPP host IP in Tunnel : %s", err)
	}
	VppHostIP, VppIP, err := createVppIP(endpoint.Spec.PrivateIP)
	if err != nil {
		klog.Fatalf("Error create VPP IP & VPP HOST IP for %s in Tunnel : %v", endpoint.Spec.PrivateIP, err)
	}
	endpoint.Spec.VppEndpointIP = VppEndpointIP
	endpoint.Spec.VppHostIP = VppHostIP
	endpoint.Spec.VppIP = VppIP

	klog.V(log.DEBUG).Infof("Tunnel controller processing added or updated submariner Endpoint object: %#v", endpoint)
	err = c.engine.InstallCable(endpoint)
	if err != nil {
		klog.Errorf("error installing cable for Endpoint %#v, %v", endpoint, err)
		return true
	}

	return false
}

//create vppIface
func createVPPEndpoint(ip string) (string, error) {
	ipSlice := strings.Split(ip, ".")
	if len(ipSlice) < 4 {
		return "", fmt.Errorf("invalid ipAddr [%s]", ip)
	}

	ipSlice[2] = strconv.Itoa(100)
	vppIP := strings.Join(ipSlice, ".")

	return vppIP, nil
}

func createVppIP(ip string) (string, string, error) {
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

func (c *controller) handleRemovedEndpoint(obj runtime.Object, numRequeues int) bool {
	endpoint := obj.(*v1.Endpoint)

	klog.V(log.DEBUG).Infof("Tunnel controller processing removed submariner Endpoint object: %#v", endpoint)

	if err := c.engine.RemoveCable(endpoint); err != nil {
		klog.Errorf("Tunnel controller failed to remove Endpoint cable %#v from the engine: %v", endpoint, err)
		return true
	}

	klog.V(log.DEBUG).Infof("Tunnel controller successfully removed Endpoint cable %s from the engine", endpoint.Spec.CableName)

	return false
}
