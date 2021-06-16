package gre

import (
	"fmt"
	"os"
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
	"k8s.io/klog"
)

const (
	cableDriverName   = "gre"
	DefaultDeviceName = "submariner"
)

func init() {
	cable.AddDriver(cableDriverName, NewDriver)
}

type gre struct {
	localEndpoint  types.SubmarinerEndpoint
	connections    []v1.Connection
	localIP        string
	remoteIP       string
	mutex          sync.Mutex
	localTunnelIP  string
	remoteTunnelIP string
	tunnelRouteIP  string
}

func NewDriver(localEndpoint types.SubmarinerEndpoint, localCluster types.SubmarinerCluster) (cable.Driver, error) {
	tunnelIPs := []string{"192.168.1.1/24", "192.168.2.1/24"}
	tunnelRoutes := []string{"192.168.1.0/24", "192.168.2.0/24"}
	localTunnelIP, tunnelRouteIP, remoteTunnelIP := selectTunnelIP(tunnelIPs, tunnelRoutes, localEndpoint.Spec.PrivateIP)
	g := gre{
		localEndpoint:  localEndpoint,
		localIP:        localEndpoint.Spec.PrivateIP,
		localTunnelIP:  localTunnelIP,
		remoteTunnelIP: remoteTunnelIP,
		tunnelRouteIP:  tunnelRouteIP,
	}
	klog.V(log.DEBUG).Infof("set GRE: %s", DefaultDeviceName)
	return &g, nil
}
func (g *gre) Init() error {
	return nil
}

func (g *gre) GetName() string {
	return cableDriverName
}

func (g *gre) ConnectToEndpoint(endpointInfo *natdiscovery.NATEndpointInfo) (string, error) {
	remoteEndpoint := endpointInfo.Endpoint
	if g.localEndpoint.Spec.ClusterID == remoteEndpoint.Spec.ClusterID {
		klog.V(log.DEBUG).Infof("Will not connect to self")
		return "", nil
	}

	remoteIP := endpointInfo.UseIP
	if remoteIP == "" {
		return "", fmt.Errorf("failed to parse remote IP %s", endpointInfo.UseIP)
	}

	klog.V(log.DEBUG).Infof("Connecting cluster %s endpoint %s", remoteEndpoint.Spec.ClusterID, remoteIP)

	g.mutex.Lock()
	defer g.mutex.Unlock()

	cable.RecordConnection(cableDriverName, &g.localEndpoint.Spec, &remoteEndpoint.Spec, string(v1.Connected), true)

	err := g.createGRE(g.localIP, g.remoteIP, g.remoteTunnelIP, g.tunnelRouteIP)
	if err != nil {
		return "", fmt.Errorf("Error to create gre : %v", err)
	}
	g.connections = append(g.connections, v1.Connection{Endpoint: remoteEndpoint.Spec, Status: v1.Connected,
		UsingIP: endpointInfo.UseIP, UsingNAT: endpointInfo.UseNAT})

	return g.remoteTunnelIP, nil
}

func (g *gre) DisconnectFromEndpoint(endpoint types.SubmarinerEndpoint) error {
	klog.V(log.DEBUG).Infof("Removing endpoint %#v", endpoint)
	deleteTunnel()
	g.connections = removeConnectionForEndpoint(g.connections, endpoint)
	cable.RecordDisconnected(cableDriverName, &g.localEndpoint.Spec, &endpoint.Spec)
	return nil
}

func (g *gre) GetActiveConnections() ([]v1.Connection, error) {
	return g.connections, nil
}

func (g *gre) GetConnections() ([]v1.Connection, error) {
	return g.connections, nil
}

//---------------------------------------------------------------------------------------------------------------------------
//my func

func removeConnectionForEndpoint(connections []v1.Connection, endpoint types.SubmarinerEndpoint) []v1.Connection {
	for j := range connections {
		if connections[j].Endpoint.CableName == endpoint.Spec.CableName {
			copy(connections[j:], connections[j+1:])
			return connections[:len(connections)-1]
		}
	}

	return connections
}

func (g *gre) createGRE(localIP string, remoteIP string, tunnelIP string, routeIP string) error {
	if err := g.setTunnel(localIP, remoteIP); err != nil {
		return err
	}
	if err := g.deviceUp(); err != nil {
		return err
	}
	if err := g.linkTunnel(tunnelIP); err != nil {
		return err
	}
	if err := g.routeTunnel(routeIP); err != nil {
		return err
	}
	return nil
}

func ipCommand(lookPath string, command []string) error {
	binary, err := exec.LookPath(lookPath)
	if err != nil {
		klog.V(log.DEBUG).Infof("Error lookpath loaded... : %v", err)
		return err
	}
	env := os.Environ()
	err = syscall.Exec(binary, command, env)
	if err != nil {
		klog.V(log.DEBUG).Infof("Err exec lookpath... : %v", err)
		return err
	}
	return nil
}

func (g *gre) setTunnel(localIP string, remoteIP string) error {
	err := ipCommand("ip", []string{"ip", "tunnel", "add", DefaultDeviceName, "gre", "local", localIP, "remote", remoteIP, "ttl 255"})
	if err != nil {
		return err
	}
	return nil
}

func (g *gre) deviceUp() error {
	err := ipCommand("ip", []string{"ip", "set", DefaultDeviceName, "up"})
	if err != nil {
		return err
	}
	return nil
}

func (g *gre) linkTunnel(tunnelIP string) error {
	err := ipCommand("ip", []string{"ip", "addr", "add", tunnelIP, "dev", DefaultDeviceName})
	if err != nil {
		return err
	}
	return nil
}
func (g *gre) routeTunnel(tunnelIP string) error {
	err := ipCommand("ip", []string{"ip", "route", "add", tunnelIP, "dev", DefaultDeviceName})
	if err != nil {
		return err
	}
	return nil
}

func deleteTunnel() error {
	err := ipCommand("ip", []string{"ip", "del", "tunnel", DefaultDeviceName})
	if err != nil {
		return err
	}
	return nil
}

func selectTunnelIP(tunnelIP []string, tunnelRouteIP []string, localIP string) (string, string, string) {
	slice := strings.Split(localIP, ".")
	num, _ := strconv.Atoi(slice[3])
	if (num % 2) == 0 {
		return tunnelIP[0], tunnelRouteIP[1], tunnelIP[1]
	} else {
		return tunnelIP[1], tunnelRouteIP[0], tunnelIP[0]
	}
}
