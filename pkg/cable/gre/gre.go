package gre

import (
	"fmt"
	"os"
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
	cableDriverName   = "gre"
	DefaultDeviceName = "gre-submariner"
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
	g.remoteIP = remoteIP
	if remoteIP == "" {
		return "", fmt.Errorf("failed to parse remote IP %s", endpointInfo.UseIP)
	}

	klog.V(log.DEBUG).Infof("Connecting cluster %s endpoint %s", remoteEndpoint.Spec.ClusterID, remoteIP)

	cable.RecordConnection(cableDriverName, &g.localEndpoint.Spec, &remoteEndpoint.Spec, string(v1.Connected), true)

	if checkExistDevice() {
		startScript("del-gre.sh")
	}
	checkExistFile("run-gre.sh")
	checkExistFile("del-gre.sh")

	err := g.makeGREfile(g.localIP, g.remoteIP, g.tunnelRouteIP, g.remoteTunnelIP)
	startScript("run-gre.sh")

	if err != nil {
		klog.V(log.DEBUG).Infof("Err Create gre : %v", err)
		return "", err
	}
	g.connections = append(g.connections, v1.Connection{Endpoint: remoteEndpoint.Spec, Status: v1.Connected,
		UsingIP: endpointInfo.UseIP, UsingNAT: endpointInfo.UseNAT})

	return endpointInfo.UseIP, nil
}

func (g *gre) DisconnectFromEndpoint(endpoint types.SubmarinerEndpoint) error {
	klog.V(log.DEBUG).Infof("Removing endpoint %#v", endpoint)
	startScript("del-gre.sh")
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
func (g *gre) makeGREfile(localIP string, remoteIP string, routeIP string, tunnelIP string) error {
	f1, err := os.Create("run-gre.sh")
	defer f1.Close()
	if err != nil {
		klog.V(log.DEBUG).Infof("err make run-gre.sh : %v", err)
		return err
	}
	fmt.Fprintf(f1, "ip tunnel add "+DefaultDeviceName+" mode gre local "+localIP+" remote "+remoteIP+" ttl 255\n")
	fmt.Fprintf(f1, "ip link set "+DefaultDeviceName+" up\n")
	fmt.Fprintf(f1, "ip route add "+routeIP+" dev "+DefaultDeviceName+"\n")
	fmt.Fprintf(f1, "ip addr add "+tunnelIP+" dev "+DefaultDeviceName+"\n")

	f2, err := os.Create("./del-gre.sh")
	defer f2.Close()
	if err != nil {
		klog.V(log.DEBUG).Infof("err make del-gre.sh : %v", err)
		return err
	}
	fmt.Fprintf(f2, "ip tunnel del "+DefaultDeviceName+"\n")
	return nil
}

func checkExistDevice() bool {
	cmd := "ip link | grep " + DefaultDeviceName
	out, _ := exec.Command("bash", "-c", cmd).Output()
	if string(out) != "" {
		return true
	} else {
		return false
	}
}

func checkExistFile(filename string) error {
	_, err := os.Stat(filename)
	if err == nil {
		err = os.Remove(filename)
		if err != nil {
			klog.V(log.DEBUG).Infof("err remove %s File... : %v", filename, err)
			return err
		}
	}
	return nil
}

func startScript(filename string) error {
	cmd := exec.Command("sh", filename)
	err := cmd.Run()
	if err != nil {
		klog.V(log.DEBUG).Infof("err start %s File... : %v", filename, err)
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
