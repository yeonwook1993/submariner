
package gre

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
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
	localEndpoint types.SubmarinerEndpoint
	connections   map[string]*v1.Connection
	localIP       string
	globalIP      [2]string
}

func NewDriver(localEndpoint types.SubmarinerEndpoint, localCluster types.SubmarinerCluster) (cable.Driver, error) {
	localIP := localEndpoint.Spec.PrivateIP
	globIP := [2]string{"10.2.1.2/30", "10.2.1.3/30"}
	g := gre{
		localEndpoint: localEndpoint,
		connections:   make(map[string]*v1.Connection),
		localIP:       localIP,
		globalIP:      globIP,
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
	remoteIP := endpointInfo.UseIP

	if g.localEndpoint.Spec.ClusterID == remoteEndpoint.Spec.ClusterID {
		klog.V(log.DEBUG).Infof("Can`t connect to self")
		return "", nil
	}
	// create  GRE Tunnel
	if err := g.setTunnel(g.localIP, remoteIP); err != nil {
		klog.V(log.DEBUG).Infof("Error establishing GRE tunnel...")
		return "", err
	}
	connection := v1.NewConnection(remoteEndpoint.Spec, remoteIP, endpointInfo.UseNAT)
	connection.SetStatus(v1.Connecting, "Connection has been created but not yet started")
	klog.V(log.DEBUG).Infof("Adding connection for cluster %s, %v", remoteEndpoint.Spec.ClusterID, connection)
	g.connections[remoteEndpoint.Spec.ClusterID] = connection

	//add to Device Default globalIP
	index := selectGlobalIP(g.localIP)

	if err := g.linkTunnel(g.globalIP[index]); err != nil {
		klog.V(log.DEBUG).Infof("Error link tunnel... :%v", err)
	}
	//ip link up dev
	if err := g.setUpDevice(); err != nil {
		klog.V(log.DEBUG).Infof("Error up device... : %v", err)
	}
	if err := initIPtables(remoteIP); err != nil {
		klog.V(log.DEBUG).Infof("Error create ipatbles ... : %v", err)
	}

	//sucess connect
	cable.RecordConnection(cableDriverName, &g.localEndpoint.Spec, &connection.Endpoint, string(v1.Connected), true)
	return remoteIP, nil
}

func (g *gre) DisconnectFromEndpoint(endpoint types.SubmarinerEndpoint) error {
	klog.Infof("Deleting connection to %v", endpoint)
	err := deleteTunnel()
	if err != nil {
		klog.Infof("Delete error...")
		return err
	}
	err = deleteIPtables(endpoint.Spec.PrivateIP)
	if err != nil {
		klog.Infof("Delete iptables err...")
		return err
	}

	return nil
}

func (g *gre) GetActiveConnections() ([]v1.Connection, error) {
	return make([]v1.Connection, 0), nil
}

func (g *gre) GetConnections() ([]v1.Connection, error) {

	return nil, nil
}

//---------------------------------------------------------------------------------------------------------------------------
//my func
func (g *gre) setTunnel(localIP string, remoteIP string) error {
	//create GRE tunnel
	binary, err := exec.LookPath("ip")
	if err != nil {
		klog.V(log.DEBUG).Infof("Error lookup IP path for set up... : %v", err)
		return err
	}

	args := []string{"ip", "tunnel", "add", DefaultDeviceName, "mode", "gre", "local", localIP, "remote", remoteIP, "ttl", "255"}

	env := os.Environ()

	err = syscall.Exec(binary, args, env)
	if err != nil {
		klog.V(log.DEBUG).Infof("Error call Ip Command... : %v", err)
		return err
	}
	return nil
}

func (g *gre) linkTunnel(globIP string) error {
	binary, err := exec.LookPath("ip")
	if err != nil {
		klog.V(log.DEBUG).Infof("Error lookup IP path for link... : %v", err)
		return err
	}

	args := []string{"ip", "addr", "add", globIP, "dev", DefaultDeviceName}

	env := os.Environ()

	err = syscall.Exec(binary, args, env)
	if err != nil {
		klog.V(log.DEBUG).Infof("Error call Ip Command...: %v", err)
		return err
	}
	return nil
}

func (g *gre) setUpDevice() error {
	binary, err := exec.LookPath("ip")
	if err != nil {
		klog.V(log.DEBUG).Infof("Error lookup IP path for link... : %v", err)
		return err
	}
	args := []string{"ip", "link", "set", DefaultDeviceName, "up"}
	env := os.Environ()
	err = syscall.Exec(binary, args, env)
	if err != nil {
		klog.V(log.DEBUG).Infof("Error device up... check your device status : %v", err)
		return err
	}
	return nil
}

func selectGlobalIP(ip string) bool {
	ips := strings.Split(ip, ".")
	res := 0
	for _, v := range ips {
		num, _ := strconv.Atoi(v)
		res += num % 2
	}
	if res%2 == 0 {
		return 0
	}
	return 1
}

func deleteTunnel() error {
	binary, err := exec.LookPath("ip")
	if err != nil {
		klog.V(log.DEBUG).Infof("Error lookup IP path for delete... : %v", err)
		return err
	}
	args := []string{"ip", "tuunel", "delete", DefaultDeviceName}
	env := os.Environ()
	err = syscall.Exec(binary, args, env)
	if err != nil {
		klog.V(log.DEBUG).Infof("Error device delete ... check your device status : %v", err)
		return err
	}
	return nil
}

func initIPtables(remoteIP string) error {
	err := ipCommand("iptables", []string{"iptables", "-A", "INPUT", "-p", "gre", "-s", remoteIP, "-j", "ACCEPT"})
	if err != nil {
		return err
	}
	err = ipCommand("iptables", []string{"iptables", "-A", "INPUT", "-i", "submariner", "-j", "ACCEPT"})
	if err != nil {
		return err
	}
	ipCommand("iptables", []string{"iptables", "-A", "INPUT", "-o", "submariner", "-j", "ACCEPT"})
	if err != nil {
		return err
	}
	return nil
}

func deleteIPtables(remoteIP string) error {
	err := ipCommand("iptables", []string{"iptables", "-D", "INPUT", "-p", "gre", "-s", remoteIP, "-j", "ACCEPT"})
	if err != nil {
		return err
	}
	err = ipCommand("iptables", []string{"iptables", "-D", "INPUT", "-i", "submariner", "-j", "ACCEPT"})
	if err != nil {
		return err
	}
	err = ipCommand("iptables", []string{"iptables", "-D", "INPUT", "-o", "submariner", "-j", "ACCEPT"})
	if err != nil {
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
