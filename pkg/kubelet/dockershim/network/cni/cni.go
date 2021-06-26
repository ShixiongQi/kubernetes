// +build !dockerless

/*
Copyright 2014 The Kubernetes Authors.

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

package cni

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/containernetworking/cni/libcni"
	cnitypes "github.com/containernetworking/cni/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1alpha2"
	"k8s.io/klog/v2"
	kubeletconfig "k8s.io/kubernetes/pkg/kubelet/apis/config"
	kubecontainer "k8s.io/kubernetes/pkg/kubelet/container"
	"k8s.io/kubernetes/pkg/kubelet/dockershim/network"
	"k8s.io/kubernetes/pkg/util/bandwidth"
	utilslice "k8s.io/kubernetes/pkg/util/slice"
	utilexec "k8s.io/utils/exec"
	// package for ebpf
	// "net"
	"log"
	osexec "os/exec"
	"os"
	"runtime"
	"syscall"
	"bytes"
	"net/http"

	"golang.org/x/sys/unix"
)

const (
	// CNIPluginName is the name of CNI plugin
	CNIPluginName = "cni"

	// defaultSyncConfigPeriod is the default period to sync CNI config
	// TODO: consider making this value configurable or to be a more appropriate value.
	defaultSyncConfigPeriod = time.Second * 5

	// supported capabilities
	// https://github.com/containernetworking/cni/blob/master/CONVENTIONS.md
	portMappingsCapability = "portMappings"
	ipRangesCapability     = "ipRanges"
	bandwidthCapability    = "bandwidth"
	dnsCapability          = "dns"
)

type cniNetworkPlugin struct {
	network.NoopNetworkPlugin

	loNetwork *cniNetwork

	sync.RWMutex
	defaultNetwork *cniNetwork

	host        network.Host
	execer      utilexec.Interface
	nsenterPath string
	confDir     string
	binDirs     []string
	cacheDir    string
	podCidr     string
}

type cniNetwork struct {
	name          string
	NetworkConfig *libcni.NetworkConfigList
	CNIConfig     libcni.CNI
	Capabilities  []string
}

// cniPortMapping maps to the standard CNI portmapping Capability
// see: https://github.com/containernetworking/cni/blob/master/CONVENTIONS.md
type cniPortMapping struct {
	HostPort      int32  `json:"hostPort"`
	ContainerPort int32  `json:"containerPort"`
	Protocol      string `json:"protocol"`
	HostIP        string `json:"hostIP"`
}

// cniBandwidthEntry maps to the standard CNI bandwidth Capability
// see: https://github.com/containernetworking/cni/blob/master/CONVENTIONS.md and
// https://github.com/containernetworking/plugins/blob/master/plugins/meta/bandwidth/README.md
type cniBandwidthEntry struct {
	// IngressRate is the bandwidth rate in bits per second for traffic through container. 0 for no limit. If IngressRate is set, IngressBurst must also be set
	IngressRate int `json:"ingressRate,omitempty"`
	// IngressBurst is the bandwidth burst in bits for traffic through container. 0 for no limit. If IngressBurst is set, IngressRate must also be set
	// NOTE: it's not used for now and defaults to 0. If IngressRate is set IngressBurst will be math.MaxInt32 ~ 2Gbit
	IngressBurst int `json:"ingressBurst,omitempty"`
	// EgressRate is the bandwidth is the bandwidth rate in bits per second for traffic through container. 0 for no limit. If EgressRate is set, EgressBurst must also be set
	EgressRate int `json:"egressRate,omitempty"`
	// EgressBurst is the bandwidth burst in bits for traffic through container. 0 for no limit. If EgressBurst is set, EgressRate must also be set
	// NOTE: it's not used for now and defaults to 0. If EgressRate is set EgressBurst will be math.MaxInt32 ~ 2Gbit
	EgressBurst int `json:"egressBurst,omitempty"`
}

// cniIPRange maps to the standard CNI ip range Capability
type cniIPRange struct {
	Subnet string `json:"subnet"`
}

// cniDNSConfig maps to the windows CNI dns Capability.
// see: https://github.com/containernetworking/cni/blob/master/CONVENTIONS.md
// Note that dns capability is only used for Windows containers.
type cniDNSConfig struct {
	// List of DNS servers of the cluster.
	Servers []string `json:"servers,omitempty"`
	// List of DNS search domains of the cluster.
	Searches []string `json:"searches,omitempty"`
	// List of DNS options.
	Options []string `json:"options,omitempty"`
}

// SplitDirs : split dirs by ","
func SplitDirs(dirs string) []string {
	// Use comma rather than colon to work better with Windows too
	return strings.Split(dirs, ",")
}

// ProbeNetworkPlugins : get the network plugin based on cni conf file and bin file
func ProbeNetworkPlugins(confDir, cacheDir string, binDirs []string) []network.NetworkPlugin {
	old := binDirs
	binDirs = make([]string, 0, len(binDirs))
	for _, dir := range old {
		if dir != "" {
			binDirs = append(binDirs, dir)
		}
	}

	plugin := &cniNetworkPlugin{
		defaultNetwork: nil,
		loNetwork:      getLoNetwork(binDirs),
		execer:         utilexec.New(),
		confDir:        confDir,
		binDirs:        binDirs,
		cacheDir:       cacheDir,
	}

	// sync NetworkConfig in best effort during probing.
	plugin.syncNetworkConfig()
	return []network.NetworkPlugin{plugin}
}

func getDefaultCNINetwork(confDir string, binDirs []string) (*cniNetwork, error) {
	files, err := libcni.ConfFiles(confDir, []string{".conf", ".conflist", ".json"})
	switch {
	case err != nil:
		return nil, err
	case len(files) == 0:
		return nil, fmt.Errorf("no networks found in %s", confDir)
	}

	cniConfig := &libcni.CNIConfig{Path: binDirs}

	sort.Strings(files)
	for _, confFile := range files {
		var confList *libcni.NetworkConfigList
		if strings.HasSuffix(confFile, ".conflist") {
			confList, err = libcni.ConfListFromFile(confFile)
			if err != nil {
				klog.Warningf("Error loading CNI config list file %s: %v", confFile, err)
				continue
			}
		} else {
			conf, err := libcni.ConfFromFile(confFile)
			if err != nil {
				klog.Warningf("Error loading CNI config file %s: %v", confFile, err)
				continue
			}
			// Ensure the config has a "type" so we know what plugin to run.
			// Also catches the case where somebody put a conflist into a conf file.
			if conf.Network.Type == "" {
				klog.Warningf("Error loading CNI config file %s: no 'type'; perhaps this is a .conflist?", confFile)
				continue
			}

			confList, err = libcni.ConfListFromConf(conf)
			if err != nil {
				klog.Warningf("Error converting CNI config file %s to list: %v", confFile, err)
				continue
			}
		}
		if len(confList.Plugins) == 0 {
			klog.Warningf("CNI config list %s has no networks, skipping", string(confList.Bytes[:maxStringLengthInLog(len(confList.Bytes))]))
			continue
		}

		// Before using this CNI config, we have to validate it to make sure that
		// all plugins of this config exist on disk
		caps, err := cniConfig.ValidateNetworkList(context.TODO(), confList)
		if err != nil {
			klog.Warningf("Error validating CNI config list %s: %v", string(confList.Bytes[:maxStringLengthInLog(len(confList.Bytes))]), err)
			continue
		}

		klog.V(4).Infof("Using CNI configuration file %s", confFile)

		return &cniNetwork{
			name:          confList.Name,
			NetworkConfig: confList,
			CNIConfig:     cniConfig,
			Capabilities:  caps,
		}, nil
	}
	return nil, fmt.Errorf("no valid networks found in %s", confDir)
}

func (plugin *cniNetworkPlugin) Init(host network.Host, hairpinMode kubeletconfig.HairpinMode, nonMasqueradeCIDR string, mtu int) error {
	err := plugin.platformInit()
	if err != nil {
		return err
	}

	plugin.host = host

	plugin.syncNetworkConfig()

	// start a goroutine to sync network config from confDir periodically to detect network config updates in every 5 seconds
	go wait.Forever(plugin.syncNetworkConfig, defaultSyncConfigPeriod)

	return nil
}

func (plugin *cniNetworkPlugin) syncNetworkConfig() {
	network, err := getDefaultCNINetwork(plugin.confDir, plugin.binDirs)
	if err != nil {
		klog.Warningf("Unable to update cni config: %s", err)
		return
	}
	plugin.setDefaultNetwork(network)
}

func (plugin *cniNetworkPlugin) getDefaultNetwork() *cniNetwork {
	plugin.RLock()
	defer plugin.RUnlock()
	return plugin.defaultNetwork
}

func (plugin *cniNetworkPlugin) setDefaultNetwork(n *cniNetwork) {
	plugin.Lock()
	defer plugin.Unlock()
	plugin.defaultNetwork = n
}

func (plugin *cniNetworkPlugin) checkInitialized() error {
	if plugin.getDefaultNetwork() == nil {
		return fmt.Errorf("cni config uninitialized")
	}

	if utilslice.ContainsString(plugin.getDefaultNetwork().Capabilities, ipRangesCapability, nil) && plugin.podCidr == "" {
		return fmt.Errorf("cni config needs ipRanges but no PodCIDR set")
	}

	return nil
}

// Event handles any change events. The only event ever sent is the PodCIDR change.
// No network plugins support changing an already-set PodCIDR
func (plugin *cniNetworkPlugin) Event(name string, details map[string]interface{}) {
	if name != network.NET_PLUGIN_EVENT_POD_CIDR_CHANGE {
		return
	}

	plugin.Lock()
	defer plugin.Unlock()

	podCIDR, ok := details[network.NET_PLUGIN_EVENT_POD_CIDR_CHANGE_DETAIL_CIDR].(string)
	if !ok {
		klog.Warningf("%s event didn't contain pod CIDR", network.NET_PLUGIN_EVENT_POD_CIDR_CHANGE)
		return
	}

	if plugin.podCidr != "" {
		klog.Warningf("Ignoring subsequent pod CIDR update to %s", podCIDR)
		return
	}

	plugin.podCidr = podCIDR
}

func (plugin *cniNetworkPlugin) Name() string {
	return CNIPluginName
}

func (plugin *cniNetworkPlugin) Status() error {
	// Can't set up pods if we don't have any CNI network configs yet
	return plugin.checkInitialized()
}

func (plugin *cniNetworkPlugin) SetUpPod(namespace string, name string, id kubecontainer.ContainerID, annotations, options map[string]string) error {
	if err := plugin.checkInitialized(); err != nil {
		return err
	}
	netnsPath, err := plugin.host.GetNetNS(id.ID)
	if err != nil {
		return fmt.Errorf("CNI failed to retrieve network namespace path: %v", err)
	}

	// Todo get the timeout from parent ctx
	cniTimeoutCtx, cancelFunc := context.WithTimeout(context.Background(), network.CNITimeoutSec*time.Second)
	defer cancelFunc()
	// Windows doesn't have loNetwork. It comes only with Linux
	if plugin.loNetwork != nil {
		if _, err = plugin.addToNetwork(cniTimeoutCtx, plugin.loNetwork, name, namespace, id, netnsPath, annotations, options); err != nil {
			return err
		}
	}

	_, err = plugin.addToNetwork(cniTimeoutCtx, plugin.getDefaultNetwork(), name, namespace, id, netnsPath, annotations, options)
	klog.InfoS("kubelet attaches the eProxy to the Pod Sandbox")
	err = WithNetNSPath(netnsPath, func(hostNS 	NetNS) error {
		// iface, err := net.InterfaceByName("eth0")
		cmd := osexec.Command("ip", "link", "show", "dev", "eth0")
		stdout, err := cmd.Output()
		if err != nil {
			log.Fatal(err)
			return err
		}
		// if err := cmd.Start(); err != nil {
		// 	log.Fatal(err)
		// 	return err
		// }
		// if err := cmd.Wait(); err != nil {
		// 	log.Fatal(err)
		// 	return err
		// }
		fmt.Printf("eproxy: %s\n", stdout)
		parts := strings.Split(string(stdout), "@if")[1]
		ifidx := strings.Split(parts, ": <")[0]
		fmt.Printf("veth ifidx: %s\n", ifidx)
		// TODO: Send ifidx to the eproxy loader
		vethIdx := []byte(ifidx)
		_, err = http.Post("http://localhost:2222", "text/plain", bytes.NewBuffer(vethIdx))
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("veth ifidx posted to eproxy\n")
		return nil
	})
	return err
}

func (plugin *cniNetworkPlugin) TearDownPod(namespace string, name string, id kubecontainer.ContainerID) error {
	if err := plugin.checkInitialized(); err != nil {
		return err
	}

	// Lack of namespace should not be fatal on teardown
	netnsPath, err := plugin.host.GetNetNS(id.ID)
	if err != nil {
		klog.Warningf("CNI failed to retrieve network namespace path: %v", err)
	}

	// Todo get the timeout from parent ctx
	cniTimeoutCtx, cancelFunc := context.WithTimeout(context.Background(), network.CNITimeoutSec*time.Second)
	defer cancelFunc()
	// Windows doesn't have loNetwork. It comes only with Linux
	if plugin.loNetwork != nil {
		// Loopback network deletion failure should not be fatal on teardown
		if err := plugin.deleteFromNetwork(cniTimeoutCtx, plugin.loNetwork, name, namespace, id, netnsPath, nil); err != nil {
			klog.Warningf("CNI failed to delete loopback network: %v", err)
		}
	}

	return plugin.deleteFromNetwork(cniTimeoutCtx, plugin.getDefaultNetwork(), name, namespace, id, netnsPath, nil)
}

func podDesc(namespace, name string, id kubecontainer.ContainerID) string {
	return fmt.Sprintf("%s_%s/%s", namespace, name, id.ID)
}

func (plugin *cniNetworkPlugin) addToNetwork(ctx context.Context, network *cniNetwork, podName string, podNamespace string, podSandboxID kubecontainer.ContainerID, podNetnsPath string, annotations, options map[string]string) (cnitypes.Result, error) {
	rt, err := plugin.buildCNIRuntimeConf(podName, podNamespace, podSandboxID, podNetnsPath, annotations, options)
	if err != nil {
		klog.Errorf("Error adding network when building cni runtime conf: %v", err)
		return nil, err
	}

	pdesc := podDesc(podNamespace, podName, podSandboxID)
	netConf, cniNet := network.NetworkConfig, network.CNIConfig
	klog.V(4).Infof("Adding %s to network %s/%s netns %q", pdesc, netConf.Plugins[0].Network.Type, netConf.Name, podNetnsPath)
	res, err := cniNet.AddNetworkList(ctx, netConf, rt)
	if err != nil {
		klog.Errorf("Error adding %s to network %s/%s: %v", pdesc, netConf.Plugins[0].Network.Type, netConf.Name, err)
		return nil, err
	}
	klog.V(4).Infof("Added %s to network %s: %v", pdesc, netConf.Name, res)
	return res, nil
}

func (plugin *cniNetworkPlugin) deleteFromNetwork(ctx context.Context, network *cniNetwork, podName string, podNamespace string, podSandboxID kubecontainer.ContainerID, podNetnsPath string, annotations map[string]string) error {
	rt, err := plugin.buildCNIRuntimeConf(podName, podNamespace, podSandboxID, podNetnsPath, annotations, nil)
	if err != nil {
		klog.Errorf("Error deleting network when building cni runtime conf: %v", err)
		return err
	}

	pdesc := podDesc(podNamespace, podName, podSandboxID)
	netConf, cniNet := network.NetworkConfig, network.CNIConfig
	klog.V(4).Infof("Deleting %s from network %s/%s netns %q", pdesc, netConf.Plugins[0].Network.Type, netConf.Name, podNetnsPath)
	err = cniNet.DelNetworkList(ctx, netConf, rt)
	// The pod may not get deleted successfully at the first time.
	// Ignore "no such file or directory" error in case the network has already been deleted in previous attempts.
	if err != nil && !strings.Contains(err.Error(), "no such file or directory") {
		klog.Errorf("Error deleting %s from network %s/%s: %v", pdesc, netConf.Plugins[0].Network.Type, netConf.Name, err)
		return err
	}
	klog.V(4).Infof("Deleted %s from network %s/%s", pdesc, netConf.Plugins[0].Network.Type, netConf.Name)
	return nil
}

func (plugin *cniNetworkPlugin) buildCNIRuntimeConf(podName string, podNs string, podSandboxID kubecontainer.ContainerID, podNetnsPath string, annotations, options map[string]string) (*libcni.RuntimeConf, error) {
	rt := &libcni.RuntimeConf{
		ContainerID: podSandboxID.ID,
		NetNS:       podNetnsPath,
		IfName:      network.DefaultInterfaceName,
		CacheDir:    plugin.cacheDir,
		Args: [][2]string{
			{"IgnoreUnknown", "1"},
			{"K8S_POD_NAMESPACE", podNs},
			{"K8S_POD_NAME", podName},
			{"K8S_POD_INFRA_CONTAINER_ID", podSandboxID.ID},
		},
	}

	// port mappings are a cni capability-based args, rather than parameters
	// to a specific plugin
	portMappings, err := plugin.host.GetPodPortMappings(podSandboxID.ID)
	if err != nil {
		return nil, fmt.Errorf("could not retrieve port mappings: %v", err)
	}
	portMappingsParam := make([]cniPortMapping, 0, len(portMappings))
	for _, p := range portMappings {
		if p.HostPort <= 0 {
			continue
		}
		portMappingsParam = append(portMappingsParam, cniPortMapping{
			HostPort:      p.HostPort,
			ContainerPort: p.ContainerPort,
			Protocol:      strings.ToLower(string(p.Protocol)),
			HostIP:        p.HostIP,
		})
	}
	rt.CapabilityArgs = map[string]interface{}{
		portMappingsCapability: portMappingsParam,
	}

	ingress, egress, err := bandwidth.ExtractPodBandwidthResources(annotations)
	if err != nil {
		return nil, fmt.Errorf("failed to get pod bandwidth from annotations: %v", err)
	}
	if ingress != nil || egress != nil {
		bandwidthParam := cniBandwidthEntry{}
		if ingress != nil {
			// see: https://github.com/containernetworking/cni/blob/master/CONVENTIONS.md and
			// https://github.com/containernetworking/plugins/blob/master/plugins/meta/bandwidth/README.md
			// Rates are in bits per second, burst values are in bits.
			bandwidthParam.IngressRate = int(ingress.Value())
			// Limit IngressBurst to math.MaxInt32, in practice limiting to 2Gbit is the equivalent of setting no limit
			bandwidthParam.IngressBurst = math.MaxInt32
		}
		if egress != nil {
			bandwidthParam.EgressRate = int(egress.Value())
			// Limit EgressBurst to math.MaxInt32, in practice limiting to 2Gbit is the equivalent of setting no limit
			bandwidthParam.EgressBurst = math.MaxInt32
		}
		rt.CapabilityArgs[bandwidthCapability] = bandwidthParam
	}

	// Set the PodCIDR
	rt.CapabilityArgs[ipRangesCapability] = [][]cniIPRange{{{Subnet: plugin.podCidr}}}

	// Set dns capability args.
	if dnsOptions, ok := options["dns"]; ok {
		dnsConfig := runtimeapi.DNSConfig{}
		err := json.Unmarshal([]byte(dnsOptions), &dnsConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal dns config %q: %v", dnsOptions, err)
		}
		if dnsParam := buildDNSCapabilities(&dnsConfig); dnsParam != nil {
			rt.CapabilityArgs[dnsCapability] = *dnsParam
		}
	}

	return rt, nil
}

func maxStringLengthInLog(length int) int {
	// we allow no more than 4096-length strings to be logged
	const maxStringLength = 4096

	if length < maxStringLength {
		return length
	}
	return maxStringLength
}

// Returns an object representing the current OS thread's network namespace
func GetCurrentNS() (NetNS, error) {
	// Lock the thread in case other goroutine executes in it and changes its
	// network namespace after getCurrentThreadNetNSPath(), otherwise it might
	// return an unexpected network namespace.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	return GetNS(getCurrentThreadNetNSPath())
}

func getCurrentThreadNetNSPath() string {
	// /proc/self/ns/net returns the namespace of the main thread, not
	// of whatever thread this goroutine is running on.  Make sure we
	// use the thread's net namespace since the thread is switching around
	return fmt.Sprintf("/proc/%d/task/%d/ns/net", os.Getpid(), unix.Gettid())
}

func (ns *netNS) Close() error {
	if err := ns.errorIfClosed(); err != nil {
		return err
	}

	if err := ns.file.Close(); err != nil {
		return fmt.Errorf("Failed to close %q: %v", ns.file.Name(), err)
	}
	ns.closed = true

	return nil
}

func (ns *netNS) Set() error {
	if err := ns.errorIfClosed(); err != nil {
		return err
	}

	if err := unix.Setns(int(ns.Fd()), unix.CLONE_NEWNET); err != nil {
		return fmt.Errorf("Error switching to ns %v: %v", ns.file.Name(), err)
	}

	return nil
}

type NetNS interface {
	// Executes the passed closure in this object's network namespace,
	// attempting to restore the original namespace before returning.
	// However, since each OS thread can have a different network namespace,
	// and Go's thread scheduling is highly variable, callers cannot
	// guarantee any specific namespace is set unless operations that
	// require that namespace are wrapped with Do().  Also, no code called
	// from Do() should call runtime.UnlockOSThread(), or the risk
	// of executing code in an incorrect namespace will be greater.  See
	// https://github.com/golang/go/wiki/LockOSThread for further details.
	Do(toRun func(NetNS) error) error

	// Sets the current network namespace to this object's network namespace.
	// Note that since Go's thread scheduling is highly variable, callers
	// cannot guarantee the requested namespace will be the current namespace
	// after this function is called; to ensure this wrap operations that
	// require the namespace with Do() instead.
	Set() error

	// Returns the filesystem path representing this object's network namespace
	Path() string

	// Returns a file descriptor representing this object's network namespace
	Fd() uintptr

	// Cleans up this instance of the network namespace; if this instance
	// is the last user the namespace will be destroyed
	Close() error
}

type netNS struct {
	file   *os.File
	closed bool
}

// netNS implements the NetNS interface
var _ NetNS = &netNS{}

const (
	// https://github.com/torvalds/linux/blob/master/include/uapi/linux/magic.h
	NSFS_MAGIC   = 0x6e736673
	PROCFS_MAGIC = 0x9fa0
)

type NSPathNotExistErr struct{ msg string }

func (e NSPathNotExistErr) Error() string { return e.msg }

type NSPathNotNSErr struct{ msg string }

func (e NSPathNotNSErr) Error() string { return e.msg }

func IsNSorErr(nspath string) error {
	stat := syscall.Statfs_t{}
	if err := syscall.Statfs(nspath, &stat); err != nil {
		if os.IsNotExist(err) {
			err = NSPathNotExistErr{msg: fmt.Sprintf("failed to Statfs %q: %v", nspath, err)}
		} else {
			err = fmt.Errorf("failed to Statfs %q: %v", nspath, err)
		}
		return err
	}

	switch stat.Type {
	case PROCFS_MAGIC, NSFS_MAGIC:
		return nil
	default:
		return NSPathNotNSErr{msg: fmt.Sprintf("unknown FS magic on %q: %x", nspath, stat.Type)}
	}
}

// Returns an object representing the namespace referred to by @path
func GetNS(nspath string) (NetNS, error) {
	err := IsNSorErr(nspath)
	if err != nil {
		return nil, err
	}

	fd, err := os.Open(nspath)
	if err != nil {
		return nil, err
	}

	return &netNS{file: fd}, nil
}

func (ns *netNS) Path() string {
	return ns.file.Name()
}

func (ns *netNS) Fd() uintptr {
	return ns.file.Fd()
}

func (ns *netNS) errorIfClosed() error {
	if ns.closed {
		return fmt.Errorf("%q has already been closed", ns.file.Name())
	}
	return nil
}

func (ns *netNS) Do(toRun func(NetNS) error) error {
	if err := ns.errorIfClosed(); err != nil {
		return err
	}

	containedCall := func(hostNS NetNS) error {
		threadNS, err := GetCurrentNS()
		if err != nil {
			return fmt.Errorf("failed to open current netns: %v", err)
		}
		defer threadNS.Close()

		// switch to target namespace
		if err = ns.Set(); err != nil {
			return fmt.Errorf("error switching to ns %v: %v", ns.file.Name(), err)
		}
		defer func() {
			err := threadNS.Set() // switch back
			if err == nil {
				// Unlock the current thread only when we successfully switched back
				// to the original namespace; otherwise leave the thread locked which
				// will force the runtime to scrap the current thread, that is maybe
				// not as optimal but at least always safe to do.
				runtime.UnlockOSThread()
			}
		}()

		return toRun(hostNS)
	}

	// save a handle to current network namespace
	hostNS, err := GetCurrentNS()
	if err != nil {
		return fmt.Errorf("Failed to open current namespace: %v", err)
	}
	defer hostNS.Close()

	var wg sync.WaitGroup
	wg.Add(1)

	// Start the callback in a new green thread so that if we later fail
	// to switch the namespace back to the original one, we can safely
	// leave the thread locked to die without a risk of the current thread
	// left lingering with incorrect namespace.
	var innerError error
	go func() {
		defer wg.Done()
		runtime.LockOSThread()
		innerError = containedCall(hostNS)
	}()
	wg.Wait()

	return innerError
}

// WithNetNSPath executes the passed closure under the given network
// namespace, restoring the original namespace afterwards.
func WithNetNSPath(nspath string, toRun func(NetNS) error) error {
	ns, err := GetNS(nspath)
	if err != nil {
		return err
	}
	defer ns.Close()
	return ns.Do(toRun)
}