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
package controllers_test

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/format"
	"github.com/submariner-io/admiral/pkg/syncer/test"
	submarinerv1 "github.com/submariner-io/submariner/pkg/apis/submariner.io/v1"
	"github.com/submariner-io/submariner/pkg/globalnet/controllers"
	"github.com/submariner-io/submariner/pkg/ipam"
	"github.com/submariner-io/submariner/pkg/iptables"
	fakeIPT "github.com/submariner-io/submariner/pkg/iptables/fake"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/dynamic"
	fakeDynClient "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/klog"
	mcsv1a1 "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"
)

const (
	namespace           = "submariner"
	localCIDR           = "169.254.1.0/24"
	globalEgressIPName  = "east-region"
	globalIngressIPName = "db-service-ingress-ip"
	serviceName         = "nginx"
)

func init() {
	klog.InitFlags(nil)

	_ = submarinerv1.AddToScheme(scheme.Scheme)
	_ = mcsv1a1.AddToScheme(scheme.Scheme)
}

func TestControllers(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Globalnet Controllers Suite")
}

type testDriverBase struct {
	controller             controllers.Interface
	restMapper             meta.RESTMapper
	dynClient              dynamic.Interface
	scheme                 *runtime.Scheme
	ipt                    *fakeIPT.IPTables
	pool                   *ipam.IPPool
	localSubnets           []string
	globalCIDR             string
	globalEgressIPs        dynamic.ResourceInterface
	clusterGlobalEgressIPs dynamic.ResourceInterface
	globalIngressIPs       dynamic.ResourceInterface
	services               dynamic.ResourceInterface
	serviceExports         dynamic.ResourceInterface
	pods                   dynamic.NamespaceableResourceInterface
}

func newTestDriverBase() *testDriverBase {
	t := &testDriverBase{
		restMapper: test.GetRESTMapperFor(&submarinerv1.Endpoint{}, &corev1.Service{}, &corev1.Node{}, &corev1.Pod{},
			&submarinerv1.GlobalEgressIP{}, &submarinerv1.ClusterGlobalEgressIP{}, &submarinerv1.GlobalIngressIP{}, &mcsv1a1.ServiceExport{}),
		scheme:       runtime.NewScheme(),
		ipt:          fakeIPT.New(),
		globalCIDR:   localCIDR,
		localSubnets: []string{},
	}

	Expect(mcsv1a1.AddToScheme(t.scheme)).To(Succeed())
	Expect(submarinerv1.AddToScheme(t.scheme)).To(Succeed())
	Expect(corev1.AddToScheme(t.scheme)).To(Succeed())

	t.dynClient = fakeDynClient.NewSimpleDynamicClient(t.scheme)

	t.globalEgressIPs = t.dynClient.Resource(*test.GetGroupVersionResourceFor(t.restMapper, &submarinerv1.GlobalEgressIP{})).
		Namespace(namespace)

	t.globalIngressIPs = t.dynClient.Resource(*test.GetGroupVersionResourceFor(t.restMapper, &submarinerv1.GlobalIngressIP{})).
		Namespace(namespace)

	t.clusterGlobalEgressIPs = t.dynClient.Resource(*test.GetGroupVersionResourceFor(t.restMapper, &submarinerv1.ClusterGlobalEgressIP{}))

	t.pods = t.dynClient.Resource(*test.GetGroupVersionResourceFor(t.restMapper, &corev1.Pod{}))

	t.services = t.dynClient.Resource(*test.GetGroupVersionResourceFor(t.restMapper, &corev1.Service{})).Namespace(namespace)

	t.serviceExports = t.dynClient.Resource(*test.GetGroupVersionResourceFor(t.restMapper, &mcsv1a1.ServiceExport{})).Namespace(namespace)

	iptables.NewFunc = func() (iptables.Interface, error) {
		return t.ipt, nil
	}

	return t
}

func (t *testDriverBase) afterEach() {
	t.controller.Stop()

	iptables.NewFunc = nil
}

func (t *testDriverBase) verifyIPsReservedInPool(ips ...string) {
	if t.pool == nil {
		return
	}

	for _, ip := range ips {
		Expect(t.pool.Reserve(ip)).To(HaveOccurred(), "IP %s was not reserved", ip)
	}
}

func (t *testDriverBase) awaitIPsReleasedFromPool(ips ...string) {
	Eventually(func() error {
		return t.pool.Reserve(ips...)
	}, 3*time.Second).Should(Succeed())
}

func (t *testDriverBase) createGlobalEgressIP(egressIP *submarinerv1.GlobalEgressIP) {
	test.CreateResource(t.globalEgressIPs, egressIP)
}

func (t *testDriverBase) createClusterGlobalEgressIP(egressIP *submarinerv1.ClusterGlobalEgressIP) {
	test.CreateResource(t.clusterGlobalEgressIPs, egressIP)
}

func (t *testDriverBase) createGlobalIngressIP(egressIP *submarinerv1.GlobalIngressIP) {
	test.CreateResource(t.globalIngressIPs, egressIP)
}

// nolint unparam - `name` always receives `globalEgressIPName`
func (t *testDriverBase) awaitGlobalEgressIPStatusAllocated(name string, expNumIPS int) {
	t.awaitEgressIPStatusAllocated(t.globalEgressIPs, name, expNumIPS)
}

func (t *testDriverBase) awaitClusterGlobalEgressIPStatusAllocated(expNumIPS int) {
	t.awaitEgressIPStatusAllocated(t.clusterGlobalEgressIPs, controllers.ClusterGlobalEgressIPName, expNumIPS)
}

func (t *testDriverBase) createPod(p *corev1.Pod) *corev1.Pod {
	return fromUnstructured(test.CreateResource(t.pods.Namespace(p.Namespace), p), &corev1.Pod{}).(*corev1.Pod)
}

func (t *testDriverBase) deletePod(p *corev1.Pod) {
	Expect(t.pods.Namespace(p.Namespace).Delete(context.TODO(), p.Name, metav1.DeleteOptions{})).To(Succeed())
}

func (t *testDriverBase) createService(service *corev1.Service) *corev1.Service {
	test.CreateResource(t.services, service)
	return service
}

func (t *testDriverBase) createServiceExport(s *corev1.Service) {
	test.CreateResource(t.serviceExports, &mcsv1a1.ServiceExport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      s.GetName(),
			Namespace: s.GetNamespace(),
		},
	})
}

func (t *testDriverBase) getGlobalIngressIPStatus(name string) *submarinerv1.GlobalIngressIPStatus {
	status := &submarinerv1.GlobalIngressIPStatus{}
	getStatus(t.globalIngressIPs, name, status)

	return status
}

func getStatus(client dynamic.ResourceInterface, name string, status interface{}) {
	obj, err := client.Get(context.TODO(), name, metav1.GetOptions{})
	Expect(err).To(Succeed())

	statusObj, ok, err := unstructured.NestedMap(obj.Object, "status")
	Expect(err).To(Succeed())

	if !ok {
		return
	}

	Expect(runtime.DefaultUnstructuredConverter.FromUnstructured(statusObj, status)).To(Succeed())
}

func getGlobalEgressIPStatus(client dynamic.ResourceInterface, name string) *submarinerv1.GlobalEgressIPStatus {
	status := &submarinerv1.GlobalEgressIPStatus{}
	getStatus(client, name, status)

	return status
}

func awaitNoAllocatedIPs(client dynamic.ResourceInterface, name string) {
	Consistently(func() int {
		status := getGlobalEgressIPStatus(client, name)
		if status == nil {
			return 0
		}

		return len(status.AllocatedIPs)
	}, 200*time.Millisecond).Should(Equal(0))
}

// nolint unparam - `atIndex` always receives `0` - remove once a caller passes non-zero
func (t *testDriverBase) awaitEgressIPStatus(client dynamic.ResourceInterface, name string, expNumIPS int, atIndex int,
	expCond ...metav1.Condition) {
	awaitStatusConditions(client, name, atIndex, expCond...)

	status := getGlobalEgressIPStatus(client, name)

	Expect(status.AllocatedIPs).To(HaveLen(expNumIPS))

	for _, ip := range status.AllocatedIPs {
		Expect(isValidIPForCIDR(t.globalCIDR, ip)).To(BeTrue(), "Allocated global IP %q is not valid for CIDR %q",
			ip, t.globalCIDR)
	}

	t.verifyIPsReservedInPool(status.AllocatedIPs...)
}

func (t *testDriverBase) awaitEgressIPStatusAllocated(client dynamic.ResourceInterface, name string, expNumIPS int) {
	t.awaitEgressIPStatus(client, name, expNumIPS, 0, metav1.Condition{
		Type:   string(submarinerv1.GlobalEgressIPAllocated),
		Status: metav1.ConditionTrue,
	})
}

// nolint unparam - `atIndex` always receives `0` - remove once a caller passes non-zero
func (t *testDriverBase) awaitIngressIPStatus(name string, atIndex int, expCond ...metav1.Condition) {
	awaitStatusConditions(t.globalIngressIPs, name, atIndex, expCond...)

	status := t.getGlobalIngressIPStatus(name)

	Expect(status.AllocatedIP).ToNot(BeEmpty())
	Expect(isValidIPForCIDR(t.globalCIDR, status.AllocatedIP)).To(BeTrue(), "Allocated global IP %q is not valid for CIDR %q",
		status.AllocatedIP, t.globalCIDR)

	t.verifyIPsReservedInPool(status.AllocatedIP)
}

func (t *testDriverBase) awaitIngressIPStatusAllocated(name string) {
	t.awaitIngressIPStatus(name, 0, metav1.Condition{
		Type:   string(submarinerv1.GlobalEgressIPAllocated),
		Status: metav1.ConditionTrue,
	})
}

func (t *testDriverBase) awaitGlobalIngressIP(name string) *submarinerv1.GlobalIngressIP {
	obj := test.AwaitResource(t.globalIngressIPs, name)

	gip := &submarinerv1.GlobalIngressIP{}
	Expect(runtime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, gip)).To(Succeed())

	return gip
}

// nolint unparam - `name` always receives `serviceName` (`"nginx"`)
func (t *testDriverBase) awaitNoGlobalIngressIP(name string) {
	time.Sleep(300 * time.Millisecond)
	test.AwaitNoResource(t.globalIngressIPs, name)
}

func awaitStatusConditions(client dynamic.ResourceInterface, name string, atIndex int, expCond ...metav1.Condition) {
	var conditions []metav1.Condition
	var notFound error

	err := wait.PollImmediate(50*time.Millisecond, 5*time.Second, func() (bool, error) {
		obj, err := client.Get(context.TODO(), name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			notFound = err
			return false, nil
		}

		notFound = nil

		if err != nil {
			return false, err
		}

		slice, ok, err := unstructured.NestedSlice(obj.Object, "status", "conditions")
		if !ok || err != nil {
			return false, err
		}

		conditions = make([]metav1.Condition, len(slice))
		for i := range slice {
			c := &metav1.Condition{}
			err = runtime.DefaultUnstructuredConverter.FromUnstructured(slice[i].(map[string]interface{}), c)
			if err != nil {
				return false, err
			}

			conditions[i] = *c
		}

		if (atIndex + len(expCond)) != len(conditions) {
			return false, nil
		}

		return true, nil
	})

	if notFound != nil {
		Fail(fmt.Sprintf("%#v", notFound))
		return
	}

	if err == wait.ErrWaitTimeout {
		if conditions == nil {
			Fail("Status conditions not found")
		}

		Fail(format.Message(conditions, fmt.Sprintf("to contain at index %d", atIndex), expCond))

		return
	}

	Expect(err).To(Succeed())

	j := atIndex

	for _, exp := range expCond {
		actual := conditions[j]
		j++

		Expect(actual.Type).To(Equal(exp.Type))
		Expect(actual.Status).To(Equal(exp.Status))
		Expect(actual.LastTransitionTime).To(Not(BeNil()))
		Expect(actual.Message).To(Not(BeEmpty()))

		if exp.Reason != "" {
			Expect(actual.Reason).To(Equal(exp.Reason))
		} else {
			Expect(actual.Reason).To(Not(BeEmpty()))
		}
	}
}

// nolint unparam - `name` always receives `globalEgressIPName` (`"east-region")
func newGlobalEgressIP(name string, numberOfIPs *int, podSelector *metav1.LabelSelector) *submarinerv1.GlobalEgressIP {
	return &submarinerv1.GlobalEgressIP{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: submarinerv1.GlobalEgressIPSpec{
			NumberOfIPs: numberOfIPs,
			PodSelector: podSelector,
		},
	}
}

func newClusterGlobalEgressIP(name string, numIPs int) *submarinerv1.ClusterGlobalEgressIP {
	return &submarinerv1.ClusterGlobalEgressIP{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: submarinerv1.ClusterGlobalEgressIPSpec{
			NumberOfIPs: &numIPs,
		},
	}
}

func newPod(namespace string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nginx",
			Namespace: namespace,
		},
		Status: corev1.PodStatus{
			PodIP: "1.2.3.4",
		},
	}
}

func newClusterIPService() *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: serviceName,
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: "1.2.3.4",
			Type:      corev1.ServiceTypeClusterIP,
		},
	}
}

func newHeadlessService(name string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: corev1.ClusterIPNone,
			Type:      corev1.ServiceTypeClusterIP,
		},
	}
}

func isValidIPForCIDR(cidr, ip string) bool {
	_, ipnet, err := net.ParseCIDR(cidr)
	Expect(err).NotTo(HaveOccurred())

	return ipnet.Contains(net.ParseIP(ip))
}

func fromUnstructured(from *unstructured.Unstructured, to runtime.Object) runtime.Object {
	err := runtime.DefaultUnstructuredConverter.FromUnstructured(from.Object, to)
	Expect(err).To(Succeed())

	return to
}
