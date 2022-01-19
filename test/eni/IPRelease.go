// SPDX-License-Identifier: Apache-2.0
// Copyright 2020-2021 Authors of Cilium

package eniTest

import (
	"fmt"
	"os"
	"time"

	"github.com/cilium/cilium/pkg/logging"
	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"
	"github.com/cilium/cilium/test/nodegroups"

	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	"gopkg.in/check.v1"
)

func getAllocatedIPsOnNode(kubectl *helpers.Kubectl, nodeName string) (int, error) {
	cn := kubectl.GetCiliumNode(nodeName)
	if cn == nil {
		return 0, fmt.Errorf("Unable to fetch cn %s", nodeName)
	}
	return len(cn.Spec.IPAM.Pool), nil
}

func hasRequiredIPsAllocated(kubectl *helpers.Kubectl, nodeName string, n int) func() bool {
	return func() bool {
		cn := kubectl.GetCiliumNode(nodeName)
		if cn == nil {
			return false
		}
		return len(cn.Spec.IPAM.Pool) == n
	}
}

func hasRequiredIPBuffer(kubectl *helpers.Kubectl, nodeName string, n int) func() bool {
	return func() bool {
		cn := kubectl.GetCiliumNode(nodeName)
		if cn == nil {
			return false
		}
		return (len(cn.Spec.IPAM.Pool) - len(cn.Status.IPAM.Used)) == n
	}
}

func hasIPsInHandshake(kubectl *helpers.Kubectl, nodeName string) func() bool {
	return func() bool {
		cn := kubectl.GetCiliumNode(nodeName)
		if cn == nil {
			return false
		}
		return len(cn.Status.IPAM.ReleaseIPs) > 0
	}
}

func hasNoIPsInHandshake(kubectl *helpers.Kubectl, nodeName string) func() bool {
	return func() bool {
		cn := kubectl.GetCiliumNode(nodeName)
		if cn == nil {
			return false
		}
		return len(cn.Status.IPAM.ReleaseIPs) == 0
	}
}

var _ = Describe("EniIPReleaseHandshakeTest", func() {
	var (
		kubectl           *helpers.Kubectl
		ciliumCli         *helpers.CiliumCli
		deploymentManager *helpers.DeploymentManager
		releaseTestNs     = "cilium-integration-tests"
	)

	BeforeAll(func() {
		var log = logging.DefaultLogger
		var logger = logrus.NewEntry(log)
		kubectl = helpers.CreateKubectl("", logger)
		ciliumCli = helpers.CreateCiliumCli(logger)
		deploymentManager = helpers.NewDeploymentManager()
		deploymentManager.SetKubectl(kubectl)
	})

	AfterAll(func() {
		deploymentManager.DeleteAll()
	})

	AfterFailed(func() {
		kubectl.CiliumReport("cilium status", "cilium endpoint list")
	})

	JustAfterEach(func() {
		kubectl.ValidateNoErrorsInLogs(CurrentGinkgoTestDescription().Duration)
	})

	It("Test IP release abort", func() {
		By("Enabling aws excess IP release feature and restarting cilium operator")
		err := ciliumCli.UpdateCiliumConfig("aws-excess-ip-release", "true", false)
		Expect(err).NotTo(Equal(check.IsNil))

		// Workaround till cilium-cli supports restarting operator based on config change
		err = kubectl.RestartOperator()
		Expect(err).NotTo(Equal(check.IsNil))

		By("Create nodegroup to deploy tests on")
		ng := nodegroups.EksNodegroup{NodePool: nodegroups.NodePool{
			Name:          "ip-release",
			ClusterName:   os.Getenv("clusterName"),
			InstanceTypes: []string{"t3.medium", "t3a.medium"},
			Region:        os.Getenv("region"),
			NumNodes:      1,
			NodeTaint:     "ip-release",
			Executor:      helpers.CreateLocalExecutor([]string{}),
			Kubectl:       kubectl,
		}}
		err = ng.CreateNodePool()
		Expect(err).To(Equal(check.IsNil))

		By("Creating a deployment to pick a node to test on")
		configFile := "nginx-with-tolerations.yaml"
		labelSelector := "zgroup=http-server"
		tmpl := helpers.ManifestGet(kubectl.BasePath(), "http-deployment-node-toleration.yaml.tmpl")
		helpers.RenderTemplateWithData(tmpl, configFile, struct{ NodeTaint string }{NodeTaint: "ip-release"})

		res := kubectl.Exec(fmt.Sprintf("kubectl -n %s apply -f %s", releaseTestNs, configFile))
		if !res.WasSuccessful() {
			Failf("error creating test workload %v", err.Error())
		}
		kubectl.WaitforNPodsRunning(releaseTestNs, "-l "+labelSelector, 2, 10*time.Minute)

		By("Fetching cilium node for test pods")
		data, err := kubectl.GetPodsNodes(releaseTestNs, labelSelector)
		if err != nil {
			Fail(err.Error())
		}
		var nodeName string
		for _, v := range data {
			nodeName = v
			break
		}

		cn := kubectl.GetCiliumNode(nodeName)
		Expect(cn).NotTo(Equal(check.IsNil))
		totalBuffer := cn.Spec.IPAM.PreAllocate + cn.Spec.IPAM.MaxAboveWatermark

		initialAllocCnt, err := getAllocatedIPsOnNode(kubectl, nodeName)
		Expect(err).NotTo(Equal(check.IsNil))

		By("Scaling replicas by 2")
		res = kubectl.Exec(fmt.Sprintf("kubectl -n %s scale deploy %s --replicas=%v", releaseTestNs, "http-server", 4))
		if !res.WasSuccessful() {
			Failf("Error while scaling replicas %v", err.Error())
		}

		By("Wait for new pods to start up")
		kubectl.WaitforNPodsRunning(releaseTestNs, "-l "+labelSelector, 4, helpers.HelperTimeout)

		By("Wait for new IPs to be allocated")
		err = helpers.WithTimeout(hasRequiredIPBuffer(kubectl, nodeName, totalBuffer), "Timeout while waiting for IPs to be released from pool",
			&helpers.TimeoutConfig{Timeout: helpers.HelperTimeout})
		ExpectWithOffset(1, err).To(BeNil(), "Timeout while waiting for IPs to be released from pool")

		By("Scale back by 2 to create excess")
		res = kubectl.Exec(fmt.Sprintf("kubectl -n %s scale deploy %s --replicas=%v", releaseTestNs, "http-server", 2))
		if !res.WasSuccessful() {
			Failf("Error while scaling replicas %v", err.Error())
		}

		By("Wait for IPs to be marked for release")
		err = helpers.WithTimeout(hasIPsInHandshake(kubectl, nodeName), "Timeout while waiting for release IPs to be marked",
			&helpers.TimeoutConfig{Timeout: 5 * time.Minute})
		ExpectWithOffset(1, err).To(BeNil(), "Timeout while waiting for release IPs to be marked")

		By("Wait for IPs to be released from the pool")
		err = helpers.WithTimeout(hasRequiredIPsAllocated(kubectl, nodeName, initialAllocCnt), "Timeout while waiting for IPs to be released from pool",
			&helpers.TimeoutConfig{Timeout: helpers.HelperTimeout})
		ExpectWithOffset(1, err).To(BeNil(), "Timeout while waiting for IPs to be released from pool")

		By("Wait for entries to be cleared from release status")
		err = helpers.WithTimeout(hasNoIPsInHandshake(kubectl, nodeName), "Timeout while waiting for entries to be cleared from release status",
			&helpers.TimeoutConfig{Timeout: helpers.HelperTimeout})
		ExpectWithOffset(1, err).To(BeNil(), "Timeout while waiting for entries to be cleared from release status")
	})

})
