// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package netperf

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/perf/common"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

const (
	netperfToolName = "netperf"
)

// Network Performance
func Netperf(n string) check.Scenario {
	return &netPerf{
		name:         n,
		ScenarioBase: check.NewScenarioBase(),
	}
}

type netPerf struct {
	check.ScenarioBase

	name string
}

func (s *netPerf) Name() string {
	if s.name == "" {
		return netperfToolName
	}
	return fmt.Sprintf("%s:%s", netperfToolName, s.name)
}

func (s *netPerf) Run(ctx context.Context, t *check.Test) {
	perfParameters := t.Context().Params().PerfParameters

	tests := []string{}

	if perfParameters.Throughput {
		tests = append(tests, "TCP_STREAM")
		if perfParameters.UDP {
			tests = append(tests, "UDP_STREAM")
		}
	}

	if perfParameters.CRR {
		tests = append(tests, "TCP_CRR")
	}

	if perfParameters.RR {
		tests = append(tests, "TCP_RR")
		if perfParameters.UDP {
			tests = append(tests, "UDP_RR")
		}
	}

	if perfParameters.SetupDelay > 0 {
		t.Context().Logf("⌛ Waiting %v before starting performance tests", perfParameters.SetupDelay)
		select {
		case <-time.After(perfParameters.SetupDelay):
		case <-ctx.Done():
			return
		}
		t.Context().Info("Finished waiting before starting performance tests")
	}

	for sample := 1; sample <= perfParameters.Samples; sample++ {
		for _, c := range t.Context().PerfClientPods() {
			c := c
			for _, server := range t.Context().PerfServerPod() {
				clientHost := strings.Contains(c.Pod.Name, check.PerfHostName)
				serverHost := strings.Contains(server.Pod.Name, check.PerfHostName)

				switch {
				case clientHost && serverHost && perfParameters.HostNet:
				case clientHost && !serverHost && perfParameters.HostToPod:
				case !clientHost && serverHost && perfParameters.PodToHost:
				case !clientHost && !serverHost && perfParameters.PodNet:

				default:
					continue
				}

				scenarioName := ""
				if strings.Contains(c.Pod.Name, check.PerfHostName) {
					scenarioName += "host"
				} else {
					scenarioName += "pod"
				}
				scenarioName += "-to-"
				if strings.Contains(server.Pod.Name, check.PerfHostName) {
					scenarioName += "host"
				} else {
					scenarioName += "pod"
				}

				sameNode := true
				if strings.Contains(c.Pod.Name, check.PerfOtherNode) {
					sameNode = false
				}

				for _, test := range tests {
					testName := netperfToolName + "_" + test + "_" + scenarioName
					action := t.NewAction(s, testName, &c, server, features.IPFamilyV4)

					action.CollectFlows = false
					action.Run(func(a *check.Action) {
						k := common.PerfTests{
							Test:     test,
							Tool:     netperfToolName,
							SameNode: sameNode,
							Sample:   sample,
							Duration: perfParameters.Duration,
							Scenario: scenarioName,
							MsgSize:  perfParameters.MessageSize,
							NetQos:   false,
						}
						perfResult := NetperfCmd(ctx, server.Pod.Status.PodIP, k, a)
						t.Context().PerfResults = append(t.Context().PerfResults, common.PerfSummary{PerfTest: k, Result: perfResult})
					})
				}
			}
		}
	}
}

func buildExecCommand(test string, sip string, duration time.Duration, args []string) []string {
	exec := []string{"/usr/local/bin/netperf", "-H", sip, "-l", duration.String(), "-t", test, "--", "-R", "1"}
	exec = append(exec, args...)

	return exec
}

func parseDuration(a *check.Action, value string) time.Duration {
	res, err := time.ParseDuration(value + "us") // by default latencies in netperf are reported in microseconds
	if err != nil {
		a.Fatalf("Unable to process netperf result, duration: %s", value)
	}
	return res
}

func parseFloat(a *check.Action, value string) float64 {
	res, err := strconv.ParseFloat(value, 64)
	if err != nil {
		a.Fatalf("Unable to process netperf result, float: %s", value)
	}
	return res
}

func NetperfCmd(ctx context.Context, sip string, perfTest common.PerfTests, a *check.Action) common.PerfResult {
	args := []string{"-o", "MIN_LATENCY,MEAN_LATENCY,MAX_LATENCY,P50_LATENCY,P90_LATENCY,P99_LATENCY,TRANSACTION_RATE,THROUGHPUT,THROUGHPUT_UNITS"}
	if perfTest.Test == "UDP_STREAM" || perfTest.NetQos {
		args = append(args, "-m", fmt.Sprintf("%d", perfTest.MsgSize))
	}
	exec := buildExecCommand(perfTest.Test, sip, perfTest.Duration, args)

	a.ExecInPod(ctx, exec)
	output := a.CmdOutput()
	a.Debugf("Netperf output: ", output)
	lines := strings.Split(output, "\n")
	if len(lines) < 2 {
		a.Fatal("Unable to process netperf result")
	}
	resultsLine := lines[len(lines)-2]
	values := strings.Split(resultsLine, ",")
	if len(values) != 9 {
		a.Fatalf("Unable to process netperf result")
	}
	a.Debugf("Numbers: %v", values)

	res := common.PerfResult{
		Timestamp: time.Now(),
		Latency: &common.LatencyMetric{
			Min:    parseDuration(a, values[0]),
			Avg:    parseDuration(a, values[1]),
			Max:    parseDuration(a, values[2]),
			Perc50: parseDuration(a, values[3]),
			Perc90: parseDuration(a, values[4]),
			Perc99: parseDuration(a, values[5]),
		},
		TransactionRateMetric: &common.TransactionRateMetric{
			TransactionRate: parseFloat(a, values[6]),
		},
		ThroughputMetric: &common.ThroughputMetric{
			Throughput: parseFloat(a, values[7]) * 1000000, // by default throughput has unit "10^6bits/s", we verify that later
		},
	}

	if strings.HasSuffix(perfTest.Test, "_STREAM") {
		// We don't want to report transaction rate or latency
		res.TransactionRateMetric = nil
		res.Latency = nil
		// Verify that throughput unit is 10^6bits/s
		if values[8] != "10^6bits/s" {
			a.Fatal("Unable to process netperf result")
		}
	}
	if strings.HasSuffix(perfTest.Test, "_RR") || strings.HasSuffix(perfTest.Test, "_CRR") {
		// We don't want to report throughput
		res.ThroughputMetric = nil
	}

	return res
}
