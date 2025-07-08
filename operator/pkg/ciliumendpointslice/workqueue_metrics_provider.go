// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumendpointslice

import "k8s.io/client-go/util/workqueue"

// cesWorkqueueMetricsProvider implements workqueue.MetricsProvider backed by the
// Metrics instance created for the CiliumEndpointSlice controller.
type cesWorkqueueMetricsProvider struct {
	m *Metrics
}

func newWorkqueueMetricsProvider(m *Metrics) workqueue.MetricsProvider {
	return &cesWorkqueueMetricsProvider{m: m}
}

func (p *cesWorkqueueMetricsProvider) NewDepthMetric(name string) workqueue.GaugeMetric {
	return p.m.WorkQueueDepth.WithLabelValues(name)
}

func (p *cesWorkqueueMetricsProvider) NewAddsMetric(name string) workqueue.CounterMetric {
	return p.m.WorkQueueAddsTotal.WithLabelValues(name)
}

func (p *cesWorkqueueMetricsProvider) NewLatencyMetric(name string) workqueue.HistogramMetric {
	return p.m.WorkQueueLatency.WithLabelValues(name)
}

func (p *cesWorkqueueMetricsProvider) NewWorkDurationMetric(name string) workqueue.HistogramMetric {
	return p.m.WorkQueueDuration.WithLabelValues(name)
}

func (p *cesWorkqueueMetricsProvider) NewUnfinishedWorkSecondsMetric(name string) workqueue.SettableGaugeMetric {
	return p.m.WorkQueueUnfinishedWork.WithLabelValues(name)
}

func (p *cesWorkqueueMetricsProvider) NewLongestRunningProcessorSecondsMetric(name string) workqueue.SettableGaugeMetric {
	return p.m.WorkQueueLongestRunningProcessor.WithLabelValues(name)
}

func (p *cesWorkqueueMetricsProvider) NewRetriesMetric(name string) workqueue.CounterMetric {
	return p.m.WorkQueueRetries.WithLabelValues(name)
}
