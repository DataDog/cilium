// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumendpointslice

import "k8s.io/client-go/util/workqueue"

// cesWorkqueueMetricsProvider implements workqueue.MetricsProvider backed by the
// Metrics instance created for the CiliumEndpointSlice controller.
type cesWorkqueueMetricsProvider struct {
	metrics *Metrics
}

func newWorkqueueMetricsProvider(metrics *Metrics) workqueue.MetricsProvider {
	return &cesWorkqueueMetricsProvider{metrics: metrics}
}

func (p *cesWorkqueueMetricsProvider) NewDepthMetric(name string) workqueue.GaugeMetric {
	return p.metrics.WorkQueueDepth.WithLabelValues(name)
}

func (p *cesWorkqueueMetricsProvider) NewAddsMetric(name string) workqueue.CounterMetric {
	return p.metrics.WorkQueueAddsTotal.WithLabelValues(name)
}

func (p *cesWorkqueueMetricsProvider) NewLatencyMetric(name string) workqueue.HistogramMetric {
	return p.metrics.WorkQueueLatency.WithLabelValues(name)
}

func (p *cesWorkqueueMetricsProvider) NewWorkDurationMetric(name string) workqueue.HistogramMetric {
	return p.metrics.WorkQueueDuration.WithLabelValues(name)
}

func (p *cesWorkqueueMetricsProvider) NewUnfinishedWorkSecondsMetric(name string) workqueue.SettableGaugeMetric {
	return p.metrics.WorkQueueUnfinishedWork.WithLabelValues(name)
}

func (p *cesWorkqueueMetricsProvider) NewLongestRunningProcessorSecondsMetric(name string) workqueue.SettableGaugeMetric {
	return p.metrics.WorkQueueLongestRunningProcessor.WithLabelValues(name)
}

func (p *cesWorkqueueMetricsProvider) NewRetriesMetric(name string) workqueue.CounterMetric {
	return p.metrics.WorkQueueRetries.WithLabelValues(name)
}
