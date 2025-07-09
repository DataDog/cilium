// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package workqueuemetrics

import "k8s.io/client-go/util/workqueue"

type workqueueMetricsProvider struct {
	metrics *Metrics
}

func NewWorkqueueMetricsProvider(metrics *Metrics) workqueue.MetricsProvider {
	return &workqueueMetricsProvider{metrics: metrics}
}

func (p *workqueueMetricsProvider) NewDepthMetric(queueName string) workqueue.GaugeMetric {
	return p.metrics.WorkQueueDepth.WithLabelValues(queueName)
}

func (p *workqueueMetricsProvider) NewAddsMetric(queueName string) workqueue.CounterMetric {
	return p.metrics.WorkQueueAddsTotal.WithLabelValues(queueName)
}

func (p *workqueueMetricsProvider) NewLatencyMetric(queueName string) workqueue.HistogramMetric {
	return p.metrics.WorkQueueLatency.WithLabelValues(queueName)
}

func (p *workqueueMetricsProvider) NewWorkDurationMetric(queueName string) workqueue.HistogramMetric {
	return p.metrics.WorkQueueDuration.WithLabelValues(queueName)
}

func (p *workqueueMetricsProvider) NewUnfinishedWorkSecondsMetric(queueName string) workqueue.SettableGaugeMetric {
	return p.metrics.WorkQueueUnfinishedWork.WithLabelValues(queueName)
}

func (p *workqueueMetricsProvider) NewLongestRunningProcessorSecondsMetric(queueName string) workqueue.SettableGaugeMetric {
	return p.metrics.WorkQueueLongestRunningProcessor.WithLabelValues(queueName)
}

func (p *workqueueMetricsProvider) NewRetriesMetric(queueName string) workqueue.CounterMetric {
	return p.metrics.WorkQueueRetries.WithLabelValues(queueName)
}
