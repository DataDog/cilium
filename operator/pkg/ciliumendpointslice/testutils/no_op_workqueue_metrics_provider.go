package testutils

import "k8s.io/client-go/util/workqueue"

// NoOpWorkqueueMetricsProvider is a no-op implementation of workqueue.MetricsProvider.
type NoOpWorkqueueMetricsProvider struct{}

type noopMetric struct{}

func (noopMetric) Inc()            {}
func (noopMetric) Dec()            {}
func (noopMetric) Set(float64)     {}
func (noopMetric) Observe(float64) {}

func (NoOpWorkqueueMetricsProvider) NewDepthMetric(string) workqueue.GaugeMetric {
	return noopMetric{}
}
func (NoOpWorkqueueMetricsProvider) NewAddsMetric(string) workqueue.CounterMetric {
	return noopMetric{}
}
func (NoOpWorkqueueMetricsProvider) NewLatencyMetric(string) workqueue.HistogramMetric {
	return noopMetric{}
}
func (NoOpWorkqueueMetricsProvider) NewWorkDurationMetric(string) workqueue.HistogramMetric {
	return noopMetric{}
}
func (NoOpWorkqueueMetricsProvider) NewUnfinishedWorkSecondsMetric(string) workqueue.SettableGaugeMetric {
	return noopMetric{}
}
func (NoOpWorkqueueMetricsProvider) NewLongestRunningProcessorSecondsMetric(string) workqueue.SettableGaugeMetric {
	return noopMetric{}
}
func (NoOpWorkqueueMetricsProvider) NewRetriesMetric(string) workqueue.CounterMetric {
	return noopMetric{}
}
