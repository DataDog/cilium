package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/client-go/util/workqueue"
)

const workqueueSubsystem = "workqueue"

type PrometheusMetricsProvider struct {
	registry  prometheus.Registerer
	namespace string
}

func NewPrometheusMetricsProvider(namespace string, registry RegisterGatherer) *PrometheusMetricsProvider {
	return &PrometheusMetricsProvider{namespace: namespace, registry: registry}
}

func (p PrometheusMetricsProvider) NewDepthMetric(name string) workqueue.GaugeMetric {
	metric := prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: p.namespace,
		Subsystem: workqueueSubsystem,
		Name:      name + "_depth",
		Help:      "Current depth of the workqueue",
	})
	p.registry.MustRegister(metric)
	return metric
}

func (p PrometheusMetricsProvider) NewAddsMetric(name string) workqueue.CounterMetric {
	metric := prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: p.namespace,
		Subsystem: workqueueSubsystem,
		Name:      name + "_adds",
		Help:      "Total number of adds handled by the workqueue",
	})
	p.registry.MustRegister(metric)
	return metric
}

func (p PrometheusMetricsProvider) NewLatencyMetric(name string) workqueue.HistogramMetric {
	metric := prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: p.namespace,
		Subsystem: workqueueSubsystem,
		Name:      name + "_latency",
		Help:      "How long an item stays in the workqueue",
		Buckets:   prometheus.DefBuckets,
	})
	p.registry.MustRegister(metric)
	return metric
}

func (p PrometheusMetricsProvider) NewWorkDurationMetric(name string) workqueue.HistogramMetric {
	metric := prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: p.namespace,
		Subsystem: workqueueSubsystem,
		Name:      name + "_work_duration",
		Help:      "How long processing an item from the workqueue takes",
		Buckets:   prometheus.DefBuckets,
	})
	p.registry.MustRegister(metric)
	return metric
}

func (p PrometheusMetricsProvider) NewUnfinishedWorkSecondsMetric(name string) workqueue.SettableGaugeMetric {
	metric := prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: p.namespace,
		Subsystem: workqueueSubsystem,
		Name:      name + "_unfinished_work_seconds",
		Help:      "How long have current threads been working",
	})
	p.registry.MustRegister(metric)
	return metric
}

func (p PrometheusMetricsProvider) NewLongestRunningProcessorSecondsMetric(name string) workqueue.SettableGaugeMetric {
	metric := prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: p.namespace,
		Subsystem: workqueueSubsystem,
		Name:      name + "_longest_running_processor_seconds",
		Help:      "How long the longest running processor has been working",
	})
	p.registry.MustRegister(metric)
	return metric
}

func (p PrometheusMetricsProvider) NewRetriesMetric(name string) workqueue.CounterMetric {
	metric := prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: p.namespace,
		Subsystem: workqueueSubsystem,
		Name:      name + "_retries",
		Help:      "Total number of retries handled by the workqueue",
	})
	p.registry.MustRegister(metric)
	return metric
}
