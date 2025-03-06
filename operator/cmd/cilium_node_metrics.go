package cmd

import (
	operatorMetrics "github.com/cilium/cilium/operator/metrics"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/client-go/util/workqueue"
)

const workqueueSubsystem = "workqueue"

type WorkqueuePrometheusMetricsProvider struct {
	registry  prometheus.Registerer
	namespace string
	subsystem string
}

func NewWorkqueuePrometheusMetricsProvider() *WorkqueuePrometheusMetricsProvider {
	return &WorkqueuePrometheusMetricsProvider{
		registry:  operatorMetrics.Registry,
		namespace: metrics.CiliumOperatorNamespace,
		subsystem: workqueueSubsystem,
	}
}

func (p WorkqueuePrometheusMetricsProvider) NewDepthMetric(name string) workqueue.GaugeMetric {
	metric := prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: p.namespace,
		Subsystem: p.subsystem,
		Name:      name + "_depth",
		Help:      "Current depth of the workqueue",
	})
	p.registry.MustRegister(metric)
	return metric
}

func (p WorkqueuePrometheusMetricsProvider) NewAddsMetric(name string) workqueue.CounterMetric {
	metric := prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: p.namespace,
		Subsystem: p.subsystem,
		Name:      name + "_adds",
		Help:      "Total number of adds handled by the workqueue",
	})
	p.registry.MustRegister(metric)
	return metric
}

func (p WorkqueuePrometheusMetricsProvider) NewLatencyMetric(name string) workqueue.HistogramMetric {
	metric := prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: p.namespace,
		Subsystem: p.subsystem,
		Name:      name + "_latency",
		Help:      "How long an item stays in the workqueue",
		Buckets:   prometheus.DefBuckets,
	})
	p.registry.MustRegister(metric)
	return metric
}

func (p WorkqueuePrometheusMetricsProvider) NewWorkDurationMetric(name string) workqueue.HistogramMetric {
	metric := prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: p.namespace,
		Subsystem: p.subsystem,
		Name:      name + "_work_duration",
		Help:      "How long processing an item from the workqueue takes",
		Buckets:   prometheus.DefBuckets,
	})
	p.registry.MustRegister(metric)
	return metric
}

func (p WorkqueuePrometheusMetricsProvider) NewUnfinishedWorkSecondsMetric(name string) workqueue.SettableGaugeMetric {
	metric := prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: p.namespace,
		Subsystem: p.subsystem,
		Name:      name + "_unfinished_work_seconds",
		Help:      "How long have current threads been working",
	})
	p.registry.MustRegister(metric)
	return metric
}

func (p WorkqueuePrometheusMetricsProvider) NewLongestRunningProcessorSecondsMetric(name string) workqueue.SettableGaugeMetric {
	metric := prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: p.namespace,
		Subsystem: p.subsystem,
		Name:      name + "_longest_running_processor_seconds",
		Help:      "How long the longest running processor has been working",
	})
	p.registry.MustRegister(metric)
	return metric
}

func (p WorkqueuePrometheusMetricsProvider) NewRetriesMetric(name string) workqueue.CounterMetric {
	metric := prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: p.namespace,
		Subsystem: p.subsystem,
		Name:      name + "_retries",
		Help:      "Total number of retries handled by the workqueue",
	})
	p.registry.MustRegister(metric)
	return metric
}
