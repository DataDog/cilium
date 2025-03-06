// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/prometheus/client_golang/prometheus"

	operatorMetrics "github.com/cilium/cilium/operator/metrics"
	"github.com/cilium/cilium/pkg/metrics"
)

const ciliumNodeSynchronizerSubsystem = "cilium_node_synchronizer"

type prometheusMetrics struct {
	registry             operatorMetrics.RegisterGatherer
	QueuedItems          prometheus.Gauge
	AllocateInterfaceOps *prometheus.CounterVec
}

// NewPrometheusMetrics returns a new interface metrics implementation backed by
// Prometheus metrics.
func NewPrometheusMetrics() *prometheusMetrics {
	m := &prometheusMetrics{
		registry: operatorMetrics.Registry,
	}

	m.QueuedItems = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: metrics.CiliumOperatorNamespace,
		Subsystem: ciliumNodeSynchronizerSubsystem,
		Name:      "queued_items",
		Help:      "Number of items queued for processing",
	})

	m.AllocateInterfaceOps = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: metrics.CiliumOperatorNamespace,
		Subsystem: ciliumNodeSynchronizerSubsystem,
		Name:      "todo",
		Help:      "TODO",
	}, []string{"subnet_id"})

	m.registry.MustRegister(m.QueuedItems)
	m.registry.MustRegister(m.AllocateInterfaceOps)

	return m
}

func (p *prometheusMetrics) IncInterfaceAllocation(subnetID string) {
	p.AllocateInterfaceOps.WithLabelValues(subnetID).Inc()
}

func (p *prometheusMetrics) SetQueuedItems(items int) {
	p.QueuedItems.Set(float64(items))
}

/*
func merge(slices ...[]float64) []float64 {
	result := make([]float64, 1)
	for _, s := range slices {
		result = append(result, s...)
	}
	return result
}
*/
