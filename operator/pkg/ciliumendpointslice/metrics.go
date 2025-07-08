// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumendpointslice

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

const (
	// LabelOutcome indicates whether the outcome of the operation was successful or not
	LabelOutcome = "outcome"

	// LabelFailureType indicates which failure type occurred when "outcome" is "fail"
	LabelFailureType = "failure_type"

	// LabelOpcode indicates the kind of CES metric, could be CEP insert or remove
	LabelOpcode = "opcode"

	// LabelQueue denotes which queue was used
	LabelQueue = "queue"

	// Label values

	// LabelValueOutcomeSuccess is used as a successful outcome of an operation
	LabelValueOutcomeSuccess = "success"

	// LabelValueOutcomeFail is used as an unsuccessful outcome of an operation
	LabelValueOutcomeFail = "fail"

	// LabelFailureTypeTransient is used to indicate a transient failure, which is retried
	LabelFailureTypeTransient = "transient"

	// LabelFailureTypeFatal is used to indicate a fatal failure, when all retries have been exhausted
	LabelFailureTypeFatal = "fatal"

	// LabelValueCEPInsert is used to indicate the number of CEPs inserted in a CES
	LabelValueCEPInsert = "cepinserted"

	// LabelValueCEPRemove is used to indicate the number of CEPs removed from a CES
	LabelValueCEPRemove = "cepremoved"

	//LabelQueueFast is used when the fast queue was used
	LabelQueueFast = "fast"

	//LabelQueueStandard is used when the standard queue was used
	LabelQueueStandard = "standard"
)

func NewMetrics() *Metrics {
	return &Metrics{
		CiliumEndpointSliceDensity: metric.NewHistogram(metric.HistogramOpts{
			Namespace: metrics.CiliumOperatorNamespace,
			Name:      "number_of_ceps_per_ces",
			Help:      "The number of CEPs batched in a CES",
			Buckets:   []float64{1, 10, 25, 50, 100, 200, 500, 1000},
		}),

		CiliumEndpointsChangeCount: metric.NewHistogramVec(metric.HistogramOpts{
			Namespace: metrics.CiliumOperatorNamespace,
			Name:      "number_of_cep_changes_per_ces",
			Help:      "The number of changed CEPs in each CES update",
			Buckets:   []float64{1, 10, 25, 50, 100, 200, 500, 1000},
		}, []string{LabelOpcode}),

		CiliumEndpointSliceSyncTotal: metric.NewCounterVec(metric.CounterOpts{
			Namespace: metrics.CiliumOperatorNamespace,
			Name:      "ces_sync_total",
			Help:      "The number of completed CES syncs by outcome",
		}, []string{LabelOutcome, LabelFailureType}),

		CiliumEndpointSliceQueueDelay: metric.NewHistogramVec(metric.HistogramOpts{
			Namespace: metrics.CiliumOperatorNamespace,
			Name:      "ces_queueing_delay_seconds",
			Help:      "CiliumEndpointSlice queueing delay in seconds",
			Buckets:   append(prometheus.DefBuckets, 60, 300, 900, 1800, 3600),
		}, []string{LabelQueue}),

		// Workqueue metrics:

		WorkQueueDepth: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace: metrics.CiliumOperatorNamespace,
			Name:      "workqueue_depth",
			Help:      "Current depth of CES workqueue.",
		}, []string{"queue_name"}),

		WorkQueueAddsTotal: metric.NewCounterVec(metric.CounterOpts{
			Namespace: metrics.CiliumOperatorNamespace,
			Name:      "workqueue_adds_total",
			Help:      "Total number of adds handled by CES workqueue.",
		}, []string{"queue_name"}),

		WorkQueueLatency: metric.NewHistogramVec(metric.HistogramOpts{
			Namespace: metrics.CiliumOperatorNamespace,
			Name:      "workqueue_queue_duration_seconds",
			Help:      "How long in seconds an item stays in CES workqueue before being requested.",
			Buckets:   prometheus.ExponentialBuckets(10e-9, 10, 10),
		}, []string{"queue_name"}),

		WorkQueueDuration: metric.NewHistogramVec(metric.HistogramOpts{
			Namespace: metrics.CiliumOperatorNamespace,
			Name:      "workqueue_work_duration_seconds",
			Help:      "How long in seconds processing an item from CES workqueue takes.",
			Buckets:   prometheus.ExponentialBuckets(10e-9, 10, 10),
		}, []string{"queue_name"}),

		WorkQueueUnfinishedWork: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace: metrics.CiliumOperatorNamespace,
			Name:      "workqueue_unfinished_work_seconds",
			Help:      "How many seconds of work has been done that is in progress and hasn't been observed by work_duration.",
		}, []string{"queue_name"}),

		WorkQueueLongestRunningProcessor: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace: metrics.CiliumOperatorNamespace,
			Name:      "workqueue_longest_running_processor_seconds",
			Help:      "How many seconds has the longest running processor for CES workqueue been running.",
		}, []string{"queue_name"}),

		WorkQueueRetries: metric.NewCounterVec(metric.CounterOpts{
			Namespace: metrics.CiliumOperatorNamespace,
			Name:      "workqueue_retries_total",
			Help:      "Total number of retries handled by CES workqueue.",
		}, []string{"queue_name"}),
	}
}

type Metrics struct {
	// CiliumEndpointSliceDensity indicates the number of CEPs batched in a CES and it used to
	// collect the number of CEPs in CES at various buckets.
	CiliumEndpointSliceDensity metric.Histogram

	// CiliumEndpointsChangeCount indicates the total number of CEPs changed for every CES request sent to k8s-apiserver.
	// This metric is used to collect number of CEP changes happening at various buckets.
	CiliumEndpointsChangeCount metric.Vec[metric.Observer]

	// CiliumEndpointSliceSyncTotal indicates the total number of completed CES syncs with k8s-apiserver by success/fail outcome.
	CiliumEndpointSliceSyncTotal metric.Vec[metric.Counter]

	// CiliumEndpointSliceQueueDelay measures the time spent by CES's in the workqueue. This measures time difference between
	// CES insert in the workqueue and removal from workqueue.
	CiliumEndpointSliceQueueDelay metric.Vec[metric.Observer] //metric.Histogram

	// Generic workqueue metrics scoped for CES controller
	WorkQueueDepth                   metric.Vec[metric.Gauge]
	WorkQueueAddsTotal               metric.Vec[metric.Counter]
	WorkQueueLatency                 metric.Vec[metric.Observer]
	WorkQueueDuration                metric.Vec[metric.Observer]
	WorkQueueUnfinishedWork          metric.Vec[metric.Gauge]
	WorkQueueLongestRunningProcessor metric.Vec[metric.Gauge]
	WorkQueueRetries                 metric.Vec[metric.Counter]
}
