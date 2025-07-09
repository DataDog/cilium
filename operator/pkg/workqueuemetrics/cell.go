package workqueuemetrics

import (
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/hive/cell"
)

var Cell = cell.Module(
	"workqueue-metrics-provider",
	"Metrics provider for client-go workqueues",

	metrics.Metric(NewMetrics),
	cell.Provide(NewWorkqueueMetricsProvider),
)
