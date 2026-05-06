// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package azure

import (
	"github.com/prometheus/client_golang/prometheus"

	apiMetrics "github.com/cilium/cilium/pkg/api/metrics"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/time"
)

const (
	labelDescription    = "description"
	labelSubscriptionID = "subscription_id"
	labelPolicy         = "policy"
)

// Metrics holds the metrics for the Azure API client. It embeds the shared
// PrometheusMetrics (APIDuration, RateLimit) and adds the Azure-specific
// rate-limit-remaining gauges.
type Metrics struct {
	*apiMetrics.PrometheusMetrics

	// RateLimitRemaining tracks the X-Ms-Ratelimit-Remaining-* response
	// headers. subscription_id is empty for tenant-scoped descriptions
	// because the budget is shared across the tenant rather than per
	// subscription.
	// See https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/request-limits-and-throttling#remaining-requests
	RateLimitRemaining *prometheus.GaugeVec

	// RateLimitRemainingResource tracks the X-Ms-Ratelimit-Remaining-Resource
	// response header.
	// See https://learn.microsoft.com/en-us/azure/virtual-machines/troubleshooting/troubleshooting-throttling-errors#call-rate-informational-response-headers
	RateLimitRemainingResource *prometheus.GaugeVec
}

// NewMetrics returns the metrics for the Azure API client.
func NewMetrics(registry *metrics.Registry) *Metrics {
	rateLimitRemaining := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: metrics.CiliumOperatorNamespace,
		Subsystem: "azure",
		Name:      "ratelimit_remaining",
		Help:      "Remaining Azure API rate-limit budget reported by the X-Ms-Ratelimit-Remaining-* response headers",
	}, []string{labelDescription, labelSubscriptionID})

	rateLimitRemainingResource := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: metrics.CiliumOperatorNamespace,
		Subsystem: "azure",
		Name:      "ratelimit_remaining_resource",
		Help:      "Remaining Azure API rate-limit budget per resource policy reported by the X-Ms-Ratelimit-Remaining-Resource response header",
	}, []string{labelPolicy, labelSubscriptionID})

	registry.MustRegister(rateLimitRemaining)
	registry.MustRegister(rateLimitRemainingResource)

	return &Metrics{
		PrometheusMetrics:          apiMetrics.NewPrometheusMetrics(metrics.Namespace, "azure", registry),
		RateLimitRemaining:         rateLimitRemaining,
		RateLimitRemainingResource: rateLimitRemainingResource,
	}
}

// ObserveRateLimitRemaining records the remaining rate-limit budget for the
// given description. subscriptionID must be empty for tenant-scoped
// descriptions.
func (m *Metrics) ObserveRateLimitRemaining(description, subscriptionID string, value float64) {
	m.RateLimitRemaining.WithLabelValues(description, subscriptionID).Set(value)
}

// ObserveRateLimitRemainingResource records the remaining rate-limit budget
// for the given Azure policy.
func (m *Metrics) ObserveRateLimitRemainingResource(policyName, subscriptionID string, value float64) {
	m.RateLimitRemainingResource.WithLabelValues(policyName, subscriptionID).Set(value)
}

// NoOpMetrics is a no-op implementation of the Azure MetricsAPI interface.
type NoOpMetrics struct {
	apiMetrics.NoOpMetrics
}

// ObserveRateLimitRemaining is a no-op.
func (m *NoOpMetrics) ObserveRateLimitRemaining(description, subscriptionID string, value float64) {
}

// ObserveRateLimitRemainingResource is a no-op.
func (m *NoOpMetrics) ObserveRateLimitRemainingResource(policyName, subscriptionID string, value float64) {
}

// ensure Metrics & NoOpMetrics implement the API client's MetricsAPI surface.
var _ interface {
	ObserveAPICall(call, status string, duration float64)
	ObserveRateLimit(operation string, duration time.Duration)
	ObserveRateLimitRemaining(description, subscriptionID string, value float64)
	ObserveRateLimitRemainingResource(policyName, subscriptionID string, value float64)
} = (*Metrics)(nil)

var _ interface {
	ObserveAPICall(call, status string, duration float64)
	ObserveRateLimit(operation string, duration time.Duration)
	ObserveRateLimitRemaining(description, subscriptionID string, value float64)
	ObserveRateLimitRemainingResource(policyName, subscriptionID string, value float64)
} = (*NoOpMetrics)(nil)
