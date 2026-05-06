// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package azure

import (
	apiMetrics "github.com/cilium/cilium/pkg/api/metrics"
	ciliumMetrics "github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
	"github.com/cilium/cilium/pkg/time"
)

const (
	labelDescription    = "description"
	labelSubscriptionID = "subscription_id"
	labelPolicy         = "policy"
)

// Metrics holds the metrics for the Azure API client.
type Metrics struct {
	APIDuration metric.Vec[metric.Observer]
	RateLimit   metric.Vec[metric.Observer]

	// RateLimitRemaining tracks the X-Ms-Ratelimit-Remaining-* response
	// headers. subscription_id is empty for tenant-scoped descriptions
	// because the budget is shared across the tenant rather than per
	// subscription.
	// See https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/request-limits-and-throttling#remaining-requests
	RateLimitRemaining metric.Vec[metric.Gauge]

	// RateLimitRemainingResource tracks the X-Ms-Ratelimit-Remaining-Resource
	// response header.
	// See https://learn.microsoft.com/en-us/azure/virtual-machines/troubleshooting/troubleshooting-throttling-errors#call-rate-informational-response-headers
	RateLimitRemainingResource metric.Vec[metric.Gauge]
}

// NewMetrics returns the metrics for the Azure API client.
func NewMetrics() *Metrics {
	m := apiMetrics.New("azure")
	return &Metrics{
		APIDuration: m.APIDuration,
		RateLimit:   m.RateLimit,

		RateLimitRemaining: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace: ciliumMetrics.CiliumOperatorNamespace,
			Subsystem: "azure",
			Name:      "ratelimit_remaining",
			Help:      "Remaining Azure API rate-limit budget reported by the X-Ms-Ratelimit-Remaining-* response headers",
		}, []string{labelDescription, labelSubscriptionID}),

		RateLimitRemainingResource: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace: ciliumMetrics.CiliumOperatorNamespace,
			Subsystem: "azure",
			Name:      "ratelimit_remaining_resource",
			Help:      "Remaining Azure API rate-limit budget per resource policy reported by the X-Ms-Ratelimit-Remaining-Resource response header",
		}, []string{labelPolicy, labelSubscriptionID}),
	}
}

// ObserveAPICall records the duration of an API call.
func (m *Metrics) ObserveAPICall(operation, status string, duration float64) {
	m.APIDuration.WithLabelValues(operation, status).Observe(duration)
}

// ObserveRateLimit records a rate-limiter blocking event.
func (m *Metrics) ObserveRateLimit(operation string, delay time.Duration) {
	m.RateLimit.WithLabelValues(operation).Observe(delay.Seconds())
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
