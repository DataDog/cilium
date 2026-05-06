// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	rateLimitMetricHeaderPrefix      = "X-Ms-Ratelimit-Remaining-"
	rateLimitRemainingResourceHeader = "X-Ms-Ratelimit-Remaining-Resource"
)

// rateLimitMetricsObserver is the subset of MetricsAPI used to record Azure
// API rate-limit budget headers. It mirrors what *Metrics in
// pkg/ipam/allocator/azure provides without creating an import cycle.
type rateLimitMetricsObserver interface {
	ObserveRateLimitRemaining(description, subscriptionID string, value float64)
	ObserveRateLimitRemainingResource(policy, subscriptionID string, value float64)
}

// rateLimitMetricsExtractor is a per-retry pipeline policy that records
// Azure API rate-limit response headers as Prometheus metrics.
//
// See https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/request-limits-and-throttling#remaining-requests
type rateLimitMetricsExtractor struct {
	logger         *slog.Logger
	subscriptionID string
	metrics        rateLimitMetricsObserver
}

var _ policy.Policy = (*rateLimitMetricsExtractor)(nil)

func newRateLimitMetricsExtractor(logger *slog.Logger, subscriptionID string, metrics rateLimitMetricsObserver) *rateLimitMetricsExtractor {
	return &rateLimitMetricsExtractor{
		logger:         logger,
		subscriptionID: subscriptionID,
		metrics:        metrics,
	}
}

// Do forwards the request, then on a non-error response extracts rate-limit
// headers into metrics. Malformed header values are logged and skipped, other
// headers in the same response are still recorded.
func (e *rateLimitMetricsExtractor) Do(req *policy.Request) (*http.Response, error) {
	resp, err := req.Next()
	if err != nil || resp == nil {
		return resp, err
	}
	e.extract(resp)
	return resp, nil
}

func (e *rateLimitMetricsExtractor) extract(resp *http.Response) {
	logger := e.logger
	if resp.Request != nil && resp.Request.URL != nil {
		logger = logger.With(
			logfields.URL, resp.Request.URL.String(),
			logfields.Status, resp.Status,
			logfields.Method, resp.Request.Method,
		)
	}

	for headerKey, headerValues := range resp.Header {
		if len(headerValues) == 0 {
			continue
		}
		headerValue := headerValues[0]
		switch {
		case headerKey == rateLimitRemainingResourceHeader:
			e.extractResource(logger, headerValue)
		case strings.HasPrefix(headerKey, rateLimitMetricHeaderPrefix):
			description := strings.ToLower(strings.TrimPrefix(headerKey, rateLimitMetricHeaderPrefix))
			e.extractRemaining(logger, description, headerValue)
		}
	}
}

func (e *rateLimitMetricsExtractor) extractRemaining(logger *slog.Logger, description, headerValue string) {
	value, err := strconv.ParseInt(headerValue, 10, 64)
	if err != nil {
		logger.Warn("Failed to parse Azure rate-limit remaining header value, skipping",
			logfields.Error, err,
			logfields.Description, description,
			logfields.Value, headerValue,
		)
		return
	}

	subscriptionID, ok := e.subscriptionIDForDescription(description)
	if !ok {
		logger.Warn("Unknown Azure rate-limit description, skipping",
			logfields.Description, description,
		)
		return
	}

	e.metrics.ObserveRateLimitRemaining(description, subscriptionID, float64(value))
}

// extractResource parses the X-Ms-Ratelimit-Remaining-Resource header, whose
// value is a comma-separated list of policy;count pairs. Malformed segments
// are logged and skipped, valid segments in the same value are still recorded.
func (e *rateLimitMetricsExtractor) extractResource(logger *slog.Logger, headerValue string) {
	if headerValue == "" {
		return
	}
	for segment := range strings.SplitSeq(headerValue, ",") {
		policyName, countStr, ok := strings.Cut(segment, ";")
		if !ok {
			logger.Warn("Failed to parse Azure rate-limit resource header segment, skipping",
				logfields.Segment, segment,
				logfields.Value, headerValue,
			)
			continue
		}
		value, err := strconv.ParseInt(countStr, 10, 64)
		if err != nil {
			logger.Warn("Failed to parse Azure rate-limit resource header count, skipping",
				logfields.Error, err,
				logfields.Policy, policyName,
				logfields.Count, countStr,
			)
			continue
		}
		e.metrics.ObserveRateLimitRemainingResource(policyName, e.subscriptionID, float64(value))
	}
}

// subscriptionIDForDescription decides which subscription_id label value to
// use for a given description. Tenant-scoped descriptions get an empty value
// because the budget is shared across the tenant rather than per subscription.
// Returns false if the description is not in a recognized scope.
func (e *rateLimitMetricsExtractor) subscriptionIDForDescription(description string) (string, bool) {
	switch {
	case strings.HasPrefix(description, "subscription-"):
		return e.subscriptionID, true
	case strings.HasPrefix(description, "tenant-"):
		return "", true
	default:
		return "", false
	}
}
