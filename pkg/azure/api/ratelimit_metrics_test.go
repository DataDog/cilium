// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
)

type observation struct {
	description    string
	subscriptionID string
	value          float64
}

type resourceObservation struct {
	policy         string
	subscriptionID string
	value          float64
}

type fakeObserver struct {
	remaining []observation
	resource  []resourceObservation
}

func (f *fakeObserver) ObserveRateLimitRemaining(description, subscriptionID string, value float64) {
	f.remaining = append(f.remaining, observation{description, subscriptionID, value})
}

func (f *fakeObserver) ObserveRateLimitRemainingResource(policyName, subscriptionID string, value float64) {
	f.resource = append(f.resource, resourceObservation{policyName, subscriptionID, value})
}

func newExtractor(t *testing.T, obs *fakeObserver) *rateLimitMetricsExtractor {
	t.Helper()
	return newRateLimitMetricsExtractor(hivetest.Logger(t), "sub-1", obs)
}

func newResponse(headers http.Header) *http.Response {
	return &http.Response{
		Status:     "200 OK",
		StatusCode: http.StatusOK,
		Header:     headers,
		Request: &http.Request{
			Method: http.MethodGet,
			URL:    &url.URL{Scheme: "https", Host: "example.test", Path: "/"},
		},
	}
}

func TestExtract_Remaining_SubscriptionScoped(t *testing.T) {
	obs := &fakeObserver{}
	headers := http.Header{}
	headers.Set("X-Ms-Ratelimit-Remaining-Subscription-Reads", "11999")
	headers.Set("X-Ms-Ratelimit-Remaining-Subscription-Writes", "1199")

	newExtractor(t, obs).extract(newResponse(headers))

	require.ElementsMatch(t, []observation{
		{"subscription-reads", "sub-1", 11999},
		{"subscription-writes", "sub-1", 1199},
	}, obs.remaining)
	require.Empty(t, obs.resource)
}

func TestExtract_Remaining_TenantScopedHasEmptySubscriptionID(t *testing.T) {
	obs := &fakeObserver{}
	headers := http.Header{}
	headers.Set("X-Ms-Ratelimit-Remaining-Tenant-Reads", "11999")
	headers.Set("X-Ms-Ratelimit-Remaining-Tenant-Writes", "1199")

	newExtractor(t, obs).extract(newResponse(headers))

	require.ElementsMatch(t, []observation{
		{"tenant-reads", "", 11999},
		{"tenant-writes", "", 1199},
	}, obs.remaining)
}

func TestExtract_Remaining_UnknownDescriptionSkipped(t *testing.T) {
	obs := &fakeObserver{}
	headers := http.Header{}
	headers.Set("X-Ms-Ratelimit-Remaining-Mystery-Scope", "42")
	// A valid header alongside the unknown one must still be recorded.
	headers.Set("X-Ms-Ratelimit-Remaining-Subscription-Reads", "5")

	newExtractor(t, obs).extract(newResponse(headers))

	require.Equal(t, []observation{{"subscription-reads", "sub-1", 5}}, obs.remaining)
	require.Empty(t, obs.resource)
}

func TestExtract_Remaining_MalformedIntegerSkipped(t *testing.T) {
	obs := &fakeObserver{}
	headers := http.Header{}
	headers.Set("X-Ms-Ratelimit-Remaining-Subscription-Reads", "not-a-number")
	// A valid header alongside the malformed one must still be recorded.
	headers.Set("X-Ms-Ratelimit-Remaining-Subscription-Writes", "7")

	newExtractor(t, obs).extract(newResponse(headers))

	require.Equal(t, []observation{{"subscription-writes", "sub-1", 7}}, obs.remaining)
}

func TestExtract_Resource_MultipleSegments(t *testing.T) {
	obs := &fakeObserver{}
	headers := http.Header{}
	headers.Set("X-Ms-Ratelimit-Remaining-Resource", "Microsoft.Compute/HighCostGet3Min;107,Microsoft.Compute/HighCostGet30Min;547")

	newExtractor(t, obs).extract(newResponse(headers))

	require.Equal(t, []resourceObservation{
		{"Microsoft.Compute/HighCostGet3Min", "sub-1", 107},
		{"Microsoft.Compute/HighCostGet30Min", "sub-1", 547},
	}, obs.resource)
}

func TestExtract_Resource_EmptyValue(t *testing.T) {
	obs := &fakeObserver{}
	headers := http.Header{}
	headers.Set("X-Ms-Ratelimit-Remaining-Resource", "")

	newExtractor(t, obs).extract(newResponse(headers))

	require.Empty(t, obs.resource)
}

func TestExtract_Resource_MalformedSegmentSkipped(t *testing.T) {
	obs := &fakeObserver{}
	headers := http.Header{}
	// Second segment has no ';' separator, extraction must skip just that
	// segment and still record the surrounding valid ones.
	headers.Set("X-Ms-Ratelimit-Remaining-Resource", "Microsoft.Compute/HighCostGet3Min;107,broken-segment,Microsoft.Compute/HighCostGet30Min;547")

	newExtractor(t, obs).extract(newResponse(headers))

	require.Equal(t, []resourceObservation{
		{"Microsoft.Compute/HighCostGet3Min", "sub-1", 107},
		{"Microsoft.Compute/HighCostGet30Min", "sub-1", 547},
	}, obs.resource)
}

func TestExtract_Resource_MalformedCountSkipped(t *testing.T) {
	obs := &fakeObserver{}
	headers := http.Header{}
	headers.Set("X-Ms-Ratelimit-Remaining-Resource", "Microsoft.Compute/HighCostGet3Min;not-a-number,Microsoft.Compute/HighCostGet30Min;547")

	newExtractor(t, obs).extract(newResponse(headers))

	require.Equal(t, []resourceObservation{
		{"Microsoft.Compute/HighCostGet30Min", "sub-1", 547},
	}, obs.resource)
}

func TestExtract_IgnoresUnrelatedHeaders(t *testing.T) {
	obs := &fakeObserver{}
	headers := http.Header{}
	headers.Set("Content-Type", "application/json")
	headers.Set("X-Ms-Request-Id", "abc")
	headers.Set("X-Ms-Ratelimit-Remaining-Subscription-Reads", "5")

	newExtractor(t, obs).extract(newResponse(headers))

	require.Equal(t, []observation{{"subscription-reads", "sub-1", 5}}, obs.remaining)
	require.Empty(t, obs.resource)
}

func TestSubscriptionIDForDescription(t *testing.T) {
	e := newRateLimitMetricsExtractor(hivetest.Logger(t), "sub-42", &fakeObserver{})

	tests := []struct {
		description string
		wantID      string
		wantOK      bool
	}{
		{"subscription-reads", "sub-42", true},
		{"subscription-writes", "sub-42", true},
		{"tenant-reads", "", true},
		{"tenant-writes", "", true},
		{"mystery-scope", "", false},
		{"", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.description, func(t *testing.T) {
			got, ok := e.subscriptionIDForDescription(tc.description)
			require.Equal(t, tc.wantOK, ok)
			require.Equal(t, tc.wantID, got)
		})
	}
}
