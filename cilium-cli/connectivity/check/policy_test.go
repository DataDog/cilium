// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package check

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

func TestCountEndpointsBelowPolicyRevision(t *testing.T) {
	identity := &models.Identity{ID: 12345}

	realized := func(rev int64) *models.EndpointStatus {
		return &models.EndpointStatus{
			Identity: identity,
			Policy: &models.EndpointPolicyStatus{
				Realized: &models.EndpointPolicy{PolicyRevision: rev},
			},
		}
	}

	tests := []struct {
		name string
		eps  []*models.Endpoint
		rev  int
		want int
	}{
		{
			name: "no endpoints",
			eps:  nil,
			rev:  10,
			want: 0,
		},
		{
			name: "identity-less endpoint is skipped",
			eps: []*models.Endpoint{
				{Status: &models.EndpointStatus{Identity: nil}},
			},
			rev:  10,
			want: 0,
		},
		{
			name: "nil status is skipped",
			eps: []*models.Endpoint{
				{Status: nil},
			},
			rev:  10,
			want: 0,
		},
		{
			name: "identity endpoint with stale realized revision is counted",
			eps: []*models.Endpoint{
				{Status: realized(9)},
			},
			rev:  10,
			want: 1,
		},
		{
			name: "identity endpoint with nil policy is counted",
			eps: []*models.Endpoint{
				{Status: &models.EndpointStatus{Identity: identity, Policy: nil}},
			},
			rev:  10,
			want: 1,
		},
		{
			name: "identity endpoint with nil realized is counted",
			eps: []*models.Endpoint{
				{Status: &models.EndpointStatus{
					Identity: identity,
					Policy:   &models.EndpointPolicyStatus{Realized: nil},
				}},
			},
			rev:  10,
			want: 1,
		},
		{
			name: "identity endpoint at target revision is not counted",
			eps: []*models.Endpoint{
				{Status: realized(10)},
			},
			rev:  10,
			want: 0,
		},
		{
			name: "identity endpoint ahead of target revision is not counted",
			eps: []*models.Endpoint{
				{Status: realized(11)},
			},
			rev:  10,
			want: 0,
		},
		{
			name: "mix: only identity-bearing lagging endpoints are counted",
			eps: []*models.Endpoint{
				{Status: realized(11)},                               // ahead, not counted
				{Status: realized(9)},                                // stale, counted
				{Status: &models.EndpointStatus{Identity: nil}},      // no identity, skipped
				{Status: nil},                                        // no status, skipped
				{Status: &models.EndpointStatus{Identity: identity}}, // identity, nil policy, counted
			},
			rev:  10,
			want: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, countEndpointsBelowPolicyRevision(tt.eps, tt.rev))
		})
	}
}

func TestExpectationsPolicyDenyResponse(t *testing.T) {
	denyNone := features.Status{Mode: features.PolicyDenyResponseNone}
	denyICMP := features.Status{Enabled: true, Mode: features.PolicyDenyResponseICMP}

	tests := []struct {
		name             string
		denyResponse     features.Status
		ipFam            features.IPFamily
		egress           Result
		wantExitCode     ExitCode
		wantICMPResponse bool
	}{
		{
			name:         "egress policy deny without icmp response times out",
			denyResponse: denyNone,
			ipFam:        features.IPFamilyV4,
			egress:       ResultPolicyDenyEgressDropCurlTimeout,
			wantExitCode: ExitCurlTimeout,
		},
		{
			name:             "ipv4 egress policy deny with icmp response fails to connect",
			denyResponse:     denyICMP,
			ipFam:            features.IPFamilyV4,
			egress:           ResultPolicyDenyEgressDropCurlTimeout,
			wantExitCode:     ExitCurlCouldntConnect,
			wantICMPResponse: true,
		},
		{
			name:             "ipv4 dns proxy egress policy deny with icmp response fails to connect",
			denyResponse:     denyICMP,
			ipFam:            features.IPFamilyV4,
			egress:           ResultDNSOKPolicyDenyEgressDropCurlTimeout,
			wantExitCode:     ExitCurlCouldntConnect,
			wantICMPResponse: true,
		},
		{
			// The ICMPv6 reject is not guaranteed to reach the client, so only
			// require that the connection fails somehow.
			name:             "ipv6 egress policy deny with icmp response accepts any error",
			denyResponse:     denyICMP,
			ipFam:            features.IPFamilyV6,
			egress:           ResultPolicyDenyEgressDropCurlTimeout,
			wantExitCode:     ExitAnyError,
			wantICMPResponse: true,
		},
		{
			// The family of a DNS name is not known upfront.
			name:             "family-less egress policy deny with icmp response accepts any error",
			denyResponse:     denyICMP,
			ipFam:            features.IPFamilyAny,
			egress:           ResultPolicyDenyEgressDropCurlTimeout,
			wantExitCode:     ExitAnyError,
			wantICMPResponse: true,
		},
		{
			// The reject only happens on the source pod's egress, so drops
			// elsewhere must keep timing out.
			name:         "unmarked drop is left untouched with icmp response",
			denyResponse: denyICMP,
			ipFam:        features.IPFamilyV4,
			egress:       ResultDropCurlTimeout,
			wantExitCode: ExitCurlTimeout,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			test := &Test{
				name: "test",
				ctx:  &ConnectivityTest{Features: features.Set{features.PolicyDenyResponse: tt.denyResponse}},
				expectFunc: func(_ *Action) (Result, Result) {
					return tt.egress, ResultNone
				},
			}

			egress, ingress := test.expectations(&Action{ipFam: tt.ipFam})
			assert.Equal(t, tt.wantExitCode, egress.ExitCode)
			assert.Equal(t, tt.wantICMPResponse, egress.ICMPDenyResponse)
			assert.True(t, egress.Drop)
			assert.Equal(t, ResultNone, ingress)
		})
	}
}
