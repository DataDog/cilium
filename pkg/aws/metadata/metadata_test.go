// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metadata

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeIMDS serves the paths GetInstanceMetadata asks for, calling handle
// before every metadata response so that a test can delay or fail it.
func fakeIMDS(t *testing.T, handle func(w http.ResponseWriter) bool) *httptest.Server {
	t.Helper()

	values := map[string]string{
		"/latest/meta-data/instance-id":                                         "i-0123456789abcdef0",
		"/latest/meta-data/instance-type":                                       "m5.large",
		"/latest/meta-data/mac":                                                 "0a:11:22:33:44:55",
		"/latest/meta-data/network/interfaces/macs/0a:11:22:33:44:55/vpc-id":    "vpc-01234567",
		"/latest/meta-data/network/interfaces/macs/0a:11:22:33:44:55/subnet-id": "subnet-01234567",
		"/latest/meta-data/placement/availability-zone":                         "us-east-1a",
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && r.URL.Path == "/latest/api/token" {
			w.Header().Set("X-Aws-Ec2-Metadata-Token-Ttl-Seconds", "21600")
			w.Write([]byte("token"))
			return
		}

		value, ok := values[r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if handle != nil && !handle(w) {
			return
		}
		w.Write([]byte(value))
	}))
	t.Cleanup(srv.Close)

	// Honoured by both config.LoadDefaultConfig and imds.New.
	t.Setenv("AWS_EC2_METADATA_SERVICE_ENDPOINT", srv.URL)
	// Keep the SDK from looking for credentials or a region on the real IMDS.
	t.Setenv("AWS_REGION", "us-east-1")
	t.Setenv("AWS_ACCESS_KEY_ID", "test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test")

	return srv
}

func TestGetInstanceMetadata(t *testing.T) {
	fakeIMDS(t, nil)

	client, err := NewClient(context.Background())
	require.NoError(t, err)

	info, err := client.GetInstanceMetadata(context.Background())
	require.NoError(t, err)
	assert.Equal(t, MetaDataInfo{
		InstanceID:       "i-0123456789abcdef0",
		InstanceType:     "m5.large",
		AvailabilityZone: "us-east-1a",
		VPCID:            "vpc-01234567",
		SubnetID:         "subnet-01234567",
	}, info)
}

// TestGetInstanceMetadataSlowIMDS covers a node whose IMDS takes longer to
// answer than the 500ms the SDK defaults to waiting for response headers.
func TestGetInstanceMetadataSlowIMDS(t *testing.T) {
	fakeIMDS(t, func(w http.ResponseWriter) bool {
		time.Sleep(700 * time.Millisecond)
		return true
	})

	client, err := NewClient(context.Background())
	require.NoError(t, err)

	info, err := client.GetInstanceMetadata(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "i-0123456789abcdef0", info.InstanceID)
}

func TestGetInstanceMetadataUnreachableIMDS(t *testing.T) {
	srv := fakeIMDS(t, nil)
	srv.Close()

	client, err := NewClient(context.Background())
	require.NoError(t, err)

	_, err = client.GetInstanceMetadata(context.Background())
	require.Error(t, err)
	assert.True(t, strings.HasPrefix(err.Error(), "unable to retrieve AWS metadata instance-id:"),
		"unexpected error %q", err)
}
