// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Code generated by client-gen. DO NOT EDIT.

package v1

import (
	"context"

	v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/discovery/v1"
	scheme "github.com/cilium/cilium/pkg/k8s/slim/k8s/client/clientset/versioned/scheme"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	gentype "k8s.io/client-go/gentype"
)

// EndpointSlicesGetter has a method to return a EndpointSliceInterface.
// A group's client should implement this interface.
type EndpointSlicesGetter interface {
	EndpointSlices(namespace string) EndpointSliceInterface
}

// EndpointSliceInterface has methods to work with EndpointSlice resources.
type EndpointSliceInterface interface {
	Create(ctx context.Context, endpointSlice *v1.EndpointSlice, opts metav1.CreateOptions) (*v1.EndpointSlice, error)
	Update(ctx context.Context, endpointSlice *v1.EndpointSlice, opts metav1.UpdateOptions) (*v1.EndpointSlice, error)
	Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts metav1.DeleteOptions, listOpts metav1.ListOptions) error
	Get(ctx context.Context, name string, opts metav1.GetOptions) (*v1.EndpointSlice, error)
	List(ctx context.Context, opts metav1.ListOptions) (*v1.EndpointSliceList, error)
	Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions, subresources ...string) (result *v1.EndpointSlice, err error)
	EndpointSliceExpansion
}

// endpointSlices implements EndpointSliceInterface
type endpointSlices struct {
	*gentype.ClientWithList[*v1.EndpointSlice, *v1.EndpointSliceList]
}

// newEndpointSlices returns a EndpointSlices
func newEndpointSlices(c *DiscoveryV1Client, namespace string) *endpointSlices {
	return &endpointSlices{
		gentype.NewClientWithList[*v1.EndpointSlice, *v1.EndpointSliceList](
			"endpointslices",
			c.RESTClient(),
			scheme.ParameterCodec,
			namespace,
			func() *v1.EndpointSlice { return &v1.EndpointSlice{} },
			func() *v1.EndpointSliceList { return &v1.EndpointSliceList{} }),
	}
}
