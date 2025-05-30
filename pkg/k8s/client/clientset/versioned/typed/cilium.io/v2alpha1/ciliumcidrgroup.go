// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Code generated by client-gen. DO NOT EDIT.

package v2alpha1

import (
	context "context"

	ciliumiov2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	scheme "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/scheme"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	gentype "k8s.io/client-go/gentype"
)

// CiliumCIDRGroupsGetter has a method to return a CiliumCIDRGroupInterface.
// A group's client should implement this interface.
type CiliumCIDRGroupsGetter interface {
	CiliumCIDRGroups() CiliumCIDRGroupInterface
}

// CiliumCIDRGroupInterface has methods to work with CiliumCIDRGroup resources.
type CiliumCIDRGroupInterface interface {
	Create(ctx context.Context, ciliumCIDRGroup *ciliumiov2alpha1.CiliumCIDRGroup, opts v1.CreateOptions) (*ciliumiov2alpha1.CiliumCIDRGroup, error)
	Update(ctx context.Context, ciliumCIDRGroup *ciliumiov2alpha1.CiliumCIDRGroup, opts v1.UpdateOptions) (*ciliumiov2alpha1.CiliumCIDRGroup, error)
	Delete(ctx context.Context, name string, opts v1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error
	Get(ctx context.Context, name string, opts v1.GetOptions) (*ciliumiov2alpha1.CiliumCIDRGroup, error)
	List(ctx context.Context, opts v1.ListOptions) (*ciliumiov2alpha1.CiliumCIDRGroupList, error)
	Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *ciliumiov2alpha1.CiliumCIDRGroup, err error)
	CiliumCIDRGroupExpansion
}

// ciliumCIDRGroups implements CiliumCIDRGroupInterface
type ciliumCIDRGroups struct {
	*gentype.ClientWithList[*ciliumiov2alpha1.CiliumCIDRGroup, *ciliumiov2alpha1.CiliumCIDRGroupList]
}

// newCiliumCIDRGroups returns a CiliumCIDRGroups
func newCiliumCIDRGroups(c *CiliumV2alpha1Client) *ciliumCIDRGroups {
	return &ciliumCIDRGroups{
		gentype.NewClientWithList[*ciliumiov2alpha1.CiliumCIDRGroup, *ciliumiov2alpha1.CiliumCIDRGroupList](
			"ciliumcidrgroups",
			c.RESTClient(),
			scheme.ParameterCodec,
			"",
			func() *ciliumiov2alpha1.CiliumCIDRGroup { return &ciliumiov2alpha1.CiliumCIDRGroup{} },
			func() *ciliumiov2alpha1.CiliumCIDRGroupList { return &ciliumiov2alpha1.CiliumCIDRGroupList{} },
		),
	}
}
