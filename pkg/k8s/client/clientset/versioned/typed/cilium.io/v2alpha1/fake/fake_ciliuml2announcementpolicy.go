// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	"context"

	v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeCiliumL2AnnouncementPolicies implements CiliumL2AnnouncementPolicyInterface
type FakeCiliumL2AnnouncementPolicies struct {
	Fake *FakeCiliumV2alpha1
}

var ciliuml2announcementpoliciesResource = v2alpha1.SchemeGroupVersion.WithResource("ciliuml2announcementpolicies")

var ciliuml2announcementpoliciesKind = v2alpha1.SchemeGroupVersion.WithKind("CiliumL2AnnouncementPolicy")

// Get takes name of the ciliumL2AnnouncementPolicy, and returns the corresponding ciliumL2AnnouncementPolicy object, and an error if there is any.
func (c *FakeCiliumL2AnnouncementPolicies) Get(ctx context.Context, name string, options v1.GetOptions) (result *v2alpha1.CiliumL2AnnouncementPolicy, err error) {
	emptyResult := &v2alpha1.CiliumL2AnnouncementPolicy{}
	obj, err := c.Fake.
		Invokes(testing.NewRootGetActionWithOptions(ciliuml2announcementpoliciesResource, name, options), emptyResult)
	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v2alpha1.CiliumL2AnnouncementPolicy), err
}

// List takes label and field selectors, and returns the list of CiliumL2AnnouncementPolicies that match those selectors.
func (c *FakeCiliumL2AnnouncementPolicies) List(ctx context.Context, opts v1.ListOptions) (result *v2alpha1.CiliumL2AnnouncementPolicyList, err error) {
	emptyResult := &v2alpha1.CiliumL2AnnouncementPolicyList{}
	obj, err := c.Fake.
		Invokes(testing.NewRootListActionWithOptions(ciliuml2announcementpoliciesResource, ciliuml2announcementpoliciesKind, opts), emptyResult)
	if obj == nil {
		return emptyResult, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v2alpha1.CiliumL2AnnouncementPolicyList{ListMeta: obj.(*v2alpha1.CiliumL2AnnouncementPolicyList).ListMeta}
	for _, item := range obj.(*v2alpha1.CiliumL2AnnouncementPolicyList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested ciliumL2AnnouncementPolicies.
func (c *FakeCiliumL2AnnouncementPolicies) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewRootWatchActionWithOptions(ciliuml2announcementpoliciesResource, opts))
}

// Create takes the representation of a ciliumL2AnnouncementPolicy and creates it.  Returns the server's representation of the ciliumL2AnnouncementPolicy, and an error, if there is any.
func (c *FakeCiliumL2AnnouncementPolicies) Create(ctx context.Context, ciliumL2AnnouncementPolicy *v2alpha1.CiliumL2AnnouncementPolicy, opts v1.CreateOptions) (result *v2alpha1.CiliumL2AnnouncementPolicy, err error) {
	emptyResult := &v2alpha1.CiliumL2AnnouncementPolicy{}
	obj, err := c.Fake.
		Invokes(testing.NewRootCreateActionWithOptions(ciliuml2announcementpoliciesResource, ciliumL2AnnouncementPolicy, opts), emptyResult)
	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v2alpha1.CiliumL2AnnouncementPolicy), err
}

// Update takes the representation of a ciliumL2AnnouncementPolicy and updates it. Returns the server's representation of the ciliumL2AnnouncementPolicy, and an error, if there is any.
func (c *FakeCiliumL2AnnouncementPolicies) Update(ctx context.Context, ciliumL2AnnouncementPolicy *v2alpha1.CiliumL2AnnouncementPolicy, opts v1.UpdateOptions) (result *v2alpha1.CiliumL2AnnouncementPolicy, err error) {
	emptyResult := &v2alpha1.CiliumL2AnnouncementPolicy{}
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateActionWithOptions(ciliuml2announcementpoliciesResource, ciliumL2AnnouncementPolicy, opts), emptyResult)
	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v2alpha1.CiliumL2AnnouncementPolicy), err
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *FakeCiliumL2AnnouncementPolicies) UpdateStatus(ctx context.Context, ciliumL2AnnouncementPolicy *v2alpha1.CiliumL2AnnouncementPolicy, opts v1.UpdateOptions) (result *v2alpha1.CiliumL2AnnouncementPolicy, err error) {
	emptyResult := &v2alpha1.CiliumL2AnnouncementPolicy{}
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateSubresourceActionWithOptions(ciliuml2announcementpoliciesResource, "status", ciliumL2AnnouncementPolicy, opts), emptyResult)
	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v2alpha1.CiliumL2AnnouncementPolicy), err
}

// Delete takes name of the ciliumL2AnnouncementPolicy and deletes it. Returns an error if one occurs.
func (c *FakeCiliumL2AnnouncementPolicies) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewRootDeleteActionWithOptions(ciliuml2announcementpoliciesResource, name, opts), &v2alpha1.CiliumL2AnnouncementPolicy{})
	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeCiliumL2AnnouncementPolicies) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	action := testing.NewRootDeleteCollectionActionWithOptions(ciliuml2announcementpoliciesResource, opts, listOpts)

	_, err := c.Fake.Invokes(action, &v2alpha1.CiliumL2AnnouncementPolicyList{})
	return err
}

// Patch applies the patch and returns the patched ciliumL2AnnouncementPolicy.
func (c *FakeCiliumL2AnnouncementPolicies) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v2alpha1.CiliumL2AnnouncementPolicy, err error) {
	emptyResult := &v2alpha1.CiliumL2AnnouncementPolicy{}
	obj, err := c.Fake.
		Invokes(testing.NewRootPatchSubresourceActionWithOptions(ciliuml2announcementpoliciesResource, name, pt, data, opts, subresources...), emptyResult)
	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v2alpha1.CiliumL2AnnouncementPolicy), err
}
