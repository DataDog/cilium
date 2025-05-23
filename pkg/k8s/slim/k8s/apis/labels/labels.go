// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Copyright 2014 The Kubernetes Authors.

package labels

import (
	"fmt"
	"maps"
	"sort"
	"strings"

	"k8s.io/apimachinery/pkg/util/validation/field"
)

// Labels allows you to present labels independently from their storage.
type Labels interface {
	// Has returns whether the provided label exists.
	Has(label string) (exists bool)

	// Get returns the value for the provided label.
	Get(label string) (value string)
}

// Set is a map of label:value. It implements Labels.
type Set map[string]string

// String returns all labels listed as a human readable string.
// Conveniently, exactly the format that ParseSelector takes.
func (ls Set) String() string {
	selector := make([]string, 0, len(ls))
	for key, value := range ls {
		selector = append(selector, key+"="+value)
	}
	// Sort for determinism.
	sort.StringSlice(selector).Sort()
	return strings.Join(selector, ",")
}

// Has returns whether the provided label exists in the map.
func (ls Set) Has(label string) bool {
	_, exists := ls[label]
	return exists
}

// Get returns the value in the map for the provided label.
func (ls Set) Get(label string) string {
	return ls[label]
}

// AsSelector converts labels into a selectors. It does not
// perform any validation, which means the server will reject
// the request if the Set contains invalid values.
func (ls Set) AsSelector() Selector {
	return SelectorFromSet(ls)
}

// AsValidatedSelector converts labels into a selectors.
// The Set is validated client-side, which allows to catch errors early.
func (ls Set) AsValidatedSelector() (Selector, error) {
	return ValidatedSelectorFromSet(ls)
}

// AsSelectorPreValidated converts labels into a selector, but
// assumes that labels are already validated and thus doesn't
// perform any validation.
// According to our measurements this is significantly faster
// in codepaths that matter at high scale.
// Note: this method copies the Set; if the Set is immutable, consider wrapping it with ValidatedSetSelector
// instead, which does not copy.
func (ls Set) AsSelectorPreValidated() Selector {
	return SelectorFromValidatedSet(ls)
}

// FormatLabels converts label map into plain string
func FormatLabels(labelMap map[string]string) string {
	l := Set(labelMap).String()
	if l == "" {
		l = "<none>"
	}
	return l
}

// Conflicts takes 2 maps and returns true if there a key match between
// the maps but the value doesn't match, and returns false in other cases
func Conflicts(labels1, labels2 Set) bool {
	small := labels1
	big := labels2
	if len(labels2) < len(labels1) {
		small = labels2
		big = labels1
	}

	for k, v := range small {
		if val, match := big[k]; match {
			if val != v {
				return true
			}
		}
	}

	return false
}

// Merge combines given maps, and does not check for any conflicts
// between the maps. In case of conflicts, second map (labels2) wins
func Merge(labels1, labels2 Set) Set {
	mergedMap := maps.Clone(labels1)
	maps.Copy(mergedMap, labels2)
	return mergedMap
}

// Equals returns true if the given maps are equal
func Equals(labels1, labels2 Set) bool {
	if len(labels1) != len(labels2) {
		return false
	}

	for k, v := range labels1 {
		value, ok := labels2[k]
		if !ok {
			return false
		}
		if value != v {
			return false
		}
	}
	return true
}

// ConvertSelectorToLabelsMap converts selector string to labels map
// and validates keys and values
func ConvertSelectorToLabelsMap(selector string, opts ...field.PathOption) (Set, error) {
	labelsMap := Set{}

	if len(selector) == 0 {
		return labelsMap, nil
	}

	for label := range strings.SplitSeq(selector, ",") {
		l := strings.Split(label, "=")
		if len(l) != 2 {
			return labelsMap, fmt.Errorf("invalid selector: %s", l)
		}
		key := strings.TrimSpace(l[0])
		if err := validateLabelKey(key, field.ToPath(opts...)); err != nil {
			return labelsMap, err
		}
		value := strings.TrimSpace(l[1])
		if err := validateLabelValue(key, value, field.ToPath(opts...)); err != nil {
			return labelsMap, err
		}
		labelsMap[key] = value
	}
	return labelsMap, nil
}
