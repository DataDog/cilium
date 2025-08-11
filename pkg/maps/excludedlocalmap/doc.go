// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package excludedlocalmap represents the map for excluded local addresses.
// This map is used to store local addresses that have been excluded from
// normal endpoint processing but still need to be recognized as local for
// routing decisions when BPF host routing is enabled.
// +groupName=maps
package excludedlocalmap
