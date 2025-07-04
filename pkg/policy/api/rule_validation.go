// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/cilium/cilium/pkg/iana"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/option"
)

const (
	maxPorts      = 40
	maxICMPFields = 40
)

var (
	ErrFromToNodesRequiresNodeSelectorOption = fmt.Errorf("FromNodes/ToNodes rules can only be applied when the %q flag is set", option.EnableNodeSelectorLabels)

	errUnsupportedICMPWithToPorts = errors.New("the ICMPs block may only be present without ToPorts. Define a separate rule to use ToPorts")
	errEmptyServerName            = errors.New("empty server name is not allowed")

	enableDefaultDenyDefault = true
)

// Sanitize validates and sanitizes a policy rule. Minor edits such as capitalization
// of the protocol name are automatically fixed up.
// As part of `EndpointSelector` sanitization we also convert the label keys to internal
// representation prefixed with the source information. Check `EndpointSelector.sanitize()`
// method for more details.
// More fundamental violations will cause an error to be returned.
//
// Note: this function is called from both the operator and the agent;
// make sure any configuration flags are bound in **both** binaries.
func (r *Rule) Sanitize() error {
	if len(r.Ingress) == 0 && len(r.IngressDeny) == 0 && len(r.Egress) == 0 && len(r.EgressDeny) == 0 {
		return fmt.Errorf("rule must have at least one of Ingress, IngressDeny, Egress, EgressDeny")
	}

	if option.Config.EnableNonDefaultDenyPolicies {
		// Fill in the default traffic posture of this Rule.
		// Default posture is per-direction (ingress or egress),
		// if there is a peer selector for that direction, the
		// default is deny, else allow.
		if r.EnableDefaultDeny.Egress == nil {
			x := len(r.Egress) > 0 || len(r.EgressDeny) > 0
			r.EnableDefaultDeny.Egress = &x
		}
		if r.EnableDefaultDeny.Ingress == nil {
			x := len(r.Ingress) > 0 || len(r.IngressDeny) > 0
			r.EnableDefaultDeny.Ingress = &x
		}
	} else {
		// Since Non Default Deny Policies is disabled by flag, set EnableDefaultDeny to true
		r.EnableDefaultDeny.Egress = &enableDefaultDenyDefault
		r.EnableDefaultDeny.Ingress = &enableDefaultDenyDefault
	}

	if r.EndpointSelector.LabelSelector == nil && r.NodeSelector.LabelSelector == nil {
		return errors.New("rule must have one of EndpointSelector or NodeSelector")
	}
	if r.EndpointSelector.LabelSelector != nil && r.NodeSelector.LabelSelector != nil {
		return errors.New("rule cannot have both EndpointSelector and NodeSelector")
	}

	if r.EndpointSelector.LabelSelector != nil {
		if err := r.EndpointSelector.Sanitize(); err != nil {
			return err
		}
	}

	var hostPolicy bool
	if r.NodeSelector.LabelSelector != nil {
		if err := r.NodeSelector.Sanitize(); err != nil {
			return err
		}
		hostPolicy = true
	}

	for i := range r.Ingress {
		if err := r.Ingress[i].sanitize(hostPolicy); err != nil {
			return err
		}
	}

	for i := range r.IngressDeny {
		if err := r.IngressDeny[i].sanitize(); err != nil {
			return err
		}
	}

	for i := range r.Egress {
		if err := r.Egress[i].sanitize(hostPolicy); err != nil {
			return err
		}
	}

	for i := range r.EgressDeny {
		if err := r.EgressDeny[i].sanitize(); err != nil {
			return err
		}
	}

	return nil
}

func countL7Rules(ports []PortRule) map[string]int {
	result := make(map[string]int)
	for _, port := range ports {
		if !port.Rules.IsEmpty() {
			result["DNS"] += len(port.Rules.DNS)
			result["HTTP"] += len(port.Rules.HTTP)
			result["Kafka"] += len(port.Rules.Kafka)
		}
	}
	return result
}

func (i *IngressRule) sanitize(hostPolicy bool) error {
	l7Members := countL7Rules(i.ToPorts)
	l7IngressSupport := map[string]bool{
		"DNS":   false,
		"Kafka": true,
		"HTTP":  true,
	}

	if err := i.IngressCommonRule.sanitize(); err != nil {
		return err
	}

	if hostPolicy && len(l7Members) > 0 {
		return errors.New("L7 policy is not supported on host ingress yet")
	}

	if len(l7Members) > 0 && !option.Config.EnableL7Proxy {
		return errors.New("L7 policy is not supported since L7 proxy is not enabled")
	}
	for member := range l7Members {
		if l7Members[member] > 0 && !l7IngressSupport[member] {
			return fmt.Errorf("L7 protocol %s is not supported on ingress yet", member)
		}
	}

	if len(i.ICMPs) > 0 && !option.Config.EnableICMPRules {
		return fmt.Errorf("ICMP rules can only be applied when the %q flag is set", option.EnableICMPRules)
	}

	if len(i.ICMPs) > 0 && len(i.ToPorts) > 0 {
		return errUnsupportedICMPWithToPorts
	}

	for n := range i.ToPorts {
		if err := i.ToPorts[n].sanitize(true); err != nil {
			return err
		}
	}

	for n := range i.ICMPs {
		if err := i.ICMPs[n].verify(); err != nil {
			return err
		}
	}

	i.SetAggregatedSelectors()

	return nil
}

func (i *IngressDenyRule) sanitize() error {
	if err := i.IngressCommonRule.sanitize(); err != nil {
		return err
	}

	if len(i.ICMPs) > 0 && !option.Config.EnableICMPRules {
		return fmt.Errorf("ICMP rules can only be applied when the %q flag is set", option.EnableICMPRules)
	}

	if len(i.ICMPs) > 0 && len(i.ToPorts) > 0 {
		return errUnsupportedICMPWithToPorts
	}

	for n := range i.ToPorts {
		if err := i.ToPorts[n].sanitize(); err != nil {
			return err
		}
	}

	for n := range i.ICMPs {
		if err := i.ICMPs[n].verify(); err != nil {
			return err
		}
	}

	i.SetAggregatedSelectors()

	return nil
}

func (i *IngressCommonRule) sanitize() error {
	l3Members := map[string]int{
		"FromEndpoints": len(i.FromEndpoints),
		"FromCIDR":      len(i.FromCIDR),
		"FromCIDRSet":   len(i.FromCIDRSet),
		"FromEntities":  len(i.FromEntities),
		"FromNodes":     len(i.FromNodes),
		"FromGroups":    len(i.FromGroups),
	}

	for m1 := range l3Members {
		for m2 := range l3Members {
			if m2 != m1 && l3Members[m1] > 0 && l3Members[m2] > 0 {
				return fmt.Errorf("combining %s and %s is not supported yet", m1, m2)
			}
		}
	}

	var retErr error

	if len(i.FromNodes) > 0 && !option.Config.EnableNodeSelectorLabels {
		retErr = ErrFromToNodesRequiresNodeSelectorOption
	}

	for n := range i.FromEndpoints {
		if err := i.FromEndpoints[n].Sanitize(); err != nil {
			return errors.Join(err, retErr)
		}
	}

	for n := range i.FromRequires {
		if err := i.FromRequires[n].Sanitize(); err != nil {
			return errors.Join(err, retErr)
		}
	}

	for n := range i.FromNodes {
		if err := i.FromNodes[n].Sanitize(); err != nil {
			return errors.Join(err, retErr)
		}
	}

	for n := range i.FromCIDR {
		if err := i.FromCIDR[n].sanitize(); err != nil {
			return errors.Join(err, retErr)
		}
	}

	for n := range i.FromCIDRSet {
		if err := i.FromCIDRSet[n].sanitize(); err != nil {
			return errors.Join(err, retErr)
		}
	}

	for _, fromEntity := range i.FromEntities {
		_, ok := EntitySelectorMapping[fromEntity]
		if !ok {
			return errors.Join(fmt.Errorf("unsupported entity: %s", fromEntity), retErr)
		}
	}

	return retErr
}

// countNonGeneratedRules counts the number of CIDRRule items which are not
// `Generated`, i.e. were directly provided by the user.
// The `Generated` field is currently only set by the `ToServices`
// implementation, which extracts service endpoints and translates them as
// ToCIDRSet rules before the CNP is passed to the policy repository.
// Therefore, we want to allow the combination of ToCIDRSet and ToServices
// rules, if (and only if) the ToCIDRSet only contains `Generated` entries.
func countNonGeneratedCIDRRules(s CIDRRuleSlice) int {
	n := 0
	for _, c := range s {
		if !c.Generated {
			n++
		}
	}
	return n
}

// countNonGeneratedEndpoints counts the number of EndpointSelector items which are not
// `Generated`, i.e. were directly provided by the user.
// The `Generated` field is currently only set by the `ToServices`
// implementation, which extracts service endpoints and translates them as
// ToEndpoints rules before the CNP is passed to the policy repository.
// Therefore, we want to allow the combination of ToEndpoints and ToServices
// rules, if (and only if) the ToEndpoints only contains `Generated` entries.
func countNonGeneratedEndpoints(s []EndpointSelector) int {
	n := 0
	for _, c := range s {
		if !c.Generated {
			n++
		}
	}
	return n
}

func (e *EgressRule) sanitize(hostPolicy bool) error {
	l3Members := e.l3Members()
	l3DependentL4Support := e.l3DependentL4Support()
	l7Members := countL7Rules(e.ToPorts)
	l7EgressSupport := map[string]bool{
		"DNS":   true,
		"Kafka": !hostPolicy,
		"HTTP":  !hostPolicy,
	}

	if err := e.EgressCommonRule.sanitize(l3Members); err != nil {
		return err
	}

	for member := range l3Members {
		if l3Members[member] > 0 && len(e.ToPorts) > 0 && !l3DependentL4Support[member] {
			return fmt.Errorf("combining %s and ToPorts is not supported yet", member)
		}
	}

	if len(l7Members) > 0 && !option.Config.EnableL7Proxy {
		return errors.New("L7 policy is not supported since L7 proxy is not enabled")
	}
	for member := range l7Members {
		if l7Members[member] > 0 && !l7EgressSupport[member] {
			where := ""
			if hostPolicy {
				where = "host "
			}
			return fmt.Errorf("L7 protocol %s is not supported on %segress yet", member, where)
		}
	}

	if len(e.ICMPs) > 0 && !option.Config.EnableICMPRules {
		return fmt.Errorf("ICMP rules can only be applied when the %q flag is set", option.EnableICMPRules)
	}

	if len(e.ICMPs) > 0 && len(e.ToPorts) > 0 {
		return errUnsupportedICMPWithToPorts
	}

	for i := range e.ToPorts {
		if err := e.ToPorts[i].sanitize(false); err != nil {
			return err
		}
	}

	for n := range e.ICMPs {
		if err := e.ICMPs[n].verify(); err != nil {
			return err
		}
	}

	for i := range e.ToFQDNs {
		err := e.ToFQDNs[i].sanitize()
		if err != nil {
			return err
		}
	}

	e.SetAggregatedSelectors()

	return nil
}

func (e *EgressRule) l3Members() map[string]int {
	l3Members := e.EgressCommonRule.l3Members()
	l3Members["ToFQDNs"] = len(e.ToFQDNs)
	return l3Members
}

func (e *EgressRule) l3DependentL4Support() map[string]bool {
	l3DependentL4Support := e.EgressCommonRule.l3DependentL4Support()
	l3DependentL4Support["ToFQDNs"] = true
	return l3DependentL4Support
}

func (e *EgressDenyRule) sanitize() error {
	l3Members := e.l3Members()
	l3DependentL4Support := e.l3DependentL4Support()

	if err := e.EgressCommonRule.sanitize(l3Members); err != nil {
		return err
	}

	for member := range l3Members {
		if l3Members[member] > 0 && len(e.ToPorts) > 0 && !l3DependentL4Support[member] {
			return fmt.Errorf("combining %s and ToPorts is not supported yet", member)
		}
	}

	if len(e.ICMPs) > 0 && !option.Config.EnableICMPRules {
		return fmt.Errorf("ICMP rules can only be applied when the %q flag is set", option.EnableICMPRules)
	}

	if len(e.ICMPs) > 0 && len(e.ToPorts) > 0 {
		return errUnsupportedICMPWithToPorts
	}

	for i := range e.ToPorts {
		if err := e.ToPorts[i].sanitize(); err != nil {
			return err
		}
	}

	for n := range e.ICMPs {
		if err := e.ICMPs[n].verify(); err != nil {
			return err
		}
	}

	e.SetAggregatedSelectors()

	return nil
}

func (e *EgressDenyRule) l3Members() map[string]int {
	return e.EgressCommonRule.l3Members()
}

func (e *EgressDenyRule) l3DependentL4Support() map[string]bool {
	return e.EgressCommonRule.l3DependentL4Support()
}

func (e *EgressCommonRule) sanitize(l3Members map[string]int) error {
	for m1 := range l3Members {
		for m2 := range l3Members {
			if m2 != m1 && l3Members[m1] > 0 && l3Members[m2] > 0 {
				return fmt.Errorf("combining %s and %s is not supported yet", m1, m2)
			}
		}
	}

	var retErr error

	if len(e.ToNodes) > 0 && !option.Config.EnableNodeSelectorLabels {
		retErr = ErrFromToNodesRequiresNodeSelectorOption
	}

	for i := range e.ToEndpoints {
		if err := e.ToEndpoints[i].Sanitize(); err != nil {
			return errors.Join(err, retErr)
		}
	}

	for i := range e.ToRequires {
		if err := e.ToRequires[i].Sanitize(); err != nil {
			return errors.Join(err, retErr)
		}
	}

	for i := range e.ToNodes {
		if err := e.ToNodes[i].Sanitize(); err != nil {
			return errors.Join(err, retErr)
		}
	}

	for i := range e.ToCIDR {
		if err := e.ToCIDR[i].sanitize(); err != nil {
			return errors.Join(err, retErr)
		}
	}
	for i := range e.ToCIDRSet {
		if err := e.ToCIDRSet[i].sanitize(); err != nil {
			return errors.Join(err, retErr)
		}
	}

	for _, toEntity := range e.ToEntities {
		_, ok := EntitySelectorMapping[toEntity]
		if !ok {
			return errors.Join(fmt.Errorf("unsupported entity: %s", toEntity), retErr)
		}
	}

	return retErr
}

func (e *EgressCommonRule) l3Members() map[string]int {
	return map[string]int{
		"ToCIDR":      len(e.ToCIDR),
		"ToCIDRSet":   countNonGeneratedCIDRRules(e.ToCIDRSet),
		"ToEndpoints": countNonGeneratedEndpoints(e.ToEndpoints),
		"ToEntities":  len(e.ToEntities),
		"ToServices":  len(e.ToServices),
		"ToGroups":    len(e.ToGroups),
		"ToNodes":     len(e.ToNodes),
	}
}

func (e *EgressCommonRule) l3DependentL4Support() map[string]bool {
	return map[string]bool{
		"ToCIDR":      true,
		"ToCIDRSet":   true,
		"ToEndpoints": true,
		"ToEntities":  true,
		"ToServices":  true,
		"ToGroups":    true,
		"ToNodes":     true,
	}
}

func (pr *L7Rules) sanitize(ports []PortProtocol) error {
	nTypes := 0

	if pr.HTTP != nil {
		nTypes++
		for i := range pr.HTTP {
			if err := pr.HTTP[i].Sanitize(); err != nil {
				return err
			}
		}
	}

	if pr.Kafka != nil {
		nTypes++
		for i := range pr.Kafka {
			if err := pr.Kafka[i].Sanitize(); err != nil {
				return err
			}
		}
	}

	if pr.DNS != nil {
		// Forthcoming TPROXY redirection restricts DNS proxy to the standard DNS port (53).
		// Require the port 53 be explicitly configured, and disallow other port numbers.
		if len(ports) == 0 {
			return errors.New("port 53 must be specified for DNS rules")
		}

		nTypes++
		for i := range pr.DNS {
			if err := pr.DNS[i].Sanitize(); err != nil {
				return err
			}
		}
	}

	if pr.L7 != nil && pr.L7Proto == "" {
		return fmt.Errorf("'l7' may only be specified when a 'l7proto' is also specified")
	}
	if pr.L7Proto != "" {
		nTypes++
		for i := range pr.L7 {
			if err := pr.L7[i].Sanitize(); err != nil {
				return err
			}
		}
	}

	if nTypes > 1 {
		return fmt.Errorf("multiple L7 protocol rule types specified in single rule")
	}
	return nil
}

// It is not allowed to configure an ingress listener, but we still
// have some unit tests relying on this. So, allow overriding this check in the unit tests.
var TestAllowIngressListener = false

func (pr *PortRule) sanitize(ingress bool) error {
	hasDNSRules := pr.Rules != nil && len(pr.Rules.DNS) > 0
	if ingress && hasDNSRules {
		return fmt.Errorf("DNS rules are not allowed on ingress")
	}

	if len(pr.ServerNames) > 0 && !pr.Rules.IsEmpty() && pr.TerminatingTLS == nil {
		return fmt.Errorf("ServerNames are not allowed with L7 rules without TLS termination")
	}
	if slices.Contains(pr.ServerNames, "") {
		return errEmptyServerName
	}

	if len(pr.Ports) > maxPorts {
		return fmt.Errorf("too many ports, the max is %d", maxPorts)
	}
	haveZeroPort := false
	for i := range pr.Ports {
		var isZero bool
		var err error
		if isZero, err = pr.Ports[i].sanitize(hasDNSRules); err != nil {
			return err
		}
		if isZero {
			haveZeroPort = true
		}
		// DNS L7 rules can be TCP, UDP or ANY, all others are TCP only.
		switch {
		case pr.Rules.IsEmpty(), hasDNSRules:
			// nothing to do if no rules OR they are DNS rules (note the comma above)
		case pr.Ports[i].Protocol != ProtoTCP:
			return fmt.Errorf("L7 rules can only apply to TCP (not %s) except for DNS rules", pr.Ports[i].Protocol)
		}
	}

	listener := pr.Listener
	if listener != nil {
		// For now we have only tested custom listener support on the egress path.  TODO
		// (jrajahalme): Lift this limitation in follow-up work once proper testing has been
		// done on the ingress path.
		if ingress && !TestAllowIngressListener {
			return fmt.Errorf("Listener is not allowed on ingress (%s)", listener.Name)
		}
		// There is no quarantee that Listener will support Cilium policy enforcement.  Even
		// now proxylib-based enforcement (e.g, Kafka) may work, but has not been tested.
		// TODO (jrajahalme): Lift this limitation in follow-up work for proxylib based
		// parsers if needed and when tested.
		if !pr.Rules.IsEmpty() {
			return fmt.Errorf("Listener is not allowed with L7 rules (%s)", listener.Name)
		}
	}

	// Sanitize L7 rules
	if !pr.Rules.IsEmpty() {
		if haveZeroPort {
			return errors.New("L7 rules can not be used when a port is 0")
		}

		if err := pr.Rules.sanitize(pr.Ports); err != nil {
			return err
		}
	}
	return nil
}

func (pr *PortDenyRule) sanitize() error {
	if len(pr.Ports) > maxPorts {
		return fmt.Errorf("too many ports, the max is %d", maxPorts)
	}
	for i := range pr.Ports {
		if _, err := pr.Ports[i].sanitize(false); err != nil {
			return err
		}
	}

	return nil
}

func (pp *PortProtocol) sanitize(hasDNSRules bool) (isZero bool, err error) {
	if pp.Port == "" {
		if !option.Config.EnableExtendedIPProtocols {
			return isZero, errors.New("port must be specified")
		}
	}

	// Port names are formatted as IANA Service Names.  This means that
	// some legal numeric literals are no longer considered numbers, e.g,
	// 0x10 is now considered a name rather than number 16.
	if iana.IsSvcName(pp.Port) {
		pp.Port = strings.ToLower(pp.Port) // Normalize for case insensitive comparison
	} else if pp.Port != "" {
		if pp.Port != "0" && (pp.Protocol == ProtoVRRP || pp.Protocol == ProtoIGMP) {
			return isZero, errors.New("port must be empty or 0")
		}
		p, err := strconv.ParseUint(pp.Port, 0, 16)
		if err != nil {
			return isZero, fmt.Errorf("unable to parse port: %w", err)
		}
		isZero = p == 0
		if hasDNSRules && pp.EndPort > int32(p) {
			return isZero, errors.New("DNS rules do not support port ranges")
		}
	}

	pp.Protocol, err = ParseL4Proto(string(pp.Protocol))
	return isZero, err
}

func (ir *ICMPRule) verify() error {
	if len(ir.Fields) > maxICMPFields {
		return fmt.Errorf("too many types, the max is %d", maxICMPFields)
	}

	for _, f := range ir.Fields {
		if f.Family != IPv4Family && f.Family != IPv6Family && f.Family != "" {
			return fmt.Errorf("wrong family: %s", f.Family)
		}
	}

	return nil
}

// sanitize the given CIDR.
func (c CIDR) sanitize() error {
	strCIDR := string(c)
	if strCIDR == "" {
		return fmt.Errorf("IP must be specified")
	}

	prefix, err := netip.ParsePrefix(strCIDR)
	if err != nil {
		_, err := netip.ParseAddr(strCIDR)
		if err != nil {
			return fmt.Errorf("unable to parse CIDR: %w", err)
		}
		return nil
	}
	prefixLength := prefix.Bits()
	if prefixLength < 0 {
		return fmt.Errorf("CIDR cannot specify non-contiguous mask %s", prefix)
	}

	return nil
}

// sanitize validates a CIDRRule by checking that the CIDR prefix itself is
// valid, and ensuring that all of the exception CIDR prefixes are contained
// within the allowed CIDR prefix.
func (c *CIDRRule) sanitize() error {
	// Exactly one of CIDR, CIDRGroupRef, or CIDRGroupSelector must be set
	cnt := 0
	if len(c.CIDRGroupRef) > 0 {
		cnt++
	}
	if len(c.Cidr) > 0 {
		cnt++
	}
	if c.CIDRGroupSelector != nil {
		cnt++
		es := NewESFromK8sLabelSelector(labels.LabelSourceCIDRGroupKeyPrefix, c.CIDRGroupSelector)
		if err := es.Sanitize(); err != nil {
			return fmt.Errorf("failed to parse cidrGroupSelector %v: %w", c.CIDRGroupSelector.String(), err)
		}
	}
	if cnt == 0 {
		return fmt.Errorf("one of cidr, cidrGroupRef, or cidrGroupSelector is required")
	}
	if cnt > 1 {
		return fmt.Errorf("more than one of cidr, cidrGroupRef, or cidrGroupSelector may not be set")
	}

	if len(c.CIDRGroupRef) > 0 || c.CIDRGroupSelector != nil {
		return nil // these are selectors;
	}

	// Only allow notation <IP address>/<prefix>. Note that this differs from
	// the logic in api.CIDR.Sanitize().
	prefix, err := netip.ParsePrefix(string(c.Cidr))
	if err != nil {
		return fmt.Errorf("unable to parse CIDRRule %q: %w", c.Cidr, err)
	}

	prefixLength := prefix.Bits()
	if prefixLength < 0 {
		return fmt.Errorf("CIDR cannot specify non-contiguous mask %s", prefix)
	}

	// Ensure that each provided exception CIDR prefix  is formatted correctly,
	// and is contained within the CIDR prefix to/from which we want to allow
	// traffic.
	for _, p := range c.ExceptCIDRs {
		except, err := netip.ParsePrefix(string(p))
		if err != nil {
			return err
		}

		// Note: this also checks that the allow CIDR prefix and the exception
		// CIDR prefixes are part of the same address family.
		if !prefix.Contains(except.Addr()) {
			return fmt.Errorf("allow CIDR prefix %s does not contain "+
				"exclude CIDR prefix %s", c.Cidr, p)
		}
	}

	return nil
}
