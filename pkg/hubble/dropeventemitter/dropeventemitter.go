// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dropeventemitter

import (
	"context"
	"log/slog"
	"slices"
	"strconv"
	"strings"

	v1 "k8s.io/api/core/v1"
	typedv1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/record"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/container/set"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/utils"
	client "github.com/cilium/cilium/pkg/k8s/client"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	metaslimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	slimscheme "github.com/cilium/cilium/pkg/k8s/slim/k8s/client/clientset/versioned/scheme"
	"github.com/cilium/cilium/pkg/k8s/watchers"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

type endpointManager interface {
	LookupCiliumID(id uint16) *endpoint.Endpoint
}

type endpointInterface interface {
	GetModel() *models.Endpoint
}

type dropEventEmitter struct {
	broadcaster     record.EventBroadcaster
	recorder        record.EventRecorder
	k8sWatcher      watchers.CacheAccessK8SWatcher
	showPolicies    bool
	reasons         []flowpb.DropReason
	endpointManager endpointManager
}

func new(log *slog.Logger, interval time.Duration, reasons []string, showPolicies bool, k8s client.Clientset, watcher watchers.CacheAccessK8SWatcher, endpointManager endpointManager) *dropEventEmitter {
	broadcaster := record.NewBroadcasterWithCorrelatorOptions(record.CorrelatorOptions{
		BurstSize:            1,
		QPS:                  1 / float32(interval.Seconds()),
		MaxEvents:            1,
		MaxIntervalInSeconds: int(interval.Seconds()),
		MessageFunc:          func(event *v1.Event) string { return event.Message },
	})
	broadcaster.StartRecordingToSink(&typedv1.EventSinkImpl{Interface: k8s.CoreV1().Events("")})

	rs := make([]flowpb.DropReason, 0, len(reasons))
	for _, reason := range reasons {
		if v, ok := flowpb.DropReason_value[strings.ToUpper(reason)]; ok {
			rs = append(rs, flowpb.DropReason(v))
		} else {
			log.Warn("Ignoring invalid drop reason", logfields.Reason, reason)
		}
	}

	return &dropEventEmitter{
		broadcaster:     broadcaster,
		recorder:        broadcaster.NewRecorder(slimscheme.Scheme, v1.EventSource{Component: "cilium"}),
		k8sWatcher:      watcher,
		reasons:         rs,
		showPolicies:    showPolicies,
		endpointManager: endpointManager,
	}
}

func (e *dropEventEmitter) ProcessFlow(ctx context.Context, flow *flowpb.Flow) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// Only handle packet drops due to policy related to a Pod
	if flow.Verdict != flowpb.Verdict_DROPPED ||
		!slices.Contains(e.reasons, flow.GetDropReasonDesc()) ||
		(flow.TrafficDirection == flowpb.TrafficDirection_INGRESS && flow.Destination.PodName == "") ||
		(flow.TrafficDirection == flowpb.TrafficDirection_EGRESS && flow.Source.PodName == "") {
		return nil
	}

	reason := strings.ToLower(flow.DropReasonDesc.String())

	var flowL4Rules []*models.PolicyRule
	var policyRevision uint64
	if e.showPolicies {
		flowL4Rules, policyRevision = getL4RulesFromEndpoint(flow.TrafficDirection, e.getLocalEndpoint(flow))
	}

	typeMeta := metaslimv1.TypeMeta{
		Kind:       "Pod",
		APIVersion: "v1",
	}

	if flow.TrafficDirection == flowpb.TrafficDirection_INGRESS {
		message := "Incoming packet dropped (" + reason + ") from " +
			endpointToString(flow.IP.Source, flow.Source) + " " +
			l4protocolToString(flow.L4) + "."

		if e.showPolicies {
			blockingPolicies := parsePolicyCorrelation(flow)
			if blockingPolicies != "" {
				message += " " + blockingPolicies
			} else {
				message += " " + parseL4Rules(flowL4Rules, policyRevision)
			}
		}

		e.recorder.Event(&slimv1.Pod{
			TypeMeta: typeMeta,
			ObjectMeta: metaslimv1.ObjectMeta{
				Name:      flow.Destination.PodName,
				Namespace: flow.Destination.Namespace,
			},
		}, v1.EventTypeWarning, "PacketDrop", message)
	} else {
		message := "Outgoing packet dropped (" + reason + ") to " +
			endpointToString(flow.IP.Destination, flow.Destination) + " " +
			l4protocolToString(flow.L4) + "."

		if e.showPolicies {
			blockingPolicies := parsePolicyCorrelation(flow)
			if blockingPolicies != "" {
				message += " " + blockingPolicies
			} else {
				message += " " + parseL4Rules(flowL4Rules, policyRevision)
			}
		}

		objMeta := metaslimv1.ObjectMeta{
			Name:      flow.Source.PodName,
			Namespace: flow.Source.Namespace,
		}
		if e.k8sWatcher != nil {
			pod, err := e.k8sWatcher.GetCachedPod(flow.Source.Namespace, flow.Source.PodName)
			if err == nil {
				objMeta.UID = pod.UID
			}
		}
		podObj := slimv1.Pod{
			TypeMeta:   typeMeta,
			ObjectMeta: objMeta,
		}
		e.recorder.Event(&podObj, v1.EventTypeWarning, "PacketDrop", message)
	}

	return nil
}

func (e *dropEventEmitter) Shutdown() {
	e.broadcaster.Shutdown()
}

func endpointToString(ip string, endpoint *flowpb.Endpoint) string {
	if endpoint.PodName != "" {
		return endpoint.Namespace + "/" + endpoint.PodName + " (" + ip + ")"
	}
	if identity.NumericIdentity(endpoint.Identity).IsReservedIdentity() {
		return identity.NumericIdentity(endpoint.Identity).String() + " (" + ip + ")"
	}
	return ip
}

func l4protocolToString(l4 *flowpb.Layer4) string {
	switch l4.Protocol.(type) {
	case *flowpb.Layer4_TCP:
		return "TCP/" + strconv.Itoa(int(l4.GetTCP().DestinationPort))
	case *flowpb.Layer4_UDP:
		return "UDP/" + strconv.Itoa(int(l4.GetUDP().DestinationPort))
	case *flowpb.Layer4_ICMPv4:
		return "ICMPv4"
	case *flowpb.Layer4_ICMPv6:
		return "ICMPv6"
	case *flowpb.Layer4_SCTP:
		return "SCTP"
	}
	return ""
}

func (e *dropEventEmitter) getLocalEndpoint(flow *flowpb.Flow) *endpoint.Endpoint {
	var endpointID uint16
	if flow.TrafficDirection == flowpb.TrafficDirection_INGRESS {
		endpointID = uint16(flow.Destination.ID)
	} else {
		endpointID = uint16(flow.Source.ID)
	}
	return e.endpointManager.LookupCiliumID(endpointID)
}

func getL4RulesFromEndpoint(direction flowpb.TrafficDirection, ep endpointInterface) ([]*models.PolicyRule, uint64) {
	if ep == nil {
		return nil, 0
	}

	model := ep.GetModel().Status
	if model == nil || model.Policy == nil || model.Policy.Realized == nil || model.Policy.Realized.L4 == nil {
		return nil, 0
	}

	policyRealizedL4 := model.Policy.Realized.L4
	policyRevision := uint64(model.Policy.Realized.PolicyRevision)
	if direction == flowpb.TrafficDirection_INGRESS {
		if policyRealizedL4.Ingress == nil {
			return nil, 0
		}
		return policyRealizedL4.Ingress, policyRevision
	} else {
		if policyRealizedL4.Egress == nil {
			return nil, 0
		}
		return policyRealizedL4.Egress, policyRevision
	}
}

func parseL4Rules(l4Rules []*models.PolicyRule, policyRevision uint64) string {
	var res []string
	var networkPolicies, clusterwideNetworkPolicies set.Set[string]

	for _, rules := range l4Rules {
		if rules == nil {
			continue
		}
		for _, policyLabels := range rules.DerivedFromRules {
			policy := utils.GetPolicyFromLabels(policyLabels, policyRevision)
			if policy == nil {
				continue
			}
			if policy.Namespace == "" {
				clusterwideNetworkPolicies.Insert(policy.Name)
				continue
			}
			networkPolicies.Insert(policy.Name)
		}
	}

	if networkPolicies.Len() > 0 {
		res = append(res, "Applied network policies: "+networkPolicies.String()+".")
	}
	if clusterwideNetworkPolicies.Len() > 0 {
		res = append(res, "Applied clusterwide network policies: "+clusterwideNetworkPolicies.String()+".")
	}
	return strings.Join(res, " ")
}

func parsePolicyCorrelation(flow *flowpb.Flow) string {
	var rules []*flowpb.Policy
	var blockingPolicies set.Set[string]
	if flow.TrafficDirection == flowpb.TrafficDirection_INGRESS {
		rules = flow.IngressDeniedBy
	} else {
		rules = flow.EgressDeniedBy
	}
	for _, rule := range rules {
		if rule.Namespace != "" {
			blockingPolicies.Insert(rule.Namespace + "/" + rule.Name)
		}
		blockingPolicies.Insert(rule.Name)
	}
	if blockingPolicies.Len() == 0 {
		return ""
	}
	return "Blocking policies: " + blockingPolicies.String()
}
