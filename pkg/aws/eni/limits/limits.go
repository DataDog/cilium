// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Copyright 2017 Lyft, Inc.

package limits

import (
	"context"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2_types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var subsysLogAttr = []any{logfields.LogSubsys, "aws-eni-limits"}

type ec2API interface {
	GetInstanceTypes(context.Context) ([]ec2_types.InstanceTypeInfo, error)
	GetInstanceType(context.Context, string) (ec2_types.InstanceTypeInfo, error)
}
type LimitsGetter struct {
	logger *slog.Logger
	api    ec2API
	lock.RWMutex
	m map[string]ipamTypes.Limits
}

func NewLimitsGetter(logger *slog.Logger, api ec2API) (*LimitsGetter, error) {
	m, err := getAll(context.Background(), api)
	if err != nil {
		return nil, err
	}
	l := &LimitsGetter{
		logger: logger.With(subsysLogAttr...),
		api:    api,
		m:      m,
	}
	return l, nil
}

func getAll(ctx context.Context, api ec2API) (map[string]ipamTypes.Limits, error) {
	m := make(map[string]ipamTypes.Limits)

	instanceTypeInfos, err := api.GetInstanceTypes(ctx)
	if err != nil {
		return nil, err
	}
	for _, instanceTypeInfo := range instanceTypeInfos {
		m[string(instanceTypeInfo.InstanceType)] = ec2InstanceTypeInfoToLimit(instanceTypeInfo)
	}
	return m, err
}

// Get returns the instance limits of a particular instance type.
func (l *LimitsGetter) Get(ctx context.Context, instanceType string) (ipamTypes.Limits, error) {
	l.RLock()
	defer l.RUnlock()

	if limit, ok := l.m[instanceType]; ok {
		l.logger.Debug("Get limits from cache",
			logfields.Limit, limit,
			logfields.InstanceType, instanceType)
		return limit, nil
	}

	instanceTypeInfo, err := l.api.GetInstanceType(ctx, instanceType)
	if err != nil {
		return ipamTypes.Limits{}, err
	}
	limit := ec2InstanceTypeInfoToLimit(instanceTypeInfo)

	l.m[instanceType] = limit

	return limit, nil
}

func ec2InstanceTypeInfoToLimit(info ec2_types.InstanceTypeInfo) ipamTypes.Limits {
	return ipamTypes.Limits{
		Adapters:       int(aws.ToInt32(info.NetworkInfo.MaximumNetworkInterfaces)),
		IPv4:           int(aws.ToInt32(info.NetworkInfo.Ipv4AddressesPerInterface)),
		IPv6:           int(aws.ToInt32(info.NetworkInfo.Ipv6AddressesPerInterface)),
		HypervisorType: string(info.Hypervisor),
		IsBareMetal:    aws.ToBool(info.BareMetal),
	}

}
