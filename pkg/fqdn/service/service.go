// Copyright 2023 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package service

import (
	"context"
	"fmt"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"google.golang.org/grpc/keepalive"
	"io"
	"net"
	"net/netip"
	"time"

	"google.golang.org/grpc"

	pb "github.com/cilium/cilium/api/v1/dnsproxy"

	"github.com/cilium/cilium/pkg/fqdn"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "fqdn/collector")

type FQDNCollectorServer struct {
	pb.UnimplementedFQNDCollectorServer
	dnsNameManager  *fqdn.NameManager
	endpointManager *endpointmanager.EndpointManager
}

func (s *FQDNCollectorServer) UpdateMappings(stream pb.FQNDCollector_UpdateMappingsServer) error {
	for {
		mapping, err := stream.Recv()
		if err == io.EOF {
			return stream.SendAndClose(&pb.Result{
				Success: true,
			})
		}
		if err != nil {
			return err
		}

		var responseIPs []netip.Addr
		var ips []net.IP
		for _, ip := range mapping.IPS {
			addr, _ := netip.ParseAddr(string(ip))
			responseIPs = append(responseIPs, addr)
			ips = append(ips, net.ParseIP(string(ip)))
		}
		log.Infof(fmt.Sprintf("Received mapping grpc : %s -> %s\n", mapping.FQDN, ips))

		ep := (*s.endpointManager).LookupIPv4(string(mapping.ClientIp))
		if ep != nil {
			ep.DNSHistory.Update(time.Now(), mapping.FQDN, responseIPs, 3600)
		} else {
			log.Errorf("Could not find endpoint for IP %s", string(mapping.ClientIp))
		}

		s.dnsNameManager.UpdateGenerateDNS(context.TODO(), time.Now(), map[string]*fqdn.DNSIPRecords{
			mapping.FQDN: {
				IPs: ips,
				TTL: int(3600),
			}})
	}
}

func newServer(dnsNameManager *fqdn.NameManager, endpointManager *endpointmanager.EndpointManager) *FQDNCollectorServer {
	s := &FQDNCollectorServer{
		dnsNameManager:  dnsNameManager,
		endpointManager: endpointManager,
	}
	return s
}

func RunServer(port int, dnsNameManager *fqdn.NameManager, endpointManager *endpointmanager.EndpointManager) {
	lis, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	var opts []grpc.ServerOption
	enforcement := keepalive.EnforcementPolicy{
		MinTime:             5 * time.Second,
		PermitWithoutStream: true,
	}
	opts = append(opts, grpc.KeepaliveEnforcementPolicy(enforcement))
	opts = append(opts, grpc.KeepaliveParams(keepalive.ServerParameters{}))
	grpcServer := grpc.NewServer(opts...)
	pb.RegisterFQNDCollectorServer(grpcServer, newServer(dnsNameManager, endpointManager))
	grpcServer.Serve(lis)
}
