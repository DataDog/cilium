package main

import (
	"context"
	"flag"
	dnsproxy2 "github.com/cilium/cilium/api/v1/dnsproxy"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/fqdn/dnsproxy"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

var (
	grpcServerAddr = flag.String("grpc_server_addr", "localhost:10000", "The server address in the format of host:port")
	log            = logging.DefaultLogger.WithField(logfields.LogSubsys, "dns-proxy-standalone")
	client         dnsproxy2.FQNDCollectorClient
	stream         dnsproxy2.FQNDCollector_UpdateMappingsClient
)

func main() {
	logging.SetLogLevel(logrus.DebugLevel)
	var opts []grpc.DialOption
	opts = append(opts, grpc.WithInsecure())

	opts = append(opts, grpc.WithBlock())
	opts = append(opts, grpc.WithKeepaliveParams(keepalive.ClientParameters{
		Time:                10,
		PermitWithoutStream: true,
	}))

	conn, err := grpc.Dial(*grpcServerAddr, opts...)
	if err != nil {
		log.Errorf("fail to dial: %v", err)
	}
	defer conn.Close()
	client = dnsproxy2.NewFQNDCollectorClient(conn)
	stream, err = client.UpdateMappings(context.TODO())
	if err != nil {
		log.Errorf("failed to create stream: %v", err)
		return
	}

	_, err = dnsproxy.StartDNSProxy("", 10001, false, 50, nil, nil, nil, handleDNSCallback, 500, time.Minute, true)
	if err != nil {
		log.WithError(err).Fatal("Unable to start standalone DNS proxy")
	}
	exitSignal := make(chan os.Signal)
	signal.Notify(exitSignal, syscall.SIGINT, syscall.SIGTERM)
	<-exitSignal
}

func sendWithRetry(message *dnsproxy2.FQDNMapping) {
	var err error
	reCreatedStream := false
	if stream == nil {
		log.Errorf("Stream unavailable")
		reCreatedStream = true
		stream, err = client.UpdateMappings(context.TODO())
		if err != nil {
			log.Errorf("failed to create stream: %v", err)
			return
		}
	}
	err = stream.Send(message)
	if err != nil {
		log.Errorf("Unable to send msg to cilium", err)
		if reCreatedStream {
			// Bail out here, since we already attempted to re-create the stream earlier
			return
		}
		// TODO(hemanthmalla) : Improve error handling and retry behavior
		if err.Error() == "EOF" {
			stream, err = client.UpdateMappings(context.TODO())
			if err != nil {
				log.Errorf("failed to create stream: %v", err)
				return
			}
			err = stream.Send(message)
			if err != nil {
				log.Errorf("Unable to send msg to cilium", err)
			} else {
				log.Infof("Sent message for %s - %v : attempt 2", message.FQDN, message.IPS)
			}
		}
	} else {
		log.Infof("Sent message for %s - %v", message.FQDN, message.IPS)
	}
}

func handleDNSCallback(lookupTime time.Time, ep *endpoint.Endpoint, epIPPort string,
	serverID identity.NumericIdentity, serverAddr string, msg *dns.Msg,
	protocol string, allowed bool, stat *dnsproxy.ProxyRequestContext) error {
	log.Infof("Recieved a callback for DNS response !! %v from %v", *msg, epIPPort)

	qname, responseIPs, TTL, CNAMEs, rcode, recordTypes, qTypes, err := dnsproxy.ExtractMsgDetails(msg)
	if err != nil {
		log.WithError(err).Error("cannot extract DNS message details")
		return err
	}
	log.Infof(qname, responseIPs, TTL, CNAMEs, rcode, recordTypes, qTypes)
	if !msg.Response {
		log.Infof("Not a DNS response returning..")
		return nil
	}

	var ips [][]byte
	for _, i := range responseIPs {
		log.Infof("%s is mapped to %s", qname, i.String())
		ips = append(ips, []byte(i.String()))
	}
	var clientIp string
	if epIPPort != "" {
		clientIp = strings.Split(epIPPort, ":")[0]
	}
	message := dnsproxy2.FQDNMapping{
		FQDN:     qname,
		IPS:      ips,
		TTL:      int32(TTL),
		ClientIp: []byte(clientIp),
	}
	ch := make(chan string, 1)
	go func() {
		sendWithRetry(&message)
		ch <- "done"
	}()

	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		// TODO: Cancel goroutine context after timeout
		log.Warningf("Timed out while trying to notify agent for %s mappings", qname)
	}

	return nil
}
