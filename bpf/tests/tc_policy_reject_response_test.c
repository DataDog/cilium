// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/* Enable code paths under test */
#define ENABLE_IPV4
#define TUNNEL_MODE

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

#include <bpf/config/node.h>
ASSIGN_CONFIG(bool, policy_deny_response_enabled, true)

#include <bpf_lxc.c>
#include "lib/endpoint.h"
#include "lib/ipcache.h"
#include "lib/policy.h"

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 1);
	__array(values, int());
} entry_call_map __section(".maps") = {
	.values = {
		[0] = &cil_from_container,
	},
};

#define CLIENT_IP v4_pod_one
#define TARGET_IP v4_ext_one
#define REMOTE_POD_IP v4_pod_two
#define LOCAL_POD_TARGET_IP v4_pod_three
#define REMOTE_CLUSTER_IP v4_node_one
#define TUNNEL_ENDPOINT_IP v4_node_two

/* Test case 1: Egress policy deny (local pod -> external) */
PKTGEN("tc", "policy_reject_response_v4_egress")
int policy_reject_response_egress_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)mac_one, (__u8 *)mac_two,
					  CLIENT_IP, TARGET_IP,
					  tcp_src_one, tcp_dst_one);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

/* Test case 2: Ingress policy deny (external -> local pod) */
PKTGEN("tc", "policy_reject_response_v4_ingress_external")
int policy_reject_response_ingress_external_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)mac_two, (__u8 *)mac_one,
					  TARGET_IP, CLIENT_IP,  /* External -> Local pod */
					  tcp_src_one, tcp_dst_one);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

/* Test case 3: Ingress policy deny (local pod -> local pod, same node) */
PKTGEN("tc", "policy_reject_response_v4_ingress_local")
int policy_reject_response_ingress_local_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)mac_two, (__u8 *)mac_one,
					  REMOTE_POD_IP, LOCAL_POD_TARGET_IP,  /* Pod -> Pod */
					  tcp_src_one, tcp_dst_one);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

/* Test case 4: Ingress policy deny (remote cluster endpoint -> local pod via tunnel) */
PKTGEN("tc", "policy_reject_response_v4_ingress_tunnel")
int policy_reject_response_ingress_tunnel_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)mac_two, (__u8 *)mac_one,
					  REMOTE_CLUSTER_IP, CLIENT_IP,  /* Remote cluster -> Local pod */
					  tcp_src_one, tcp_dst_one);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

/* Setup for egress policy deny test */
SETUP("tc", "policy_reject_response_v4_egress")
int policy_reject_response_egress_setup(struct __ctx_buff *ctx)
{
	/* Add endpoint for source */
	endpoint_v4_add_entry(CLIENT_IP, 0, 0, 0, 0, 0, NULL, NULL);

	/* Add ipcache entries */
	ipcache_v4_add_entry(CLIENT_IP, 0, 112233, 0, 0);   /* Local pod */
	ipcache_v4_add_entry(TARGET_IP, 0, 445566, 0, 0);   /* External */

	/* Add policy that denies egress to target */
	policy_add_egress_deny_all_entry();

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, 0);
	return TEST_ERROR;
}

/* Setup for ingress policy deny from external source */
SETUP("tc", "policy_reject_response_v4_ingress_external")
int policy_reject_response_ingress_external_setup(struct __ctx_buff *ctx)
{
	/* Add endpoint for target (local pod) */
	endpoint_v4_add_entry(CLIENT_IP, 0, 0, 0, 0, 0, NULL, NULL);

	/* Add ipcache entries */
	ipcache_v4_add_entry(CLIENT_IP, 0, 112233, 0, 0);   /* Local pod target */
	ipcache_v4_add_entry(TARGET_IP, 0, 445566, 0, 0);   /* External source */

	/* Add policy that denies ingress from external sources */
	policy_add_ingress_deny_all_entry();

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, 0);
	return TEST_ERROR;
}

/* Setup for ingress policy deny from local pod */
SETUP("tc", "policy_reject_response_v4_ingress_local")
int policy_reject_response_ingress_local_setup(struct __ctx_buff *ctx)
{
	/* Add endpoints for both source and target pods */
	endpoint_v4_add_entry(REMOTE_POD_IP, 0, 0, 0, 0, 0, NULL, NULL);         /* Source pod */
	endpoint_v4_add_entry(LOCAL_POD_TARGET_IP, 0, 0, 0, 0, 0, NULL, NULL);   /* Target pod */

	/* Add ipcache entries */
	ipcache_v4_add_entry(REMOTE_POD_IP, 0, 778899, 0, 0);         /* Source local pod */
	ipcache_v4_add_entry(LOCAL_POD_TARGET_IP, 0, 998877, 0, 0);   /* Target local pod */

	/* Add policy that denies ingress between local pods */
	policy_add_ingress_deny_all_entry();

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, 0);
	return TEST_ERROR;
}

/* Setup for ingress policy deny from remote cluster via tunnel */
SETUP("tc", "policy_reject_response_v4_ingress_tunnel")
int policy_reject_response_ingress_tunnel_setup(struct __ctx_buff *ctx)
{
	/* Add endpoint for target (local pod) */
	endpoint_v4_add_entry(CLIENT_IP, 0, 0, 0, 0, 0, NULL, NULL);

	/* Add ipcache entries for cluster endpoints */
	ipcache_v4_add_entry(CLIENT_IP, 0, 112233, 0, 0);               /* Local pod target */
	ipcache_v4_add_entry_with_flags(REMOTE_CLUSTER_IP, 0, 334455, 
					TUNNEL_ENDPOINT_IP, 0, false);  /* Remote cluster source with tunnel */

	/* Add policy that denies ingress from remote cluster */
	policy_add_ingress_deny_all_entry();

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, 0);
	return TEST_ERROR;
}

/* Check for egress policy deny test */
CHECK("tc", "policy_reject_response_v4_egress")
int policy_reject_response_egress_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct iphdr *l3;
	struct icmphdr *icmp;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	/* Should redirect ICMP response back to local interface */
	assert(*status_code == TC_ACT_REDIRECT);

	l3 = data + sizeof(__u32) + sizeof(struct ethhdr);

	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	/* Verify this is an ICMP response packet */
	if (l3->protocol != IPPROTO_ICMP)
		test_fatal("expected ICMP protocol, got %d", l3->protocol);

	/* For egress: source should be target, destination should be client */
	if (l3->saddr != TARGET_IP)
		test_fatal("ICMP src should be target IP");

	if (l3->daddr != CLIENT_IP)
		test_fatal("ICMP dst should be client IP");

	icmp = (void *)l3 + sizeof(struct iphdr);

	if ((void *)icmp + sizeof(struct icmphdr) > data_end)
		test_fatal("ICMP header out of bounds");

	/* Verify ICMP error type and code for policy rejection */
	if (icmp->type != ICMP_DEST_UNREACH)
		test_fatal("expected ICMP_DEST_UNREACH, got type %d", icmp->type);

	if (icmp->code != ICMP_PKT_FILTERED)
		test_fatal("expected ICMP_PKT_FILTERED, got code %d", icmp->code);

	test_finish();
}

/* Check for ingress policy deny from external source */
CHECK("tc", "policy_reject_response_v4_ingress_external")
int policy_reject_response_ingress_external_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct iphdr *l3;
	struct icmphdr *icmp;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	/* Should redirect ICMP response back via host interface for external source */
	assert(*status_code == TC_ACT_REDIRECT);

	l3 = data + sizeof(__u32) + sizeof(struct ethhdr);

	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	/* Verify this is an ICMP response packet */
	if (l3->protocol != IPPROTO_ICMP)
		test_fatal("expected ICMP protocol, got %d", l3->protocol);

	/* For ingress from external: source should be local pod, destination should be external source */
	if (l3->saddr != CLIENT_IP)
		test_fatal("ICMP src should be local pod IP, got %x", l3->saddr);

	if (l3->daddr != TARGET_IP)
		test_fatal("ICMP dst should be external source IP, got %x", l3->daddr);

	icmp = (void *)l3 + sizeof(struct iphdr);

	if ((void *)icmp + sizeof(struct icmphdr) > data_end)
		test_fatal("ICMP header out of bounds");

	/* Verify ICMP error type and code for policy rejection */
	if (icmp->type != ICMP_DEST_UNREACH)
		test_fatal("expected ICMP_DEST_UNREACH, got type %d", icmp->type);

	if (icmp->code != ICMP_PKT_FILTERED)
		test_fatal("expected ICMP_PKT_FILTERED, got code %d", icmp->code);

	test_finish();
}

/* Check for ingress policy deny from local pod */
CHECK("tc", "policy_reject_response_v4_ingress_local")
int policy_reject_response_ingress_local_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct iphdr *l3;
	struct icmphdr *icmp;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	/* Should redirect ICMP response back to local interface for local source */
	assert(*status_code == TC_ACT_REDIRECT);

	l3 = data + sizeof(__u32) + sizeof(struct ethhdr);

	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	/* Verify this is an ICMP response packet */
	if (l3->protocol != IPPROTO_ICMP)
		test_fatal("expected ICMP protocol, got %d", l3->protocol);

	/* For ingress from local pod: source should be target pod, destination should be source pod */
	if (l3->saddr != LOCAL_POD_TARGET_IP)
		test_fatal("ICMP src should be target pod IP, got %x", l3->saddr);

	if (l3->daddr != REMOTE_POD_IP)
		test_fatal("ICMP dst should be source pod IP, got %x", l3->daddr);

	icmp = (void *)l3 + sizeof(struct iphdr);

	if ((void *)icmp + sizeof(struct icmphdr) > data_end)
		test_fatal("ICMP header out of bounds");

	/* Verify ICMP error type and code for policy rejection */
	if (icmp->type != ICMP_DEST_UNREACH)
		test_fatal("expected ICMP_DEST_UNREACH, got type %d", icmp->type);

	if (icmp->code != ICMP_PKT_FILTERED)
		test_fatal("expected ICMP_PKT_FILTERED, got code %d", icmp->code);

	test_finish();
}

/* Check for ingress policy deny from remote cluster via tunnel */
CHECK("tc", "policy_reject_response_v4_ingress_tunnel")
int policy_reject_response_ingress_tunnel_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct iphdr *l3;
	struct icmphdr *icmp;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	/* Should redirect ICMP response back via tunnel encapsulation */
	assert(*status_code == TC_ACT_REDIRECT);

	l3 = data + sizeof(__u32) + sizeof(struct ethhdr);

	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	/* Verify this is an ICMP response packet */
	if (l3->protocol != IPPROTO_ICMP)
		test_fatal("expected ICMP protocol, got %d", l3->protocol);

	/* For ingress from remote cluster: source should be local pod, destination should be remote cluster IP */
	if (l3->saddr != CLIENT_IP)
		test_fatal("ICMP src should be local pod IP, got %x", l3->saddr);

	if (l3->daddr != REMOTE_CLUSTER_IP)
		test_fatal("ICMP dst should be remote cluster IP, got %x", l3->daddr);

	icmp = (void *)l3 + sizeof(struct iphdr);

	if ((void *)icmp + sizeof(struct icmphdr) > data_end)
		test_fatal("ICMP header out of bounds");

	/* Verify ICMP error type and code for policy rejection */
	if (icmp->type != ICMP_DEST_UNREACH)
		test_fatal("expected ICMP_DEST_UNREACH, got type %d", icmp->type);

	if (icmp->code != ICMP_PKT_FILTERED)
		test_fatal("expected ICMP_PKT_FILTERED, got code %d", icmp->code);

	test_finish();
}
