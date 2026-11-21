/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

#define ENABLE_IPV4

#include "lib/bpf_host.h"

ASSIGN_CONFIG(bool, enable_host_tcx_next, true)

/* Ethertype unknown to Cilium (IEEE 802 local experimental), which
 * cil_from_netdev passes up the stack.
 */
#define UNKNOWN_ETH_P	0x88B5

PKTGEN(PROG_TYPE, "tc_host_tcx_next")
int host_tcx_next_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct ethhdr *l2;

	pktgen__init(&builder, ctx);

	l2 = pktgen__push_ethhdr(&builder);
	if (!l2)
		return TEST_ERROR;
	ethhdr__set_macs(l2, (__u8 *)mac_one, (__u8 *)mac_two);
	l2->h_proto = bpf_htons(UNKNOWN_ETH_P);

	pktgen__finish(&builder);
	return 0;
}

SETUP(PROG_TYPE, "tc_host_tcx_next")
int host_tcx_next_setup(struct __ctx_buff *ctx)
{
	return netdev_receive_packet(ctx);
}

CHECK(PROG_TYPE, "tc_host_tcx_next")
int host_tcx_next_check(const struct __ctx_buff *ctx)
{
	void *data = ctx_data(ctx);
	void *data_end = ctx_data_end(ctx);
	__u32 *status_code;

	test_init();

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	assert(*status_code == (__u32)EXPECTED_VERDICT);

	test_finish();
}
