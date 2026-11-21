// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/* Packets on another device than the one the program is attached to, e.g.
 * when cil_host_policy is tail called from a pod's hook, keep TC_ACT_OK.
 */
#define EXPECTED_VERDICT	TC_ACT_OK

#include "tc_host_tcx_next.h"

ASSIGN_CONFIG(__u32, interface_ifindex, 42)
