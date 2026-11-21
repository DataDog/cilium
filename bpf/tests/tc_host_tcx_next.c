// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/* BPF_PROG_TEST_RUN runs the program on the loopback device. */
#define EXPECTED_VERDICT	TCX_NEXT

#include "tc_host_tcx_next.h"

ASSIGN_CONFIG(__u32, interface_ifindex, 1)
