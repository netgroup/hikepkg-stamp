// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

/* HIKe Prog Name comes always first */
#define HIKE_PROG_NAME    stamp_lite

/* filter out packets that are not needed
 * check if SSID corresponds to cached packet
 */

#define HIKE_PRINT_LEVEL HIKE_PRINT_LEVEL_DEBUG

#include "hike_vm.h"
#include "parse_helpers.h"

HIKE_PROG(HIKE_PROG_NAME)
{
        __u64 hvm_ret = 0;
        hike_pr_debug("hello");

out:
        HVM_RET = hvm_ret;
        return HIKE_XDP_VM;
drop:
        hike_pr_debug("drop packet");
        return HIKE_XDP_ABORTED;
}

EXPORT_HIKE_PROG_1(HIKE_PROG_NAME);

char LICENSE[] SEC("license") = "Dual BSD/GPL";