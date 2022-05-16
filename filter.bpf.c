// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

/* HIKe Prog Name comes always first */
#define HIKE_PROG_NAME    filter

/* filter out packets that are not needed
 * check if packet is UDP
 * check if UDP dest port is STAMP
 */

#define HIKE_PRINT_LEVEL HIKE_PRINT_LEVEL_DEBUG

#include "hike_vm.h"
#include "parse_helpers.h"
#include "stamplib.h"

HIKE_PROG(HIKE_PROG_NAME)
{
        struct hdr_cursor *cur;
        struct pkt_info *info;
        __u64 hvm_ret = 0; /* set to 1 if packet won't be processed */
        int offset;
        __be16 *udp_dest;
        int ret;

        /* retrieve packet information from HIKe shared memory*/
        info = hike_pcpu_shmem();
        if (unlikely(!info))
                goto drop;

        /* take the reference to the cursor object which has been saved into
         * the HIKe shared memory
         */
        cur = pkt_info_cur(info);
        /* no need for checking cur != NULL here */

        /* we search for the UDP protocol just after the L3 one which should
	 * be, in this case, the IPv6 protocol.
	 */
	offset = cur->nhoff;
        ret = ipv6_find_hdr(ctx, cur, &offset, IPPROTO_UDP, NULL, NULL);
        if (unlikely(ret < 0)) {
                hike_pr_debug("UDP not found; rc: %d", ret);
                hvm_ret = 1;
                goto out;
        }

        /* set offset to UDP destination port */
        offset += 2;

        udp_dest = (__be16 *)cur_header_pointer(ctx, cur, offset, 2);
        if (unlikely(!udp_dest)) 
                goto drop;

        if (bpf_ntohs(*udp_dest) != STAMP_DST_PORT) {
                hike_pr_debug("Destination port is not STAMP: %u", bpf_ntohs(*udp_dest));
                hvm_ret = 1;
                goto out;
        }

/*      won't check if size of the packet is enough to contain STAMP
        useless overhead

        hike_pr_debug("sizeof struct eth_ipv6_srh: %lu", sizeof(struct eth_ipv6_srh));
        hike_pr_debug("size of 2 segments: 32");
        hike_pr_debug("sizeof struct udp_stamp: %lu", sizeof(struct udp_stamp));
        hike_pr_debug("sizeof(struct pkt_info): %lu", sizeof(struct pkt_info));
        hike_pr_debug("ctx->data: %u, ctx->data_end: %u", ctx->data, ctx->data_end);
        hike_pr_debug("packet size: ctx->data_end - ctx->data = %d", ctx->data_end - ctx->data);
 */

out:
        hike_pr_debug("hvm_ret: %d", hvm_ret);
        HVM_RET = hvm_ret;
        return HIKE_XDP_VM;
drop:
        hike_pr_debug("drop packet");
        return HIKE_XDP_ABORTED;
}

EXPORT_HIKE_PROG_1(HIKE_PROG_NAME);

char LICENSE[] SEC("license") = "Dual BSD/GPL";