// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

/* HIKe Prog Name comes always first */
#define HIKE_PROG_NAME    filter

/* filter out packets that are not needed
 * check if SSID corresponds to cached packet
 */

#define HIKE_PRINT_LEVEL HIKE_PRINT_LEVEL_DEBUG

#include <linux/udp.h>

#include "hike_vm.h"
#include "parse_helpers.h"
#include "stamplib.h"

#define CACHED_PKT 0
#define NEW_PKT 1
#define NON_STAMP_PKT 2

bpf_map(map_cache_l23, LRU_HASH, __be16, struct eth_ipv6_srh,
        MAX_ENTRIES_CACHE_MAP);

HIKE_PROG(HIKE_PROG_NAME)
{
        __u64 hvm_ret = CACHED_PKT;
        struct stamp* stamp_ptr;
        struct hdr_cursor *cur;
        struct pkt_info *info;
        struct udphdr *udph;
        int offset = 0;
        __u16 udp_dest;
        char *map_ptr;
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

        ret = ipv6_find_hdr(ctx, cur, &offset, IPPROTO_UDP, NULL, NULL);
        if (unlikely(ret < 0)) {
                hike_pr_debug("UDP not found; rc: %d", ret);
                hvm_ret = NON_STAMP_PKT;
                goto out;
        }

        udph = (struct udphdr *)cur_header_pointer(ctx, cur, offset, sizeof(*udph));
        if (unlikely(!udph)) 
                goto drop;

        udp_dest = bpf_ntohs(udph->dest);
        if (udp_dest != STAMP_DST_PORT) {
                hike_pr_debug("Destination port is not STAMP: %u", udp_dest);
                hvm_ret = NON_STAMP_PKT;
                goto out;
        }

        offset += sizeof(*udph);
        stamp_ptr = (struct stamp *)cur_header_pointer(ctx, cur, offset, 
                                                       sizeof(*stamp_ptr));
        if (unlikely(!stamp_ptr))
                goto drop;

        /* check if packet is cached or is new */
        hike_pr_debug("ssid: 0x%x", bpf_ntohs(stamp_ptr->ssid));
        map_ptr = bpf_map_lookup_elem(&map_cache_l23, &stamp_ptr->ssid);
        if (unlikely(!map_ptr))
                hvm_ret = NEW_PKT;
        else
                hike_pr_debug("pointer: 0x%x", map_ptr);

out:
        hike_pr_debug("hvm_ret: %d", hvm_ret);
        HVM_RET = hvm_ret;
        return HIKE_XDP_VM;
drop:
        hike_pr_debug("drop packet");
        return HIKE_XDP_ABORTED;
}

EXPORT_HIKE_PROG_1(HIKE_PROG_NAME);
EXPORT_HIKE_PROG_MAP(HIKE_PROG_NAME, map_cache_l23);

char LICENSE[] SEC("license") = "Dual BSD/GPL";