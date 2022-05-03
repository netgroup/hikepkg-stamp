// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

/* HIKe Prog Name comes always first */
#define HIKE_PROG_NAME    cache

/* filter out packets that are not needed
 * check if SSID corresponds to cached packet
 */

#define HIKE_PRINT_LEVEL HIKE_PRINT_LEVEL_DEBUG

#include "hike_vm.h"
#include "parse_helpers.h"
#include "stamplib.h"

bpf_map(map_cache_l23, LRU_HASH, __be16, struct eth_ipv6_srh,
        MAX_ENTRIES_CACHE_MAP);
bpf_map(map_cache_l4, LRU_HASH, __be16, struct udp_stamp,
        MAX_ENTRIES_CACHE_MAP);

HIKE_PROG(HIKE_PROG_NAME)
{
        struct eth_ipv6_srh *l23;
        struct hdr_cursor *cur;
        struct pkt_info *info;
        struct udp_stamp *l4;
        int offset = 0;
        long ret;

        /* retrieve packet information from HIKe shared memory*/
        info = hike_pcpu_shmem();
        if (unlikely(!info))
                goto drop;
        /* take the reference to the cursor object which has been saved into
        * the HIKe shared memory
        */
        cur = pkt_info_cur(info);
        /* no need for checking cur != NULL here */

        /* layer 2 and 3: Ethernet, IPv6 and SRH headers */
        l23 = (struct eth_ipv6_srh *)cur_header_pointer(ctx, cur, cur->mhoff,
                                                        sizeof(*l23));
        if (unlikely(!l23))
                goto drop;

        /* TODO: segment list */

        /* layer 4: UDP header and STAMP payload */
        ret = ipv6_find_hdr(ctx, cur, &offset, IPPROTO_UDP, NULL, NULL);
        if (unlikely(ret < 0))
        {
                hike_pr_err("UDP not found; rc: %d", ret);
                goto drop;
        }
        l4 = (struct udp_stamp *)cur_header_pointer(ctx, cur, offset,
                                                    sizeof(*l4));
        if (unlikely(!l4))
                goto drop;

        hike_pr_debug("ssid: 0x%x", bpf_ntohs(l4->stamp.ssid));

        /* cache data in maps, use SSID as key */
        ret = bpf_map_update_elem(&map_cache_l23, &l4->stamp.ssid, l23,
                                  BPF_NOEXIST);
        if (unlikely(ret != 0))
        {
                hike_pr_err("cannot update l23 map, err: %d", ret);
                goto drop;
        }

        ret = bpf_map_update_elem(&map_cache_l4, &l4->stamp.ssid, l4,
                                  BPF_NOEXIST);
        if (unlikely(ret != 0))
        {
                hike_pr_err("cannot update l4 map, err: %d", ret);
                goto drop;
        }
        



        hike_pr_debug("hello");

        HVM_RET = 0;
        return HIKE_XDP_VM;
drop:
        hike_pr_debug("drop packet");
        return HIKE_XDP_ABORTED;
}

EXPORT_HIKE_PROG_1(HIKE_PROG_NAME);
EXPORT_HIKE_PROG_MAP(HIKE_PROG_NAME, map_cache_l23);
EXPORT_HIKE_PROG_MAP(HIKE_PROG_NAME, map_cache_l4);

char LICENSE[] SEC("license") = "Dual BSD/GPL";