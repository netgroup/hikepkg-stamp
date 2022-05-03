// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

/* HIKe Prog Name comes always first */
#define HIKE_PROG_NAME    stamp_full

/* filter out packets that are not needed
 * check if SSID corresponds to cached packet
 */

#define HIKE_PRINT_LEVEL HIKE_PRINT_LEVEL_DEBUG

#include "hike_vm.h"
#include "parse_helpers.h"
#include "stamplib.h"

bpf_map(map_time, HASH, __u8, __u64, 1);

HIKE_PROG(HIKE_PROG_NAME)
{
        struct eth_ipv6_srh *l23;
        __u64 receive_timestamp;
        struct hdr_cursor *cur;
        struct pkt_info *info;
        struct udp_stamp *l4;
        int offset = 0;
        __u64 boottime;
        __u64 *delta;
        __u8 key = 0;
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

        /* read boot time from kernel, read delta between kernel boot time
         * and user space clock real time from map. Add them up and get
         * current clock real time.
         * 
         * Need to have started already python script stamp_maps.py to populate
         * map with delta value, if map is empty, the packet is dropped.
         */
        boottime = bpf_ktime_get_boot_ns();
        delta = bpf_map_lookup_elem(&map_time, &key);
        if (unlikely(!delta)) {
                hike_pr_err("could not read delta from map");
                goto drop;
        }
        receive_timestamp = boottime + *delta;
        /* converto to NTP format */
        receive_timestamp = (__u64) (receive_timestamp / 1000000000) << 32 |
                            (receive_timestamp % 1000000000);
        l4->stamp.timestamp = bpf_cpu_to_be64(receive_timestamp);
        l4->stamp.receive_timestamp = bpf_cpu_to_be64(receive_timestamp);
        l4->stamp.sess_send_seq_num = l4->stamp.seq_number;
        l4->stamp.sess_send_timestamp = l4->stamp.timestamp;
        l4->stamp.sess_send_err_estimate = l4->stamp.error_estimate;
        l4->stamp.error_estimate = bpf_htons(ERROR_ESTIMATE);
        l4->stamp.sess_send_ttl = l23->ip6h.hop_limit;



        hike_pr_debug("hello");
        HVM_RET = 0;
        return HIKE_XDP_VM;
drop:
        hike_pr_debug("drop packet");
        return HIKE_XDP_ABORTED;
}

EXPORT_HIKE_PROG_1(HIKE_PROG_NAME);
EXPORT_HIKE_PROG_MAP(HIKE_PROG_NAME, map_time);

char LICENSE[] SEC("license") = "Dual BSD/GPL";