// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

/* HIKe Prog Name comes always first */
#define HIKE_PROG_NAME    collector

/* filter out packets that are not needed
 * check if SSID corresponds to cached packet
 */

//#define HIKE_PRINT_LEVEL HIKE_PRINT_LEVEL_DEBUG
#define HIKE_PRINT_LEVEL 0

#include "hike_vm.h"
#include "parse_helpers.h"
#include "stamplib.h"

bpf_map(map_time, HASH, __u8, __u64, 1);
bpf_map(map_collector, LRU_HASH, struct collector_key, struct collector_value,
        MAX_ENTRIES_COLLECTOR_MAP);

HIKE_PROG(HIKE_PROG_NAME)
{
        struct collector_value *col_value_print;
        struct collector_value col_value;
        struct collector_key col_key;
        struct stamp* stamp_ptr;
        __u64 receive_timestamp;
        struct hdr_cursor *cur;
        struct pkt_info *info;
        __u16 udp_dest;
        int offset = 0;
        __u64 boottime;
        //__u64 delta = 1;        /* use for TEST 2 */
        __u64 *delta;         /* use for TEST 1 */
        __u8 key = 0;
        long ret;

        /* retrieve packet information from HIKe shared memory*/
        info = hike_pcpu_shmem();
        if (unlikely(!info)) {
		hike_pr_debug("cannot retrieve pkt info");
                goto drop;
	}
        /* take the reference to the cursor object which has been saved into
        * the HIKe shared memory
        */
        cur = pkt_info_cur(info);
        /* no need for checking cur != NULL here */

        ret = ipv6_find_hdr(ctx, cur, &offset, IPPROTO_UDP, NULL, NULL);
        if (unlikely(ret < 0)) {
                hike_pr_debug("UDP not found; rc: %d", ret);
                goto drop;
        }

        offset += sizeof(struct udphdr);
        stamp_ptr = (struct stamp *)cur_header_pointer(ctx, cur, offset, 
                                                       sizeof(*stamp_ptr));
        if (unlikely(!stamp_ptr)) {
		hike_pr_debug("cannot retrieve stamp ptr");
                goto drop;
	}

        /* read boot time from kernel, read delta between kernel boot time
         * and user space clock real time from map. Add them up and get
         * current clock real time.
         * 
         * Need to have started already python script stamp_maps.py to populate
         * map with delta value, if map is empty, the packet is dropped.
         */
        boottime = bpf_ktime_get_boot_ns();
                                                    /* use for TEST 1 */
        delta = bpf_map_lookup_elem(&map_time, &key);
	if (unlikely(!delta)) {
                hike_pr_err("could not read delta from map");
                goto drop;
        }                                              /* until here */
        //receive_timestamp = boottime + delta;       /* use for TEST 2 */
        receive_timestamp = boottime + *delta;    /* use for TEST 1 */
        /* convert to NTP format */
        receive_timestamp = (__u64) (receive_timestamp / 1000000000) << 32 |
                            (receive_timestamp % 1000000000);
        /* prepare key and value structs for map */
        col_key.ssid = bpf_ntohs(stamp_ptr->ssid);
        col_key.seq_number = bpf_ntohl(stamp_ptr->seq_number);
        col_value.sender = bpf_be64_to_cpu(stamp_ptr->sess_send_timestamp);
        col_value.refl_receive = bpf_be64_to_cpu(stamp_ptr->receive_timestamp);
        col_value.refl_send = bpf_be64_to_cpu(stamp_ptr->timestamp);
        col_value.collector = receive_timestamp;
        /* write into map */
        /* use for real implementation */
        // ret = bpf_map_update_elem(&map_collector, &col_key, &col_value,
        //                           BPF_NOEXIST);

        /* TEST 1
         * delta represents a counter, instead of writing the timestamps
         * in their map, the counter is incremented and rewritten on map
         */
        *delta = *delta + 1;
        ret = bpf_map_update_elem(&map_time, &key, delta, BPF_EXIST);

        /* TEST 2
         * col_value.sender represents a counter
         * the counter is incremented and rewritten on map
         */
	// memset(&col_key, 0, sizeof(struct collector_key));
	// hike_pr_debug("key.ssid: %d\tkey.seq_number: %d", col_key.ssid, col_key.seq_number);
        // col_value_print = bpf_map_lookup_elem(&map_collector, &col_key);
        // if (unlikely(!col_value_print)) {
        //         hike_pr_err("could not read collector data from map");
        //         goto drop;
        // }
	// col_value.sender = col_value_print->sender + 1;
	// hike_pr_debug("sender: %d", col_value.sender);
        // ret = bpf_map_update_elem(&map_collector, &col_key, &col_value,
        //                           BPF_ANY);


	hike_pr_debug("map update ret: %d", ret);


// DEBUG...
        // col_value_print = bpf_map_lookup_elem(&map_collector, &col_key);
        // if (unlikely(!col_value_print)) {
        //         hike_pr_err("could not read collector data from map");
        //         goto drop;
        // }
        // hike_pr_debug("timestamps:\n%llx", col_value_print->sender);
        // hike_pr_debug("%llx", col_value_print->refl_receive);
        // hike_pr_debug("%llx", col_value_print->refl_send);
        // hike_pr_debug("%llx", col_value_print->collector);

drop:
        hike_pr_debug("drop packet");
        return HIKE_XDP_ABORTED;
out:
        hike_pr_debug("pass packet");
        return XDP_PASS;
}

EXPORT_HIKE_PROG_1(HIKE_PROG_NAME);
EXPORT_HIKE_PROG_MAP(HIKE_PROG_NAME, map_collector);
EXPORT_HIKE_PROG_MAP(HIKE_PROG_NAME, map_time);

char LICENSE[] SEC("license") = "Dual BSD/GPL";
