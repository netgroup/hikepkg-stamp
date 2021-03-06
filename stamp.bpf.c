// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

/* HIKe Prog Name comes always first */
#define HIKE_PROG_NAME    stamp

/*
 * Only works on UDP packets. Implements STAMP protocol.
 * 
 * Need to populate map with the "stamp_maps.py" script to work.
 * If map is empty, the packet is dropped.
 */

#define HIKE_PRINT_LEVEL HIKE_PRINT_LEVEL_DEBUG

#define REAL
//#define REPL

#include <linux/udp.h>
#include <linux/ipv6.h>

#ifdef REAL
  #include "hike_vm.h"
  #include "parse_helpers.h"
#endif  

#ifdef REPL
  #define HIKE_DEBUG 1 
  //#include "tb_defs.h"
  #include "ip6_hset_repl.h"
  #include "mock.h"

#endif

#define STAMP_DST_PORT 862
#define ERROR_ESTIMATE 0x8001

struct stamp {
  __be32 seq_number;
  __be64 timestamp;
  __be16 error_estimate;
  __be16 ssid;
  __be64 receive_timestamp;
  __be32 sess_send_seq_num;
  __be64 sess_send_timestamp;
  __be16 sess_send_err_estimate;
  __u16 mbz_16;
  __u8 sess_send_ttl;
} __attribute__((packed));

bpf_map(map_time, HASH, __u8, __u64, 1);

HIKE_PROG(HIKE_PROG_NAME)
{
  struct stamp* stamp_ptr;
  __u64 receive_timestamp;
  struct hdr_cursor *cur;
  struct pkt_info *info;
  struct ipv6hdr *ip6h;
  struct udphdr *udph;
  __u64 hvm_ret = 0; /* set to 1 if packet won't be processed */
  __u32 nanoseconds;
  __u64 timestamp;
  __u16 udp_dest;
  __u16 udp_poff; //udp payload offset
  __u64 boottime;
  int offset = 0;
  __u32 seconds;
  __u64 *delta;
  __u8 key = 0;
  __u8 ttl;
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

  /* get TTL from IPv6 packet */
  ip6h = (struct ipv6hdr *)cur_header_pointer(ctx, cur, cur->nhoff, sizeof(*ip6h));
  if (unlikely(!ip6h)) 
    goto drop;
  ttl = ip6h->hop_limit;

  /* ipv6_find_hdr is defined in parse_helpers.h
   * when the fourth parameter is -1, it returns the 
   * "layer 4" final protocol
   */
  ret = ipv6_find_hdr(ctx, cur, &offset, IPPROTO_UDP, NULL, NULL);
  if (unlikely(ret < 0)) {
    hike_pr_debug("UDP not found; rc: %d", ret);
    hvm_ret = 1;
    goto out;
  }

  udph = (struct udphdr *)cur_header_pointer(ctx, cur, offset, sizeof(*udph));
  if (unlikely(!udph)) 
    goto drop;

  udp_dest = bpf_ntohs(udph->dest);
  if (udp_dest != STAMP_DST_PORT) {
    hike_pr_debug("Destination port is not STAMP: %u", udp_dest);
    hvm_ret = 1;
    goto out;
  }

  udp_poff = offset + sizeof(*udph);
  stamp_ptr = (struct stamp *)cur_header_pointer(ctx, cur, udp_poff, 
                                    sizeof(*stamp_ptr));
  if (unlikely(!stamp_ptr))
    goto drop;

/* read boot time from kernel, read delta between kernel boot time
 * and user space clock real time from map. Add them up and get
 * current clock real time.
 * 
 * Need to have started already python script stamp_maps.py to populate
 * map with delta value, if map is empty, the packet is dropped.
 */
  timestamp = stamp_ptr->timestamp;
  hike_pr_debug("sender timestamp: %llx", bpf_be64_to_cpu(timestamp));
  boottime = bpf_ktime_get_boot_ns();
  hike_pr_debug("boot time (nanoseconds): %llx", boottime);
  delta = bpf_map_lookup_elem(&map_time, &key);
  if (unlikely(!delta)) {
    hike_pr_err("could not read delta from map");
		goto drop;
  }
  hike_pr_debug("delta (nanoseconds): %llx", *delta);
  receive_timestamp = boottime + *delta;
  hike_pr_debug("receive timestamp (nanoseconds): %llx", receive_timestamp);
  seconds = receive_timestamp / 1000000000;
  nanoseconds = receive_timestamp % 1000000000;
  receive_timestamp = (__u64) seconds << 32 | nanoseconds;
  hike_pr_debug("receive timestamp (NTP): %llx", receive_timestamp);
  receive_timestamp = bpf_cpu_to_be64(receive_timestamp);
  hike_pr_debug("new timestamp be (NTP): %llx", receive_timestamp);
  stamp_ptr->timestamp = receive_timestamp;
  stamp_ptr->receive_timestamp = receive_timestamp;
  stamp_ptr->sess_send_seq_num = stamp_ptr->seq_number;
  stamp_ptr->sess_send_timestamp = timestamp;
  stamp_ptr->sess_send_err_estimate = stamp_ptr->error_estimate;
  stamp_ptr->error_estimate = bpf_htons(ERROR_ESTIMATE);
  stamp_ptr->sess_send_ttl = ttl;

out:
  HVM_RET = hvm_ret;
	return HIKE_XDP_VM;

drop:
  hike_pr_debug("drop packet");
	return HIKE_XDP_ABORTED;

}

// #undef eth_h 
#undef ip6h  
#undef udph

EXPORT_HIKE_PROG_1(HIKE_PROG_NAME);
EXPORT_HIKE_PROG_MAP(HIKE_PROG_NAME, map_time);

#ifdef REAL
char LICENSE[] SEC("license") = "Dual BSD/GPL";
#endif
