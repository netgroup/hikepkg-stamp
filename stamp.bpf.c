// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

/* HIKe Prog Name comes always first */
#define HIKE_PROG_NAME    stamp

/*
 * Only works on UDP packets. Implements STAMP protocol.
 * 
 * TODO: finish protocol implementation. Receive timestamp done.
 * 
 * Need to populate map with the "stamp_maps.py" script to work.
 * If map is empty, the packet is dropped.
 */

#define HIKE_DEBUG 1

#define REAL
//#define REPL

#include <linux/udp.h>

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

struct stamp {
  __u32 seq_number;
  __u64 timestamp;
  __u16 error_estimate;
  __u16 ssid;
  __u64 receive_timestamp;
  __u32 sess_send_seq_num;
  __u32 sess_send_timestamp;
  __u16 sess_send_err_estimate;
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
  struct udphdr *udph;
  __u64 hvm_ret = 0; /* set to 1 if packet won't be processed */
  __u64 timestamp;
  __u16 udp_dest;
  __u16 udp_plen;
  __u16 udp_poff; //udp payload offset
  __u64 boottime;
  int offset = 0;
  __u64 *delta;
  __u8 key = 0;
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

  /* ipv6_find_hdr is defined in parse_helpers.h
   * when the fourth parameter is -1, it returns the 
   * "layer 4" final protocol
   */
  ret = ipv6_find_hdr(ctx, cur, &offset, -1, NULL, NULL);
  if (unlikely(ret < 0)) {
    switch (ret) {
    case -ENOENT:
      /* fallthrough */
    case -ELOOP:
      /* fallthrough */
    case -EOPNOTSUPP:
      DEBUG_HKPRG_PRINT("No Transport Info; error: %d", ret);
      hvm_ret = 1;
      goto out;
    default:
      DEBUG_HKPRG_PRINT("Unrecoverable error: %d", ret);
      goto drop;
    }
  }

  if (ret == 58) { //Hide ICMPv6 packets
    hvm_ret = 1;
    goto out;
  }

  if (ret != IPPROTO_UDP) {
    DEBUG_HKPRG_PRINT("Transport <> UDP : %d", ret);
    hvm_ret = 1;
    goto out;
  }

  udph = (struct udphdr *)cur_header_pointer(ctx, cur, offset,
                                             sizeof(*udph));
  if (unlikely(!udph)) 
    goto drop;

  udp_dest = bpf_ntohs(udph->dest);
  if (udp_dest != STAMP_DST_PORT) {
    DEBUG_HKPRG_PRINT("Destination port is not STAMP: %u", udp_dest);
    hvm_ret = 1;
    goto out;
  }

  //udp_len including header
  udp_plen = bpf_ntohs(udph->len) - sizeof(*udph);
  DEBUG_HKPRG_PRINT("UDP payload len: %d", udp_plen);

  udp_poff = offset + sizeof(*udph);

  HVM_RET = hvm_ret;

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

  timestamp = *((__u64 *)&stamp_ptr->timestamp) ;
  timestamp = bpf_be64_to_cpu(timestamp);
  DEBUG_HKPRG_PRINT("timestamp : %llx", timestamp); 

  boottime = bpf_ktime_get_boot_ns();
  DEBUG_HKPRG_PRINT("boot time: %llx", boottime);
  delta = bpf_map_lookup_elem(&map_time, &key);
  if (unlikely(!delta))
		goto drop;
  DEBUG_HKPRG_PRINT("delta: %llx", *delta);
  receive_timestamp = boottime + *delta;
  DEBUG_HKPRG_PRINT("new timestamp: %llx", receive_timestamp);
  receive_timestamp = bpf_cpu_to_be64(receive_timestamp);
  DEBUG_HKPRG_PRINT("new timestamp be: %llx", receive_timestamp);
  stamp_ptr->receive_timestamp = receive_timestamp;

out:
	return HIKE_XDP_VM;

drop:
  DEBUG_HKPRG_PRINT("drop packet");
	return HIKE_XDP_ABORTED;

}
EXPORT_HIKE_PROG_1(HIKE_PROG_NAME);
EXPORT_HIKE_PROG_MAP(HIKE_PROG_NAME, map_time);

#ifdef REAL
char LICENSE[] SEC("license") = "Dual BSD/GPL";
#endif
