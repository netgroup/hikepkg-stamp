// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

/* HIKe Prog Name comes always first */
#define HIKE_PROG_NAME    udp_checksum

/* Recalculate correct UDP checksum
 */

#define HIKE_DEBUG 1

#define REAL
//#define REPL

#define IPV6_ADDR_SIZE 128
#define IPPROTO_SRH 43
#define HOP_LIMIT 64

#include <linux/udp.h>
#include <linux/ipv6.h>
#include <linux/seg6.h>

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

HIKE_PROG(HIKE_PROG_NAME)
{
  struct ipv6hdr ip6h_pseudo;
  // struct ipv6_sr_hdr *srh;
  struct in6_addr *ip6_last_seg;
  struct hdr_cursor *cur;
  struct pkt_info *info;
  struct ipv6hdr *ip6h;
  struct udphdr *udph;
  int offset = 0;
  __sum16 check;
  int ret;

  __u64 display;
  __u64 display2;

  /* retrieve packet information from HIKe shared memory*/
  info = hike_pcpu_shmem();
  if (unlikely(!info))
    goto drop;

  /* take the reference to the cursor object which has been saved into
   * the HIKe shared memory
   */
  cur = pkt_info_cur(info);
  /* no need for checking cur != NULL here */


  /* prepare pseudoheader IPv6 */
  ip6h = (struct ipv6hdr *)cur_header_pointer(ctx, cur, cur->nhoff,
            sizeof(*ip6h));
  if (unlikely(!ip6h)) 
    goto drop;

  /* get destination addr for pseudoheader from last segment of SRH */
  ret = ipv6_find_hdr(ctx, cur, &offset, IPPROTO_SRH, NULL, NULL);
  if (unlikely(ret < 0)) {
    switch (ret) {
    case -ENOENT:
      /* fallthrough */
    case -ELOOP:
      /* fallthrough */
    case -EOPNOTSUPP:
      DEBUG_HKPRG_PRINT("-EOPNOTSUPP; error: %d", ret);
      goto out;
    default:
      DEBUG_HKPRG_PRINT("Unrecoverable error: %d", ret);
      goto drop;
    }
  }
  if (ret != IPPROTO_SRH) {
    DEBUG_HKPRG_PRINT("No SRH : %d", ret);
    goto out;
  }
  /* if we are sure that there is at least 1 segment, allocating memory for
   * the srh is not necessary
   */
  //   srh = (struct ipv6_sr_hdr *)cur_header_pointer(ctx, cur, offset,
  //                                                  sizeof(*srh));
  //   if (unlikely(!srh)) 
  //     goto drop;
  // }
  // DEBUG_HKPRG_PRINT("sizeof(*srh): %d", sizeof(*srh));
  // ip6_last_seg = (struct in6_addr *)cur_header_pointer(ctx, cur,
  //                                      offset + sizeof(*srh), sizeof(*ip6_last_seg));
  ip6_last_seg = (struct in6_addr *)cur_header_pointer(
               ctx, cur, offset + sizeof(struct ipv6_sr_hdr), sizeof(*ip6_last_seg));
  if (unlikely(!ip6_last_seg)) 
    goto drop;
  display = *((__u64 *)ip6_last_seg);
  display = bpf_be64_to_cpu(display);
  display2 = *((__u64 *)ip6_last_seg + 1);
  display2 = bpf_be64_to_cpu(display2);
  DEBUG_HKPRG_PRINT("last segment (used as destination addr): %llx %llx",
                    display, display2);

  /* UDP */
  offset = 0;
  ret = ipv6_find_hdr(ctx, cur, &offset, -1, NULL, NULL);
  if (unlikely(ret < 0)) {
    switch (ret) {
    case -ENOENT:
      /* fallthrough */
    case -ELOOP:
      /* fallthrough */
    case -EOPNOTSUPP:
      DEBUG_HKPRG_PRINT("No Transport Info; error: %d", ret);
      goto out;
    default:
      DEBUG_HKPRG_PRINT("Unrecoverable error: %d", ret);
      goto drop;
    }
  }
  if (ret != IPPROTO_UDP) {
    DEBUG_HKPRG_PRINT("Transport <> UDP : %d", ret);
    goto out;
  }
  udph = (struct udphdr *)cur_header_pointer(ctx, cur, offset, sizeof(*udph));
  if (unlikely(!udph)) 
    goto drop;

  /* populate data into pseudoheader */
  ip6h_pseudo.daddr = *ip6_last_seg;
  ip6h_pseudo.saddr = ip6h->saddr;
  ip6h_pseudo.payload_len = udph->len;
  ip6h_pseudo.nexthdr = IPPROTO_UDP;

  /* checksum */
  ret = ipv6_udp_checksum(ctx, &ip6h_pseudo, udph, &check);
	if (unlikely(ret)) {
		DEBUG_HKPRG_PRINT("Error: checksum error=%d", ret);
    DEBUG_HKPRG_PRINT("udp check=0x%x", bpf_ntohs(check));
		goto out;
	}
  udph->check = check;
  DEBUG_HKPRG_PRINT("udp check=0x%x", bpf_ntohs(check));

out:
  HVM_RET = 0;
	return HIKE_XDP_VM;

drop:
  DEBUG_HKPRG_PRINT("drop packet");
	return HIKE_XDP_ABORTED;

}

EXPORT_HIKE_PROG_1(HIKE_PROG_NAME);

#ifdef REAL
char LICENSE[] SEC("license") = "Dual BSD/GPL";
#endif
