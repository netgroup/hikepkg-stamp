// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

/* HIKe Prog Name comes always first */
#define HIKE_PROG_NAME    l234_addr_swap

/* Swap src and dst addresses in Eth and IPv6 headers
 * Reset IPv6 hop limit
 * Swap src and dst port numbers in UDP header
 * Recalculate correct UDP checksum
 */

#define HIKE_DEBUG 1

#define REAL
//#define REPL

#include <linux/if_ether.h>
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

HIKE_PROG(HIKE_PROG_NAME)
{
  unsigned char	eth_addr[ETH_ALEN] = "asd";
  struct hdr_cursor *cur;
  struct pkt_info *info;
  struct ethhdr *eth_h;
  struct ipv6hdr *ip6h;
  struct udphdr *udph;
  __u64 hvm_ret = 0; /* set to 1 if packet won't be processed */
  __u64 eth_src;
  __u64 eth_dst;
  __u16 udp_dest;
  __u16 udp_poff; //udp payload offset
  int offset = 0;
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

  /* Ethernet */
  eth_h = (struct ethhdr *)cur_header_pointer(ctx, cur, cur->mhoff,
                                              sizeof(*eth_h));
  if (unlikely(!eth_h)) 
    goto drop;

  // eth_dst = (*((__u64 *)&eth_h->h_dest[0])) & 0xffffffffffff;
  // eth_src = (*((__u64 *)&eth_h->h_source[0])) & 0xffffffffffff;
  memcpy(&eth_dst, &eth_h->h_dest[0], ETH_ALEN);
  memcpy(&eth_src, eth_h->h_source, ETH_ALEN);
  DEBUG_HKPRG_PRINT("Layer 2 dst : %llx", eth_dst);
  DEBUG_HKPRG_PRINT("Layer 2 src : %llx", eth_src);
  memcpy(eth_addr, eth_h->h_source, ETH_ALEN);

  DEBUG_HKPRG_PRINT("eth addr : %lx", *((__u32*) eth_addr));
  DEBUG_HKPRG_PRINT("eth src : %lx", *((__u32*) eth_h->h_source));
  DEBUG_HKPRG_PRINT("eth dst : %lx", *((__u32*) eth_h->h_dest));
  memcpy(&eth_h->h_dest[0], eth_addr, ETH_ALEN);
  memcpy(&eth_h->h_source[0], eth_addr, ETH_ALEN);
  DEBUG_HKPRG_PRINT("Swapping...");
  DEBUG_HKPRG_PRINT("eth src : %lx", *((__u32*) eth_h->h_source));
  DEBUG_HKPRG_PRINT("eth dst : %lx", *((__u32*) eth_h->h_dest));
  // memcpy(eth_addr, eth_h->h_dest, ETH_ALEN);
  // memcpy(eth_h->h_dest, eth_h->h_source, ETH_ALEN);
  // memcpy(eth_h->h_source, eth_addr, ETH_ALEN);













out:
	return HIKE_XDP_VM;

drop:
  DEBUG_HKPRG_PRINT("drop packet");
	return HIKE_XDP_ABORTED;

}

EXPORT_HIKE_PROG_1(HIKE_PROG_NAME);

#ifdef REAL
char LICENSE[] SEC("license") = "Dual BSD/GPL";
#endif
