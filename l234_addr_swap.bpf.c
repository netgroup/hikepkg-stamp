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

#define IPV6_ADDR_SIZE 128
#define HOP_LIMIT 64

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
  unsigned char	eth_addr[ETH_ALEN];
  struct in6_addr ip6addr;
  struct hdr_cursor *cur;
  struct pkt_info *info;
  struct ethhdr *eth_h;
  struct ipv6hdr *ip6h;
  struct udphdr *udph;
  __u64 hvm_ret = 0; /* set to 1 if packet won't be processed */
  __u16 udp_port;
  int offset = 0;
  __u64 eth_src;
  __u64 eth_dst;
  __sum16 check;
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

  memcpy(&eth_dst, eth_h->h_dest, ETH_ALEN);
  memcpy(&eth_src, eth_h->h_source, ETH_ALEN);
  DEBUG_HKPRG_PRINT("Layer 2 dst : %llx", eth_dst);
  DEBUG_HKPRG_PRINT("Layer 2 src : %llx", eth_src);
  memcpy(eth_addr, eth_h->h_source, ETH_ALEN);
  memcpy(eth_h->h_source, eth_h->h_dest, ETH_ALEN);
  memcpy(eth_h->h_dest, eth_addr, ETH_ALEN);
  DEBUG_HKPRG_PRINT("Swapping...");
  memcpy(&eth_dst, eth_h->h_dest, ETH_ALEN);
  memcpy(&eth_src, eth_h->h_source, ETH_ALEN);
  DEBUG_HKPRG_PRINT("Layer 2 dst : %llx", eth_dst);
  DEBUG_HKPRG_PRINT("Layer 2 src : %llx", eth_src);

  /* IPv6 */
  ip6h = (struct ipv6hdr *)cur_header_pointer(ctx, cur, cur->nhoff,
            sizeof(*ip6h));
  if (unlikely(!ip6h)) 
    goto drop;
  ip6addr = ip6h->saddr;
  ip6h->saddr = ip6h->daddr;
  ip6h->daddr = ip6addr;
  ip6h->hop_limit = HOP_LIMIT;

  /* UDP */
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
  if (ret != IPPROTO_UDP) {
    DEBUG_HKPRG_PRINT("Transport <> UDP : %d", ret);
    hvm_ret = 1;
    goto out;
  }
  udph = (struct udphdr *)cur_header_pointer(ctx, cur, offset, sizeof(*udph));
  if (unlikely(!udph)) 
    goto drop;
  udp_port = udph->source;
  udph->source = udph->dest;
  udph->dest = udp_port;
  /* checksum */
  ret = ipv6_udp_checksum(ctx, ip6h, udph, &check);
	if (unlikely(ret)) {
		DEBUG_HKPRG_PRINT("Error: checksum error=%d", ret);
    DEBUG_HKPRG_PRINT("udp check=0x%x", bpf_ntohs(check));
		goto out;
	}
  udph->check = check;

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
