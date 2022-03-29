// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

/* HIKe Prog Name comes always first */
#define HIKE_PROG_NAME l234_addr_swap

/* Swap src and dst addresses in Eth and IPv6 headers
 * Reset IPv6 hop limit
 * Swap src and dst port numbers in UDP header
 */

#define HIKE_PRINT_LEVEL HIKE_PRINT_LEVEL_DEBUG

#define REAL
//#define REPL

#define HOP_LIMIT 64

#include <linux/if_ether.h>
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
        unsigned char eth_addr[ETH_ALEN];
        struct in6_addr *seg_high;
        struct in6_addr *seg_low;
        // struct in6_addr ip6addr;
        struct ipv6_sr_hdr *srh;
        struct hdr_cursor *cur;
        struct pkt_info *info;
        struct ethhdr *eth_h;
        struct ipv6hdr *ip6h;
        struct in6_addr temp;
        struct udphdr *udph;
        __u8 first_segment;
        __u16 udp_port;
        int offset = 0;
        __u64 eth_src;
        __u64 eth_dst;
        int ret;

        // struct in6_addr (*segments)[2];

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
        memcpy(eth_addr, eth_h->h_source, ETH_ALEN);
        memcpy(eth_h->h_source, eth_h->h_dest, ETH_ALEN);
        memcpy(eth_h->h_dest, eth_addr, ETH_ALEN);
        memcpy(&eth_dst, eth_h->h_dest, ETH_ALEN);
        memcpy(&eth_src, eth_h->h_source, ETH_ALEN);
        hike_pr_debug("Layer 2 dst : %llx", eth_dst);
        hike_pr_debug("Layer 2 src : %llx", eth_src);

        /* IPv6 */
        ip6h = (struct ipv6hdr *)cur_header_pointer(ctx, cur, cur->nhoff,
                                                    sizeof(*ip6h));
        if (unlikely(!ip6h))
                goto drop;
        // ip6addr = ip6h->saddr;
        ip6h->saddr = ip6h->daddr;
        // ip6h->daddr = ip6addr;
        ip6h->hop_limit = HOP_LIMIT;

        /* SRH */
        ret = ipv6_find_hdr(ctx, cur, &offset, NEXTHDR_ROUTING, NULL, NULL);
        if (unlikely(ret < 0))
        {
                hike_pr_debug("SRH not found; rc: %d", ret);
                goto drop;
        }
        srh = (struct ipv6_sr_hdr *)cur_header_pointer(ctx, cur, offset,
                                                       sizeof(*srh));
        if (unlikely(!srh))
                goto drop;
        first_segment = srh->first_segment;
        srh->segments_left = first_segment;
        if (first_segment != 0)
        { /* curly brackets needed to limit scope of array (goto error) */
                // struct in6_addr (*segments)[first_segment +1];
                offset += sizeof(struct ipv6_sr_hdr);
                // segments = (struct in6_addr(*)[first_segment +1])cur_header_pointer(
                //             ctx, cur, offset, sizeof(*segments));
                // if (unlikely(!segments))
                //         goto drop;
                /* reverse segment list */
                for (__u8 low = 0, high = srh->first_segment; low < high; low++, high--) {
                        seg_low = (struct in6_addr *)cur_header_pointer(
                                ctx, cur, offset, sizeof(*seg_low));
                        if (unlikely(!seg_low)) 
                                goto drop;
                        seg_high = (struct in6_addr *)cur_header_pointer(
                                ctx, cur, offset + high * sizeof(*seg_high), sizeof(*seg_high));
                        if (unlikely(!seg_high)) 
                                goto drop;
                        temp = *seg_low;
                        *seg_low = *seg_high;
                        *seg_high = temp;
                }



                // for (__u8 low = 0, high = srh->first_segment; low < high; low++, high--)
                // {
                //         struct in6_addr temp = (*segments)[low];
                //         (*segments)[low] = (*segments)[high];
                //         (*segments)[high] = temp;
                // }
                // hike_pr_debug("seg1: %x%x", (*segments)[srh->first_segment].s6_addr[14],
                //                 (*segments)[srh->first_segment].s6_addr[15]);
                // hike_pr_debug("seg list size: %u", sizeof((*segments)));
                /* IPv6 daddr is new first segment */
                // ip6addr = (*segments)[srh->first_segment];
                // ip6h->daddr = (*segments)[first_segment];
                // hike_pr_debug("seg0: %llx", *((__u64 *) &ip6addr));
                // memcpy(&ip6h->daddr, &(*segments)[0], 16);
        }

        /* UDP */
        offset = 0;
        ret = ipv6_find_hdr(ctx, cur, &offset, IPPROTO_UDP, NULL, NULL);
        if (unlikely(ret < 0))
        {
                hike_pr_debug("UDP not found; rc: %d", ret);
                goto drop;
        }
        udph = (struct udphdr *)cur_header_pointer(ctx, cur, offset, sizeof(*udph));
        if (unlikely(!udph))
                goto drop;
        udp_port = udph->source;
        udph->source = udph->dest;
        udph->dest = udp_port;

        HVM_RET = 0;
        return HIKE_XDP_VM;

drop:
        hike_pr_debug("drop packet");
        return HIKE_XDP_ABORTED;
}

EXPORT_HIKE_PROG_1(HIKE_PROG_NAME);

#ifdef REAL
char LICENSE[] SEC("license") = "Dual BSD/GPL";
#endif
