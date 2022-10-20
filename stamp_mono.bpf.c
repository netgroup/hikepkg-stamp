// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

/* HIKe Prog Name comes always first */
#define HIKE_PROG_NAME    stamp_mono

/* addresses swap, stamp timestamps and udp checksum all at once
 */

//#define HIKE_PRINT_LEVEL HIKE_PRINT_LEVEL_DEBUG
#define HIKE_PRINT_LEVEL 0

#include "hike_vm.h"
#include "parse_helpers.h"
#include "stamplib.h"

#define HIKE_EBPF_PROG_L2XCON_IFMAX	8

bpf_map(map_time, HASH, __u8, __u64, 1);

bpf_map(map_eth, HASH, __u8, struct eth_src_dst, 1);
bpf_map(map_ipv6, HASH, __u8, struct ip_src_dst, 1);
bpf_map(map_seglist, HASH, __u8, struct in6_addr, 256);

bpf_map(l2xcon_map, ARRAY, __u32, __u32, HIKE_EBPF_PROG_L2XCON_IFMAX);

HIKE_PROG(HIKE_PROG_NAME)
{
        const __u32 iif = ctx->ingress_ifindex;
        unsigned char (*eth_addr)[ETH_ALEN];
        struct eth_src_dst *eth_src_dst_ptr;
        struct ip_src_dst *ip_src_dst_ptr;
        struct ipv6hdr *ip6h_pseudo;
        struct in6_addr *ip6addr;
        struct stamp* stamp_ptr;
        __u64 receive_timestamp;
        struct ipv6_sr_hdr *srh;
        struct hdr_cursor *cur;
        struct pkt_info *info;
        struct ipv6hdr *ip6h;
        struct ethhdr *eth_h;
        struct in6_addr *seg;
        struct udphdr *udph;
        __be16 *udp_dest;
        __u16 udp_port;
        int offset = 0;
        __u64 boottime;
        __sum16 check;
        __u8 key0 = 0;
        __u8 key1 = 1;
        __u64 *delta;
        __u32 *oif;
        long ret;
        int i, j;

        /* FILTER */
        /* retrieve packet information from HIKe shared memory*/
        info = hike_pcpu_shmem();
        if (unlikely(!info))
                goto drop;

        /* take the reference to the cursor object which has been saved into
         * the HIKe shared memory
         */
        cur = pkt_info_cur(info);
        /* no need for checking cur != NULL here */

        boottime = bpf_ktime_get_boot_ns();

        /* scratch area on shmem starts after the pkt_info area */
        /* allocate pseudoheader in shmem */
        ip6h_pseudo = hike_pcpu_shmem_obj(sizeof(struct pkt_info), struct ipv6hdr);
                if (unlikely(!ip6h_pseudo)) {
                        hike_pr_crit("error during access to shmem");
                        goto drop;
                }

        /* Ethernet */
        eth_h = (struct ethhdr *)cur_header_pointer(ctx, cur, cur->mhoff,
                                                    sizeof(*eth_h));
        if (unlikely(!eth_h))
                goto drop;

// use a single key for the whole struct
        eth_src_dst_ptr = (struct eth_src_dst *) bpf_map_lookup_elem(&map_eth, &key0);
        if (unlikely(!eth_src_dst_ptr))
                goto drop;
        memcpy(eth_h->h_source, eth_src_dst_ptr->h_source, ETH_ALEN);
        memcpy(eth_h->h_dest, eth_src_dst_ptr->h_dest, ETH_ALEN);

        /* IPv6 */
        ip6h = (struct ipv6hdr *)cur_header_pointer(ctx, cur, cur->nhoff,
                                                    sizeof(*ip6h));
        if (unlikely(!ip6h))
                goto drop;

        ip6h->hop_limit = HOP_LIMIT;

// use a single key for the whole struct
        ip_src_dst_ptr = (struct ip_src_dst *) bpf_map_lookup_elem(&map_ipv6, &key0);
        if (unlikely(!ip_src_dst_ptr))
                goto drop;
        ip6h->saddr = ip_src_dst_ptr->saddr;
        ip6h->daddr = ip_src_dst_ptr->daddr;
        /* pseudoheader */
        ip6h_pseudo->saddr = ip6h->saddr;

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
        /* reset segments left */
        srh->segments_left = srh->first_segment;
        /* do segment list from maps */
        offset += sizeof(*srh);
        for (i = 0, j=0; i <= srh->first_segment; i++, offset += sizeof(*seg), j++)
        {
                ip6addr = (struct in6_addr *) bpf_map_lookup_elem(&map_seglist, &j);
                // relax_verifier();
                if (unlikely(!ip6addr))
                        goto drop;
                hike_pr_debug("segment [%d]: %llx %llx", j,
                              bpf_be64_to_cpu(*((__u64 *) ip6addr)),
                              bpf_be64_to_cpu(*((__u64 *) ip6addr + 1)));
                seg = (struct in6_addr *)cur_header_pointer(ctx, cur, offset,
                                                            sizeof(*seg));
                if (unlikely(!seg)) 
                        goto drop;
                *seg = *ip6addr;
                /* pseudoheader needs last segment as destination */
                if (i == 0)
                        ip6h_pseudo->daddr = *ip6addr;
        }

        /* UDP */
        offset = cur->nhoff;
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
        /* pseudoheader */
        ip6h_pseudo->payload_len = udph->len;
        ip6h_pseudo->nexthdr = IPPROTO_UDP;

        offset += sizeof(*udph);
        stamp_ptr = (struct stamp *)cur_header_pointer(ctx, cur, offset, 
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
        delta = bpf_map_lookup_elem(&map_time, &key0);
        if (unlikely(!delta)) {
                hike_pr_err("could not read delta from map");
                goto drop;
        }
        receive_timestamp = boottime + *delta;
        /* converto to NTP format */
        receive_timestamp = (__u64) (receive_timestamp / 1000000000) << 32 |
                            (receive_timestamp % 1000000000);
        stamp_ptr->sess_send_timestamp = stamp_ptr->timestamp;
        stamp_ptr->receive_timestamp = bpf_cpu_to_be64(receive_timestamp);
        stamp_ptr->timestamp = bpf_cpu_to_be64(receive_timestamp);
        stamp_ptr->sess_send_seq_num = stamp_ptr->seq_number;
        stamp_ptr->sess_send_err_estimate = stamp_ptr->error_estimate;
        stamp_ptr->error_estimate = bpf_htons(ERROR_ESTIMATE);
        stamp_ptr->sess_send_ttl = ip6h->hop_limit;

        /* checksum */
        ret = ipv6_udp_checksum(ctx, ip6h_pseudo, udph, &check);
        if (unlikely(ret)) {
                hike_pr_err("Error: checksum error=%d", ret);
                goto drop;
        }
        udph->check = check;
        hike_pr_debug("udp check=0x%x", bpf_ntohs(check));

        /* layer 2 cross connect */
        hike_pr_debug("HIKe Prog: l2xcon REG_1=0x%llx, iif=%d", _I_REG(1), iif);

	oif = bpf_map_lookup_elem(&l2xcon_map, &iif);
	if (!oif) {
		hike_pr_debug("HIKe Prog: l2xcon invalid oif");
		return XDP_ABORTED;
	}

	hike_pr_debug("HIKe Prog: l2xcon cros-connectiong iif=%d, oif=%d",
		    iif, *oif);

	return bpf_redirect(*oif, 0);
        
out:
        hike_pr_debug("pass packet");
        return XDP_PASS;
drop:
        hike_pr_debug("drop packet");
        return HIKE_XDP_ABORTED;
}

EXPORT_HIKE_PROG_1(HIKE_PROG_NAME);
EXPORT_HIKE_PROG_MAP(HIKE_PROG_NAME, map_time);

char LICENSE[] SEC("license") = "Dual BSD/GPL";
