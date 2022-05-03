#include <linux/if_ether.h>
#include <linux/udp.h>
#include <linux/ipv6.h>
#include <linux/seg6.h>

#include "hike_vm.h"


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

struct eth_ipv6_srh {
        struct ethhdr eth_h;
        struct ipv6hdr ip6h;
        struct ipv6_sr_hdr srh;
} __attribute__((packed));

struct udp_stamp {
        struct udphdr udph;
        struct stamp stamp;
} __attribute__((packed));

struct collector_key {
        __u16 ssid;
        __u32 seq_number;
} __attribute__((packed));

struct collector_value {
        __u64 sender;
        __u64 refl_receive;
        __u64 refl_send;
        __u64 collector;
} __attribute__((packed));




#define STAMP_DST_PORT 42069
// #define STAMP_DST_PORT 862
#define ERROR_ESTIMATE 0x8001
#define MAX_ENTRIES_CACHE_MAP 1024
#define MAX_ENTRIES_COLLECTOR_MAP 64

