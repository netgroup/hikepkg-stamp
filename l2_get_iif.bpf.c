// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

/* HIKe Prog Name comes always first */
#define HIKE_PROG_NAME    l2_get_iif

/* Return input interface index */

#define HIKE_DEBUG 1

#define REAL
//#define REPL

#include <linux/if_ether.h>

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
  const __u32 iif = ctx->ingress_ifindex;
  DEBUG_HKPRG_PRINT("input interface index = %u", iif);
  HVM_RET = iif;
  return HIKE_XDP_VM;
}

EXPORT_HIKE_PROG_1(HIKE_PROG_NAME);

#ifdef REAL
char LICENSE[] SEC("license") = "Dual BSD/GPL";
#endif
