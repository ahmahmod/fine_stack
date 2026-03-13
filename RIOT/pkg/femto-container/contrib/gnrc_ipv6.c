#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#include "femtocontainer/femtocontainer.h"
#include "call.h"
#include "net/gnrc.h"
#include "net/gnrc/ipv6/nib.h"
#include "net/gnrc/rpl/srh.h"
#include "net/gnrc/rpl/sr_table.h"

#define ENABLE_DEBUG (1)
#include "debug.h"


uint32_t bpf_ipv6_addr_is_multicast(f12r_t *bpf, uint32_t dst, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5){
    (void)bpf;
    (void)a2;
    (void)a3;
    (void)a4;
    (void)a5;

    ipv6_addr_t *dst1 = (ipv6_addr_t *)(uintptr_t) dst;
    return ipv6_addr_is_multicast(dst1);
}

uint32_t bpf_ipv6_addr_set_aiid(f12r_t *bpf, uint32_t addr, uint32_t iid, uint32_t a3, uint32_t a4, uint32_t a5){
    (void)bpf;
    (void)a3;
    (void)a4;
    (void)a5;

    ipv6_addr_t *addr1 = (ipv6_addr_t*) (uintptr_t) addr;
    uint8_t *iid1 = (uint8_t*)(uintptr_t) iid;

    ipv6_addr_set_aiid(addr1, iid1);
    return 0;
}

uint32_t bpf_gnrc_ipv6_nib_pl_set(f12r_t *bpf, uint32_t iface, uint32_t pfx, uint32_t pfx_len, uint32_t valid_ltime, uint32_t pref_ltime){
    (void)bpf;

    kernel_pid_t iface1 = (kernel_pid_t) iface;
    if((iface1 > 7) || (iface1 < 4)){
        // printf("iface > 7 or iface < 4 -- iface = %d\n", iface1);
        return -1;
    }
    ipv6_addr_t *pfx1 = (ipv6_addr_t*) (uintptr_t) pfx;

    return gnrc_ipv6_nib_pl_set(iface1, pfx1, pfx_len, valid_ltime, pref_ltime);
}

uint32_t bpf_gnrc_ipv6_nib_ft_del(f12r_t *bpf, uint32_t dst, uint32_t dst_len, uint32_t a3, uint32_t a4, uint32_t a5){
    (void)bpf;
    (void)a3;
    (void)a4;
    (void)a5;

    ipv6_addr_t *dst1 = (ipv6_addr_t *) (uintptr_t) dst;
    gnrc_ipv6_nib_ft_del(dst1, dst_len);
    return 0;
}

uint32_t bpf_gnrc_ipv6_nib_ft_add(f12r_t *bpf, uint32_t dst, uint32_t dst_len, uint32_t next_hop, uint32_t iface, uint32_t lifetime){
    (void)bpf;
    ipv6_addr_t *dst1 = (ipv6_addr_t *) (uintptr_t) (uintptr_t) dst;                                   
    ipv6_addr_t *next_hop1 = (ipv6_addr_t *)(uintptr_t) next_hop;
    kernel_pid_t iface1 = (kernel_pid_t) iface;

    if ((iface1 > 7) || (iface1 < 4)){
        printf("iface > 7 or iface < 4 -- iface = %d\n", iface1);
        return -1;
    }

    return gnrc_ipv6_nib_ft_add(dst1, dst_len, next_hop1, iface1, lifetime);
}

/* SR */
uint32_t bpf_gnrc_sr_delete_route(f12r_t *bpf, uint32_t dst_node, uint32_t dst_size, uint32_t a3, uint32_t a4, uint32_t a5){
    (void)bpf;
    (void)a3;
    (void)a4;
    (void)a5;

    ipv6_addr_t *dst_node1 = (ipv6_addr_t *) (uintptr_t) dst_node; 

    return  gnrc_sr_delete_route(dst_node1, dst_size);

}

uint32_t bpf_gnrc_sr_add_new_dst(f12r_t *bpf, uint32_t child, uint32_t parent, uint32_t sr_iface_id, uint32_t sr_flags, uint32_t lifetime){
    (void)bpf;

    ipv6_addr_t *child1 = (ipv6_addr_t *)(uintptr_t) child; 
    ipv6_addr_t *parent1 = (ipv6_addr_t *)(uintptr_t) parent;
    kernel_pid_t sr_iface_id1 = (kernel_pid_t) sr_iface_id;

    // printf("bpf_gnrc_sr_add_new_dst called parent: %s\n",
    //         ipv6_addr_to_str(addr_str, parent1, sizeof(addr_str)));
    return gnrc_sr_add_new_dst(child1, sizeof(ipv6_addr_t), parent1, sr_iface_id1, sr_flags, lifetime);
}

uint32_t bpf_gnrc_sr_initialize_table(f12r_t *bpf, uint32_t addr, uint32_t iface, uint32_t a3, uint32_t a4, uint32_t a5){
    (void)bpf;
    (void)a3;
    (void)a4;
    (void)a5;

    ipv6_addr_t *addr1 = (ipv6_addr_t *) (uintptr_t) addr;
    kernel_pid_t iface1 = (kernel_pid_t) iface;

    gnrc_sr_initialize_table(addr1, iface1);
    return 0;
}

uint32_t bpf_gnrc_sr_deinitialize_table(f12r_t *bpf, uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5){
    (void)bpf;
    (void)a1;
    (void)a2;
    (void)a3;
    (void)a4;
    (void)a5;

    gnrc_sr_deinitialize_table();
    return 0;
}

uint32_t bpf_ipv6_addr_init_prefix(f12r_t *bpf, uint32_t out, uint32_t prefix, uint32_t bits, uint32_t a4, uint32_t a5){
    (void)bpf;
    (void)a4;
    (void)a5;

    ipv6_addr_t *out1 = (ipv6_addr_t *)out;
    ipv6_addr_t *prefix1 = (ipv6_addr_t *)prefix;
    uint8_t bits1 = (uint8_t) bits;

    ipv6_addr_init_prefix(out1, prefix1, bits1);
    return 1;
}

uint32_t bpf_ipv6_addr_match_prefix(f12r_t *bpf, uint32_t a, uint32_t b, uint32_t a3, uint32_t a4, uint32_t a5)
{
    (void)bpf;
    (void)a3;
    (void)a4;
    (void)a5;

    ipv6_addr_t *a1 = (ipv6_addr_t *)a;
    ipv6_addr_t *b1 = (ipv6_addr_t *)b;

    return (uint32_t) ipv6_addr_match_prefix(a1,b1);
}
uint32_t bpf_gnrc_ipv6_nib_pl_iter(f12r_t *bpf, uint32_t iface, uint32_t state, uint32_t ple, uint32_t a4, uint32_t a5){
    (void)bpf;
    (void)a4;
    (void)a5;

    unsigned iface1 = (unsigned) iface; 
    void **state1 = (void **) state;
    gnrc_ipv6_nib_pl_t *ple1 = (gnrc_ipv6_nib_pl_t *) ple;

    return (uint32_t) gnrc_ipv6_nib_pl_iter(iface1, state1, ple1);

}

uint32_t bpf_gnrc_ipv6_nib_ft_iter(f12r_t *bpf, uint32_t next_hop, uint32_t iface, uint32_t state, uint32_t fte, uint32_t a5){
    (void)bpf;
    (void)a5;

    ipv6_addr_t *next_hop1 = (ipv6_addr_t *) next_hop;
    unsigned iface1 = (unsigned) iface; 
    void **state1 = (void **) state;
    gnrc_ipv6_nib_ft_t *fte1 = (gnrc_ipv6_nib_ft_t *) fte;

    return (uint32_t) gnrc_ipv6_nib_ft_iter(next_hop1, iface1, state1, fte1);
}

uint32_t bpf_ipv6_addr_is_global(f12r_t *bpf, uint32_t addr, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5){
    (void)bpf;
    (void)a2;
    (void)a3;
    (void)a4;
    (void)a5;

    return ipv6_addr_is_global((ipv6_addr_t *) addr);
}

uint32_t bpf_ipv6_addr_is_unspecified(f12r_t *bpf, uint32_t addr, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5){
    (void)bpf;
    (void)a2;
    (void)a3;
    (void)a4;
    (void)a5;

    return ipv6_addr_is_unspecified((ipv6_addr_t *) addr);
}

uint32_t bpf_ipv6_addr_equal(f12r_t *bpf, uint32_t addr1, uint32_t addr2, uint32_t a3, uint32_t a4, uint32_t a5){
    (void)bpf;
    (void)a3;
    (void)a4;
    (void)a5;

    return ipv6_addr_equal((ipv6_addr_t *) addr1, (ipv6_addr_t *) addr2);
}


uint32_t bpf_ipv6_nc_from_addr(f12r_t *bpf, uint32_t addr, uint32_t iface, uint32_t a3, uint32_t a4, uint32_t a5){
    (void)bpf;
    (void)a3;
    (void)a4;
    (void)a5;

    ipv6_addr_t *addr1 = (ipv6_addr_t *) addr;
    kernel_pid_t iface1 = (kernel_pid_t) iface;
    if(ipv6_addr_is_unspecified(addr1)){
        return -1;
    }

    eui64_t neigh_iid = {{0}};
    memcpy(&neigh_iid, ((uint8_t*) addr1) + 8, sizeof(eui64_t));
    uint8_t neigh_l2add[sizeof(eui64_t)];
    int res = l2util_ipv6_iid_to_addr(NETDEV_TYPE_IEEE802154, &neigh_iid, neigh_l2add);
    
    if (res > 0){
        gnrc_ipv6_nib_nc_del(addr1, iface);
        res = gnrc_ipv6_nib_nc_set(addr1, iface1, (uint8_t *) &neigh_l2add, res);
        gnrc_ipv6_nib_nc_mark_reachable(addr1);
    }

    return res;
}

static char addr_str[IPV6_ADDR_MAX_STR_LEN];
uint32_t bpf_ipv6_addr_from_str(f12r_t *bpf, uint32_t str, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5){
    (void)bpf;
    (void)a2;
    (void)a3;
    (void)a4;
    (void)a5;

    ipv6_addr_t addr1;
    ipv6_addr_from_str(&addr1, (const char *) (uintptr_t) str);
    printf("address: %s\n", ipv6_addr_to_str(addr_str, &addr1, sizeof(addr_str)));

    return (uintptr_t) &addr1;
    
}
