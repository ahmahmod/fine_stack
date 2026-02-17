#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#include "femtocontainer/femtocontainer.h"
#include "call.h"
#include "net/gnrc.h"

#define ENABLE_DEBUG (1)
#include "debug.h"


uint32_t bpf_gnrc_netif_get_by_pid(f12r_t *bpf, uint32_t pid, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5){
    (void)bpf;
    (void)a2;
    (void)a3;
    (void)a4;
    (void)a5;

    kernel_pid_t pid1 = (kernel_pid_t)pid;
    return (uintptr_t) gnrc_netif_get_by_pid(pid1);
}

uint32_t bpf_gnrc_netif_get_by_prefix(f12r_t *bpf, uint32_t prefix, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5){
    (void)bpf;
    (void)a2;
    (void)a3;
    (void)a4;
    (void)a5;

    ipv6_addr_t *prefix1 = (ipv6_addr_t *)prefix;
    return (uintptr_t) gnrc_netif_get_by_prefix(prefix1);
}

uint32_t bpf_gnrc_netif_ipv6_addr_add_internal(f12r_t *bpf, uint32_t netif, uint32_t addr, uint32_t pfx_len, uint32_t flags, uint32_t a5){
    (void)bpf;
    (void)a5;

    gnrc_netif_t *netif1 = (gnrc_netif_t *)(uintptr_t)  netif;
    ipv6_addr_t *addr1 = (ipv6_addr_t *)(uintptr_t)  addr;
    uint8_t flags1 = (uint8_t) flags;

    return gnrc_netif_ipv6_addr_add_internal(netif1, addr1, pfx_len, flags1);
}


uint32_t bpf_gnrc_netif_ipv6_get_iid(f12r_t *bpf, uint32_t netif, uint32_t iid, uint32_t a3, uint32_t a4, uint32_t a5){
    (void)bpf;
    (void)a3;
    (void)a4;
    (void)a5;

    gnrc_netif_t *netif1 = (gnrc_netif_t *)(uintptr_t)  netif;
    eui64_t *iid1 = (eui64_t *)(uintptr_t)  iid;

    return gnrc_netif_ipv6_get_iid(netif1, iid1);
}

uint32_t bpf_gnrc_netif_ipv6_addr_match(f12r_t *bpf, uint32_t netif, uint32_t addr, uint32_t a3, uint32_t a4, uint32_t a5){
    (void)bpf;
    (void)a3;
    (void)a4;
    (void)a5;

    gnrc_netif_t *netif1 = (gnrc_netif_t *)(uintptr_t)  netif;
    ipv6_addr_t *addr1 = (ipv6_addr_t *)(uintptr_t)  addr;
    // int x = gnrc_netif_ipv6_addr_match(netif1, addr1);
    // printf("addr match: %d", x);

    return gnrc_netif_ipv6_addr_match(netif1, addr1);
}

extern const ipv6_addr_t ipv6_addr_all_rpl_nodes;
uint32_t find_interface_with_rpl_mcast(f12r_t *bpf, uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5){
    (void)bpf;
    (void)a1;
    (void)a2;
    (void)a3;
    (void)a4;
    (void)a5;
    gnrc_netif_t *netif = NULL;

    while ((netif = gnrc_netif_iter(netif))) {
        for (unsigned i = 0; i < GNRC_NETIF_IPV6_GROUPS_NUMOF; i++) {
            if (ipv6_addr_equal(&netif->ipv6.groups[i], &ipv6_addr_all_rpl_nodes)) {
                return (uintptr_t) netif;
            }
        }
    }
    return (uintptr_t) NULL;
}

uint32_t bpf_gnrc_netif_get_ipv6_addr_by_idx(f12r_t *bpf, uint32_t netif, uint32_t idx, uint32_t a3, uint32_t a4, uint32_t a5){
    (void)bpf;
    (void)a3;
    (void)a4;
    (void)a5;   

    gnrc_netif_t *netif1 = (gnrc_netif_t *)netif;
    return (uintptr_t) &netif1->ipv6.addrs[idx];
}

uint32_t bpf_gnrc_netif_get_by_ipv6_addr(f12r_t *bpf, uint32_t addr, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5)
{
    (void)bpf;
    (void)a2;
    (void)a3;
    (void)a4;
    (void)a5;

    return (uintptr_t) gnrc_netif_get_by_ipv6_addr((ipv6_addr_t *)(uintptr_t) addr);
}

uint32_t bpf_netif_get_pid(f12r_t *bpf, uint32_t netif, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5)
{
    (void)bpf;
    (void)a2;
    (void)a3;
    (void)a4;
    (void)a5;
    gnrc_netif_t *netif1 = (gnrc_netif_t *)netif;
    return  netif1->pid;
}