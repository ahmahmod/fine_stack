/*
 * Copyright (C) 2020 Inria
 * Copyright (C) 2020 Koen Zandberg <koen@bergzand.net>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "femtocontainer/femtocontainer.h"
#include "shared.h"
#include "femtocontainer/store.h"
#include "call.h"
#include "xtimer.h"
#include "byteorder.h"
#include "evtimer.h"
#include "evtimer_msg.h"
#include "net/gnrc.h"


#ifdef MODULE_GCOAP
#include "net/gcoap.h"
#include "net/nanocoap.h"
#endif

#include "saul.h"
#include "saul_reg.h"
#include "fmt.h"

#ifdef MODULE_ZTIMER
#include "ztimer.h"
#endif

#define ENABLE_DEBUG 0

/* RPL */
#include "trickle.h"

/*MALLOC PKTBUF*/
extern uint32_t bpf_gnrc_pktbuf_start_write_malloc(f12r_t *bpf, uint32_t pkt, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);
extern uint32_t bpf_gnrc_pktbuf_release_malloc(f12r_t *bpf, uint32_t pkt, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);
extern uint32_t bpf_gnrc_pktbuf_mark_malloc(f12r_t *bpf, uint32_t pkt, uint32_t size, uint32_t type, uint32_t a4, uint32_t a5);

/*STATIC PKTBUF*/
extern uint32_t bpf_gnrc_pktbuf_start_write_static(f12r_t *bpf, uint32_t pkt, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);
extern uint32_t bpf_gnrc_pktbuf_release_static(f12r_t *bpf, uint32_t pkt, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);
extern uint32_t bpf_gnrc_pktbuf_mark_static(f12r_t *bpf, uint32_t pkt, uint32_t size, uint32_t type, uint32_t a4, uint32_t a5);
extern uint32_t bpf_gnrc_pktbuf_add(f12r_t *bpf, uint32_t next, uint32_t data, uint32_t size, uint32_t type, uint32_t a5);
/*PKT*/
extern uint32_t bpf_gnrc_pktsnip_search_type(f12r_t *bpf, uint32_t pkt, uint32_t type, uint32_t a3, uint32_t a4, uint32_t a5);

extern uint32_t bpf_gnrc_pktsnip_get_type(f12r_t *bpf, uint32_t pkt, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);
extern uint32_t bpf_gnrc_pktsnip_set_type(f12r_t *bpf, uint32_t pkt, uint32_t type, uint32_t a3, uint32_t a4, uint32_t a5);

extern uint32_t bpf_gnrc_pktsnip_get_next(f12r_t *bpf, uint32_t pkt, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);
extern uint32_t bpf_gnrc_pktsnip_set_next(f12r_t *bpf, uint32_t pkt, uint32_t next, uint32_t a3, uint32_t a4, uint32_t a5);

extern uint32_t bpf_gnrc_pktsnip_get_size(f12r_t *bpf, uint32_t pkt, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);

extern uint32_t bpf_gnrc_pktsnip_get_data(f12r_t *bpf, uint32_t pkt, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);

extern uint32_t bpf_gnrc_pktsnip_get_udp_hcsum(f12r_t *bpf, uint32_t udp_hdr, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);
extern uint32_t bpf_gnrc_pktsnip_get_udp_dst_port(f12r_t *bpf, uint32_t udp_hdr, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);
extern uint32_t bpf_gnrc_pktsnip_set_udp_len(f12r_t *bpf, uint32_t udp_hdr, uint32_t size, uint32_t a3, uint32_t a4, uint32_t a5);

extern uint32_t bpf_gnrc_get_pkt_len(f12r_t *bpf, uint32_t pkt, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);

/*NETAPI*/
extern uint32_t bpf_gnrc_netapi_dispatch_send(f12r_t *bpf, uint32_t pkt, uint32_t demux_ctx, uint32_t type, uint32_t a4, uint32_t a5);
extern uint32_t bpf_gnrc_netapi_dispatch_receive(f12r_t *bpf, uint32_t type, uint32_t demux_ctx, uint32_t pkt, uint32_t a4, uint32_t a5);

/*Cross Layer*/
extern uint32_t bpf_calc_csum(f12r_t *bpf, uint32_t hdr, uint32_t pseudo_hdr, uint32_t payload, uint32_t a4, uint32_t a5);
extern uint32_t bpf_gnrc_icmpv6_build(f12r_t *bpf, uint32_t next, uint32_t type, uint32_t code, uint32_t size, uint32_t a5);

/*UDP*/
extern uint32_t bpf_gnrc_udp_calc_csum(f12r_t *bpf, uint32_t hdr, uint32_t pseudo_hdr, uint32_t a3, uint32_t a4, uint32_t a5);

/* RPL */
extern uint32_t bpf_gnrc_rpl_get_instance_by_index(f12r_t *bpf, uint32_t index, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);
extern uint32_t bpf_gnrc_rpl_get_instance_by_id(f12r_t *bpf, uint32_t id, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);
//extern uint32_t bpf_gnrc_rpl_get_dodag_from_instance(f12r_t *bpf, uint32_t instance, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);
extern uint32_t bpf_gnrc_rpl_instance_add(f12r_t *bpf, uint32_t instance_id, uint32_t inst, uint32_t a3, uint32_t a4, uint32_t a5);
extern uint32_t bpf_gnrc_rpl_instance_remove(f12r_t *bpf, uint32_t inst, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);
extern uint32_t bpf_gnrc_rpl_dodag_init(f12r_t *bpf, uint32_t inst, uint32_t dodag_id, uint32_t iface, uint32_t a4, uint32_t a5);
extern uint32_t bpf_gnrc_rpl_parent_add_by_addr(f12r_t *bpf, uint32_t dodag, uint32_t addr, uint32_t parent, uint32_t a4, uint32_t a5);
extern uint32_t bpf_gnrc_rpl_parent_remove(f12r_t *bpf, uint32_t parent, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);
extern uint32_t bpf_gnrc_rpl_parent_update(f12r_t *bpf, uint32_t dodag, uint32_t parent, uint32_t a3, uint32_t a4, uint32_t a5);
extern uint32_t bpf_gnrc_rpl_local_repair(f12r_t *bpf, uint32_t dodag, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);
extern uint32_t bpf_gnrc_rpl_delay_dao(f12r_t *bpf, uint32_t dodag, uint32_t long_delay, uint32_t a3, uint32_t a4, uint32_t a5);
extern uint32_t bpf_gnrc_rpl_get_of_for_ocp(f12r_t *bpf, uint32_t ocp, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);
extern uint32_t bpf_gnrc_rpl_send(f12r_t *bpf, uint32_t pkt, uint32_t iface, uint32_t src, uint32_t dst, uint32_t dodag_id);
extern uint32_t bpf_gnrc_rpl_init(f12r_t *bpf, uint32_t pid, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);
extern uint32_t bpf_gnrc_rpl_is_root(f12r_t *bpf, uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);
extern uint32_t bpf_gnrc_rpl_mode(f12r_t *bpf, uint32_t set, uint32_t mode, uint32_t a3, uint32_t a4, uint32_t a5);
extern uint32_t bpf_gnrc_rpl_root_dodag_id(f12r_t *bpf, uint32_t set, uint32_t dodag_id, uint32_t a3, uint32_t a4, uint32_t a5);
/* IPV6 */
extern uint32_t bpf_ipv6_addr_is_multicast(f12r_t *bpf, uint32_t dst, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);
extern uint32_t bpf_ipv6_addr_set_aiid(f12r_t *bpf, uint32_t addr, uint32_t iid, uint32_t a3, uint32_t a4, uint32_t a5);
extern uint32_t bpf_gnrc_ipv6_nib_pl_set(f12r_t *bpf, uint32_t iface, uint32_t pfx, uint32_t pfx_len, uint32_t valid_ltime, uint32_t pref_ltime);
extern uint32_t bpf_gnrc_ipv6_nib_ft_del(f12r_t *bpf, uint32_t dst, uint32_t dst_len, uint32_t a3, uint32_t a4, uint32_t a5);
extern uint32_t bpf_gnrc_ipv6_nib_ft_add(f12r_t *bpf, uint32_t dst, uint32_t dst_len, uint32_t next_hop, uint32_t iface, uint32_t lifetime);
extern uint32_t bpf_gnrc_ipv6_nib_ft_iter(f12r_t *bpf, uint32_t next_hop, uint32_t iface, uint32_t state, uint32_t fte, uint32_t a5);
extern uint32_t bpf_gnrc_ipv6_nib_pl_iter(f12r_t *bpf, uint32_t iface, uint32_t state, uint32_t ple, uint32_t a4, uint32_t a5);
extern uint32_t bpf_gnrc_sr_delete_route(f12r_t *bpf, uint32_t dst_node, uint32_t dst_size, uint32_t a3, uint32_t a4, uint32_t a5);
extern uint32_t bpf_gnrc_sr_add_new_dst(f12r_t *bpf, uint32_t child, uint32_t parent, uint32_t sr_iface_id, uint32_t sr_flags, uint32_t lifetime);
extern uint32_t bpf_gnrc_sr_initialize_table(f12r_t *bpf, uint32_t addr, uint32_t iface, uint32_t a3, uint32_t a4, uint32_t a5);
extern uint32_t bpf_gnrc_sr_deinitialize_table(f12r_t *bpf, uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);
extern uint32_t bpf_ipv6_addr_init_prefix(f12r_t *bpf, uint32_t out, uint32_t prefix, uint32_t bits, uint32_t a4, uint32_t a5);
extern uint32_t bpf_ipv6_addr_match_prefix(f12r_t *bpf, uint32_t a, uint32_t b, uint32_t a3, uint32_t a4, uint32_t a5);
extern uint32_t bpf_ipv6_addr_is_global(f12r_t *bpf, uint32_t addr, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);
extern uint32_t bpf_ipv6_addr_is_unspecified(f12r_t *bpf, uint32_t addr, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);
extern uint32_t bpf_ipv6_addr_equal(f12r_t *bpf, uint32_t addr1, uint32_t addr2, uint32_t a3, uint32_t a4, uint32_t a5);
extern uint32_t bpf_ipv6_nc_from_addr(f12r_t *bpf, uint32_t addr, uint32_t iface, uint32_t a3, uint32_t a4, uint32_t a5);
extern uint32_t bpf_ipv6_addr_from_str(f12r_t *bpf, uint32_t str, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);

/* NETIF */
extern uint32_t bpf_gnrc_netif_get_by_pid(f12r_t *bpf, uint32_t pid, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);
extern uint32_t bpf_gnrc_netif_get_by_prefix(f12r_t *bpf, uint32_t prefix, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);
extern uint32_t bpf_gnrc_netif_ipv6_addr_add_internal(f12r_t *bpf, uint32_t netif, uint32_t addr, uint32_t pfx_len, uint32_t flags, uint32_t a5);
extern uint32_t bpf_gnrc_netif_ipv6_get_iid(f12r_t *bpf, uint32_t netif, uint32_t iid, uint32_t a3, uint32_t a4, uint32_t a5);
extern uint32_t bpf_gnrc_netif_ipv6_addr_match(f12r_t *bpf, uint32_t netif, uint32_t addr, uint32_t a3, uint32_t a4, uint32_t a5);
extern uint32_t find_interface_with_rpl_mcast(f12r_t *bpf, uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);
extern uint32_t bpf_gnrc_netif_get_ipv6_addr_by_idx(f12r_t *bpf, uint32_t netif, uint32_t idx, uint32_t a3, uint32_t a4, uint32_t a5);
extern uint32_t bpf_gnrc_netif_get_by_ipv6_addr(f12r_t *bpf, uint32_t addr, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);
extern uint32_t bpf_netif_get_pid(f12r_t *bpf, uint32_t netif, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);
/*--------------------------------------------------------------------------------------------------------------------------------*/
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"

// #if ENABLE_DEBUG
uint32_t f12r_vm_printf(f12r_t *bpf, uint32_t fmt, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5)
{
    (void)bpf;
    if (ENABLE_DEBUG) {
        return printf((char*)(uintptr_t)fmt, a2, a3, a4, a5);
    }
    return 0;
}
#pragma GCC diagnostic pop

uint32_t f12r_vm_store_local(f12r_t *bpf, uint32_t key, uint32_t value, uint32_t a3, uint32_t a4, uint32_t a5)
{
    (void)a3;
    (void)a4;
    (void)a5;
    return (uint32_t)bpf_store_update_local(bpf, key, value);
}

uint32_t f12r_vm_store_global(f12r_t *bpf, uint32_t key, uint32_t value, uint32_t a3, uint32_t a4, uint32_t a5)
{
    (void)bpf;
    (void)a3;
    (void)a4;
    (void)a5;
    return (uint32_t)bpf_store_update_global(key, value);
}

uint32_t f12r_vm_fetch_local(f12r_t *bpf, uint32_t key, uint32_t value, uint32_t a3, uint32_t a4, uint32_t a5)
{
    (void)bpf;
    (void)a3;
    (void)a4;
    (void)a5;
    if (f12r_store_allowed(bpf, (void*)value, sizeof(uint32_t)) < 0) {
        return -1;
    }
    return (uint32_t)bpf_store_fetch_local(bpf, key, (uint32_t*)(uintptr_t)value);
}

uint32_t f12r_vm_fetch_global(f12r_t *bpf, uint32_t key, uint32_t value, uint32_t a3, uint32_t a4, uint32_t a5)
{
    (void)bpf;
    (void)a3;
    (void)a4;
    (void)a5;
    if (f12r_store_allowed(bpf, (void*)value, sizeof(uint32_t)) < 0) {
        return -1;
    }
    return (uint32_t)bpf_store_fetch_global(key, (uint32_t*)(uintptr_t)value);
}
// #endif


uint32_t f12r_vm_memcpy(f12r_t *bpf, uint32_t dest_p, uint32_t src_p, uint32_t size, uint32_t a4, uint32_t a5)
{
    (void)bpf;
    (void)a4;
    (void)a5;

    void *dest = (void *)(uintptr_t)dest_p;
    const void *src = (const void *)(uintptr_t)src_p;

    return (uintptr_t) memcpy(dest, src, size);
}

/*By Ahmad*/
uint32_t f12r_vm_memcmp(f12r_t *f12r, uint32_t dest_p, uint32_t src_p, uint32_t size, uint32_t a4, uint32_t a5){
    (void)f12r;
    (void)a4;
    (void)a5;

    void *dest = (void *)(uintptr_t)dest_p;
    const void *src = (const void *)(uintptr_t)src_p;

    return memcmp(dest, src, size);
}


uint32_t f12r_vm_memset(f12r_t *f12r, uint32_t dest_p, uint32_t value, uint32_t size, uint32_t a4, uint32_t a5){
    (void)f12r;
    (void)a4;
    (void)a5;

    uint8_t *dest_p1 = (uint8_t *) dest_p;
    uint8_t value1 = (uint8_t) value;

    return (uintptr_t) memset(dest_p1, value1, size);

}

uint32_t f12r_vm_malloc(f12r_t *bpf, uint32_t size, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5)
{
    (void)bpf;
    (void)a2;
    (void)a3;
    (void)a4;
    (void)a5;

    return (uintptr_t) malloc(size);
}

uint32_t f12r_vm_free(f12r_t *bpf, uint32_t ptr, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5){
    (void)bpf;
    (void)a2;
    (void)a3;
    (void)a4;
    (void)a5;

    free((void *)(uintptr_t)ptr);
    return 0;
}

uint32_t bpf_vm_pointer_get_element(f12r_t *bpf, uint32_t p, uint32_t offset, uint32_t size, uint32_t a4, uint32_t a5)
{
    (void)bpf;
    (void)a4;
    (void)a5;

    uint8_t *p1 = (uint8_t *)(uintptr_t)p;
    if (p1 == NULL) {
        return UINT32_MAX; // Handle null pointer
    }

    p1 = p1 + offset;
    uint32_t value_at_offset = 0;

    memcpy(&value_at_offset, p1, size);

    return value_at_offset; // Return the value at the offset
}

uint32_t bpf_vm_pointer_get_element_pointer(f12r_t *bpf, uint32_t p, uint32_t offset, uint32_t a3, uint32_t a4, uint32_t a5)
{
    (void)bpf;
    (void)a3;
    (void)a4;
    (void)a5;

    if (p == 0) {
        return UINT32_MAX; // Indicate error with a specific value
    }

    uint8_t *p1 = (uint8_t *)(uintptr_t)p;

    // Assuming no further validation of offset is possible here
    p1 += offset;

    return (uintptr_t) p1; // Return the value at the offset
}

uint32_t bpf_vm_pointer_set_element(f12r_t *bpf, uint32_t p, uint32_t offset, uint32_t value, uint32_t len, uint32_t a5)
{
    (void)bpf;
    (void)a5;

    uint8_t *p1 = (uint8_t *)(uintptr_t)p;
    if (p1 == NULL) {
        return -1; // Handle null pointer
    }

    p1 = p1 + offset;
    memcpy(p1, &value, len);

    return 0; // Return the value at the offset
}

// #if USE_RPL
uint32_t bpf_trickle_reset_timer(f12r_t *bpf, uint32_t trickle, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5){
    (void)bpf;
    (void)a2;
    (void)a3;
    (void)a4;
    (void)a5;

    trickle_t *trickle1 = (trickle_t *) (uintptr_t)trickle;
    trickle_reset_timer(trickle1);
    return 0;
}

uint32_t bpf_trickle_increment_counter(f12r_t *bpf, uint32_t trickle, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5){
    (void)bpf;
    (void)a2;
    (void)a3;
    (void)a4;
    (void)a5;

    trickle_t *trickle1 = (trickle_t *) (uintptr_t)trickle;
    trickle_increment_counter(trickle1);
    return 0;

}
#define GNRC_RPL_MSG_TYPE_TRICKLE_MSG         (0x0901)
uint32_t bpf_trickle_start_timer(f12r_t *bpf, uint32_t pid, uint32_t trickle, uint32_t Imin, uint32_t Imax, uint32_t k){
    (void) bpf;
    kernel_pid_t pid1 = (kernel_pid_t) pid;
    trickle_t *trickle1 = (trickle_t *) (uintptr_t)trickle;
    uint8_t Imax1= (uint8_t) Imax;
    uint8_t k1 = (uint8_t) k;

    trickle_start(pid1, trickle1, GNRC_RPL_MSG_TYPE_TRICKLE_MSG, Imin, Imax1, k1);
    return 0;
}
// #endif

uint32_t bpf_byteorder_ntohs(f12r_t *bpf, uint32_t bytes, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5){
    (void)bpf;
    (void)a2;
    (void)a3;
    (void)a4;
    (void)a5;

    uint16_t bytes1 = (uint16_t) bytes;
    return ntohs(bytes1);
}
uint32_t bpf_byteorder_htons(f12r_t *bpf, uint32_t bytes, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5){
    (void)bpf;
    (void)a2;
    (void)a3;
    (void)a4;
    (void)a5;

    uint16_t bytes1 = (uint16_t) bytes;
    return htons(bytes1);
}
uint32_t bpf_byteorder_ntohl(f12r_t *bpf, uint32_t bytes, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5){
    (void)bpf;
    (void)a2;
    (void)a3;
    (void)a4;
    (void)a5;

    return ntohl(bytes);
}
uint32_t bpf_byteorder_htonl(f12r_t *bpf, uint32_t bytes, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5){
    (void)bpf;
    (void)a2;
    (void)a3;
    (void)a4;
    (void)a5;

    return htonl(bytes);
}

uint32_t bpf_trigger_hook(f12r_t *bpf, uint32_t hook_trigger, uint32_t ctx, uint32_t size_ctx, uint32_t a4, uint32_t a5){
    (void)bpf;
    (void)a4;
    (void)a5;

    void *ctx1 = (void *)(uintptr_t) ctx;
    int64_t vm_res = 0;

    int res = f12r_hook_execute(hook_trigger, ctx1, size_ctx, &vm_res);
    // printf("FC Call: Return code (expected 0): %d\n", res);
    (void) res;

    return (uint32_t) vm_res;
}

uint32_t bpf_evtimer_add_del(f12r_t *bpf, uint32_t evtimer, uint32_t event, uint32_t type, uint32_t a4, uint32_t a5){
    (void)bpf;
    (void)a4;
    (void)a5;

    // evtimer_t *evtimer1 = (evtimer_t *) evtimer;
    // evtimer_event_t *event1 = (evtimer_event_t *) event;

    switch (type){
        case 0: // add
            evtimer_add((evtimer_t *)(uintptr_t)evtimer, (evtimer_event_t *)(uintptr_t)event);
            break;
        case 1: // del
            evtimer_del((evtimer_t *)(uintptr_t)evtimer, (evtimer_event_t *)(uintptr_t)event);
            break;
    }
    return 1;
}

uint32_t bpf_evtimer_add_msg(f12r_t *bpf, uint32_t evtimer, uint32_t event, uint32_t pid, uint32_t a4, uint32_t a5){
    (void)bpf;
    (void)a4;
    (void)a5;


    // evtimer_t *evtimer1 = (evtimer_t *) evtimer;
    // evtimer_event_t *event1 = (evtimer_event_t *) event;

    evtimer_add_msg((evtimer_msg_t *)(uintptr_t)evtimer, (evtimer_msg_event_t *)(uintptr_t)event, (kernel_pid_t)pid);
    return 1;

}

#ifdef MODULE_ZTIMER
uint32_t f12r_vm_ztimer_now(f12r_t *bpf, uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5)
{
    (void)bpf;
    (void)a1;
    (void)a2;
    (void)a3;
    (void)a4;
    (void)a5;

    return ztimer_now(ZTIMER_USEC);
}
uint32_t f12r_vm_ztimer_periodic_wakeup(f12r_t *bpf, uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5)
{
    (void)bpf;
    (void)a1;
    (void)a2;
    (void)a3;
    (void)a4;
    (void)a5;

    uint32_t *last = (uint32_t*)(intptr_t)a1;

    ztimer_periodic_wakeup(ZTIMER_USEC, last, a2);
    return 0;
}
#endif


f12r_call_t f12r_get_external_call(uint32_t num)
{
    switch(num) {

        /*Memory Access*/
        case BPF_FUNC_BPF_PRINTF:
            return &f12r_vm_printf;
        case BPF_FUNC_BPF_STORE_LOCAL:
            return &f12r_vm_store_local;
        case BPF_FUNC_BPF_STORE_GLOBAL:
            return &f12r_vm_store_global;
        case BPF_FUNC_BPF_FETCH_LOCAL:
            return &f12r_vm_fetch_local;
        case BPF_FUNC_BPF_FETCH_GLOBAL:
            return &f12r_vm_fetch_global;
        case BPF_FUNC_BPF_MEMSET:
            return &f12r_vm_memset;
        case BPF_FUNC_BPF_MALLOC:
            return &f12r_vm_malloc;
        case BPF_FUNC_BPF_FREE:
            return &f12r_vm_free;
        case BPF_FUNC_BPF_MEMCPY:
            return &f12r_vm_memcpy;
        case BPF_FUNC_BPF_MEMCMP:
            return &f12r_vm_memcmp;
        case BPF_FUNC_BPF_POINTER_GET_ELEMENT:
            return &bpf_vm_pointer_get_element;
        case BPF_FUNC_BPF_POINTER_ELEMENT_POINTER:
            return &bpf_vm_pointer_get_element_pointer;
        case BPF_FUNC_BPF_POINTER_SET_ELEMENT:
            return &bpf_vm_pointer_set_element;

        case BPF_FUNC_BPF_TRIGGER_HOOK:
            return &bpf_trigger_hook;

        case BPF_FUNC_BPF_EVTIMER_ADD_DEL:
            return &bpf_evtimer_add_del;
        case BPF_FUNC_BPF_EVTIMER_ADD_MSG:
            return &bpf_evtimer_add_msg;
    // #if (USE_RPL || USE_UDP)
        case BPF_FUNC_BPF_BYTEORDER_NTOHS:
            return &bpf_byteorder_ntohs;
        case BPF_FUNC_BPF_BYTEORDER_HTONS:
            return &bpf_byteorder_htons;
        case BPF_FUNC_BPF_BYTEORDER_NTOHL:
            return &bpf_byteorder_ntohl;
        case BPF_FUNC_BPF_BYTEORDER_HTONL:
            return &bpf_byteorder_htonl;
    // #endif

      
        
        
    #if USE_RPL
        /*Static PKTBUF*/
        case BPF_FUNC_BPF_GNRC_PKT_BUFF_START_WRITE_STATIC:
            return &bpf_gnrc_pktbuf_start_write;
        case BPF_FUNC_BPF_GNRC_PKT_BUFF_RELEASE_STATIC:
            return &bpf_gnrc_pktbuf_release;
        case BPF_FUNC_BPF_GNRC_PKT_BUFF_MARK_STATIC:
            return &bpf_gnrc_pktbuf_mark;
        case BPF_FUNC_BPF_GNRC_PKT_BUFF_ADD_STATIC:
            return &bpf_gnrc_pktbuf_add;

        /*PKT*/
        case BPF_FUNC_BPF_GNRC_PKT_SEARCH_TYPE:
            return &bpf_gnrc_pktsnip_search_type;
        case BPF_FUNC_BPF_GNRC_PKT_SET_TYPE:
            return &bpf_gnrc_pktsnip_set_type;
        case BPF_FUNC_BPF_GNRC_PKT_GET_TYPE:
            return &bpf_gnrc_pktsnip_get_type;

        case BPF_FUNC_BPF_GNRC_PKT_SET_NEXT:
            return &bpf_gnrc_pktsnip_set_next;
        case BPF_FUNC_BPF_GNRC_PKT_GET_NEXT:
            return &bpf_gnrc_pktsnip_get_next;

        case BPF_FUNC_BPF_GNRC_PKT_GET_SIZE:
            return &bpf_gnrc_pktsnip_get_size;

        case BPF_FUNC_BPF_GNRC_PKT_GET_DATA:
            return &bpf_gnrc_pktsnip_get_data;

        case BPF_FUNC_BPF_GNRC_PKT_GET_PKT_LEN:
            return &bpf_gnrc_get_pkt_len;
    // #endif

        /*UDP*/
    // #if USE_UDP
        case BPF_FUNC_BPF_GNRC_PKT_GET_UDP_HCSUM:
            return &bpf_gnrc_pktsnip_get_udp_hcsum;
        case BPF_FUNC_BPF_GNRC_CALC_UDP_CSUM:
            return &bpf_gnrc_udp_calc_csum;
        case BPF_FUNC_BPF_GNRC_PKT_GET_UDP_DST_PORT:
            return &bpf_gnrc_pktsnip_get_udp_dst_port;
        case BPF_FUNC_BPF_GNRC_PKT_SET_UDP_LEN:
            return &bpf_gnrc_pktsnip_set_udp_len;
    
        /*NETAPI*/
        case BPF_FUNC_BPF_GNRC_NETAPI_DISPATCH_SEND:
            return &bpf_gnrc_netapi_dispatch_send;
        case BPF_FUNC_BPF_GNRC_NETAPI_DISPATCH_RX:
            return &bpf_gnrc_netapi_dispatch_receive;

        /*CROSS*/
        case BPF_FUNC_BPF_CALC_CSUM:
            return &bpf_calc_csum;
        case BPF_FUNC_BPF_ICMPV6_BUILD:
            return &bpf_gnrc_icmpv6_build;
    // #endif

    // #if USE_RPL
        /*-----------------------------*/
        case BPF_FUNC_BPF_TRICKLE_RESET_TIMER:
            return &bpf_trickle_reset_timer;
        case BPF_FUNC_BPF_TRICKLE_INCRE_TIMER:
            return &bpf_trickle_increment_counter;
        case BPF_FUNC_BPF_TRICKLE_START_TIMER:
            return &bpf_trickle_start_timer;
        /* RPL */
        case BPF_FUNC_BPF_GNRC_RPL_GET_INSTANCE_BY_INDEX:
            return &bpf_gnrc_rpl_get_instance_by_index;
        case BPF_FUNC_BPF_GNRC_RPL_GET_INSTANCE_BY_ID:
            return &bpf_gnrc_rpl_get_instance_by_id;
        case BPF_FUNC_BPF_GNRC_RPL_INSTANCE_ADD:
            return &bpf_gnrc_rpl_instance_add;
        case BPF_FUNC_BPF_GNRC_RPL_INSTANCE_REM:
            return &bpf_gnrc_rpl_instance_remove;
        case BPF_FUNC_BPF_GNRC_RPL_DODAG_INIT:
            return &bpf_gnrc_rpl_dodag_init;
        case BPF_FUNC_BPF_GNRC_RPL_PARENT_ADD_ADDR:
            return &bpf_gnrc_rpl_parent_add_by_addr;
        case BPF_FUNC_BPF_GNRC_RPL_PARENT_REMOVE:
            return &bpf_gnrc_rpl_parent_remove;
        case BPF_FUNC_BPF_GNRC_RPL_PARENT_UPDATE:
            return &bpf_gnrc_rpl_parent_update;
        case BPF_FUNC_BPF_GNRC_RPL_LOCAL_REPAIR:
            return &bpf_gnrc_rpl_local_repair;
        case BPF_FUNC_BPF_GNRC_RPL_DELAY_DAO:
            return &bpf_gnrc_rpl_delay_dao;
        case BPF_FUNC_BPF_GNRC_RPL_GET_OF_FOR_OCP:
            return &bpf_gnrc_rpl_get_of_for_ocp;
        case BPF_FUNC_BPF_RPL_SEND:
            return &bpf_gnrc_rpl_send;
        case BPF_FUNC_BPF_RPL_INIT:
            return bpf_gnrc_rpl_init;
        case BPF_FUNC_BPF_RPL_SET_IS_ROOT:
            return &bpf_gnrc_rpl_is_root;
        case BPF_FUNC_BPF_RPL_SET_ROOT_DODAG_ID:
            return &bpf_gnrc_rpl_root_dodag_id;
        case BPF_FUNC_BPF_RPL_MODE:
            return &bpf_gnrc_rpl_mode;
   
        
        /* IPv6 */
        case BPF_FUNC_BPF_IPV6_ADDR_IS_MULTICAST:
            return &bpf_ipv6_addr_is_multicast;
        case BPF_FUNC_BPF_IPV6_ADDR_SET_IID:
            return &bpf_ipv6_addr_set_aiid;
        case BPF_FUNC_BPF_GNRC_IPV6_NIB_PL_SET:
            return &bpf_gnrc_ipv6_nib_pl_set;
        case BPF_FUNC_BPF_GNRC_IPV6_NIB_FT_ITER:
            return &bpf_gnrc_ipv6_nib_ft_iter;
    // #ifdef MODULE_GNRC_RPL_SR
        case BPF_FUNC_BPF_GNRC_SR_DELETE_ROUTE:
            return &bpf_gnrc_sr_delete_route;
        case BPF_FUNC_BPF_GNRC_SR_ADD_NEW_DST:
            return &bpf_gnrc_sr_add_new_dst;
        case BPF_FUNC_BPF_GNRC_SR_INIIT_TABLE:
            return &bpf_gnrc_sr_initialize_table;
        case BPF_FUNC_BPF_GNRC_SR_DEINIIT_TABLE:
            return &bpf_gnrc_sr_deinitialize_table;

        case BPF_FUNC_BPF_IPV6_ADDR_MATCH_PREFIX:
            return &bpf_ipv6_addr_match_prefix;
        case BPF_FUNC_BPF_GNRC_IPV6_NIB_PL_ITER:
            return &bpf_gnrc_ipv6_nib_pl_iter;
        case BPF_FUNC_BPF_IPV6_ADDR_IS_GLOBAL:
            return &bpf_ipv6_addr_is_global;
        case BPF_FUNC_BPF_IPV6_ADDR_NOT_SPECIF:
            return &bpf_ipv6_addr_is_unspecified;
        case BPF_FUNC_BPF_IPV6_ADDR_EQUAL:
            return &bpf_ipv6_addr_equal;
        case BPF_FUNC_BPF_IPV6_NC_FROM_ADDR:
            return &bpf_ipv6_nc_from_addr;
        case BPF_FUNC_BPF_IPV6_ADDR_FROM_STR:
            return &bpf_ipv6_addr_from_str;
        // #endif
    
    
    // #if USE_RPL
        /* NETIF*/
        case BPF_FUNC_BPF_GNRC_NETIF_IPV6_ADDR_ADD_INTERNAL:
            return &bpf_gnrc_netif_ipv6_addr_add_internal;
        case BPF_FUNC_BPF_GNRC_NETIF_IPV6_GET_IID:
            return &bpf_gnrc_netif_ipv6_get_iid;
        case BPF_FUNC_BPF_GNRC_NETIF_IPV6_ADDR_MATCH:
            return &bpf_gnrc_netif_ipv6_addr_match;
    // #ifdef MODULE_GNRC_RPL
        case BPF_FUNC_BPF_FIND_INTERFACE_RPL_MCST:
            return &find_interface_with_rpl_mcast;
    // #endif
        case BPF_FUNC_BPF_GNRC_NETIF_GET_IPV6_ADDR_BY_IDX:
            return &bpf_gnrc_netif_get_ipv6_addr_by_idx;
        case BPF_FUNC_BPF_GNRC_NETIF_GET_BY_IPV6:
            return bpf_gnrc_netif_get_by_ipv6_addr;
        case BPF_FUNC_BPF_NETIF_GET_PID:
            return &bpf_netif_get_pid;
    #endif
        /*-----------------------------*/
        // Needed in SDN mode
        case BPF_FUNC_BPF_GNRC_IPV6_NIB_FT_ADD:
            return &bpf_gnrc_ipv6_nib_ft_add;
        case BPF_FUNC_BPF_GNRC_IPV6_NIB_FT_DEL:
            return &bpf_gnrc_ipv6_nib_ft_del;
        
        
        /* NETIF*/
        case BPF_FUNC_BPF_GNRC_NETIF_GET_BY_PID:
            return &bpf_gnrc_netif_get_by_pid;
        case BPF_FUNC_BPF_GNRC_NETIF_GET_BY_PREFIX:
            return &bpf_gnrc_netif_get_by_prefix;


#ifdef MODULE_SAUL_REG
        case BPF_FUNC_BPF_SAUL_REG_FIND_NTH:
            return &f12r_vm_saul_reg_find_nth;
        case BPF_FUNC_BPF_SAUL_REG_FIND_TYPE:
            return &f12r_vm_saul_reg_find_type;
        case BPF_FUNC_BPF_SAUL_REG_READ:
            return &f12r_vm_saul_reg_read;
#endif

#ifdef MODULE_GCOAP
        case BPF_FUNC_BPF_GCOAP_RESP_INIT:
            return &f12r_vm_gcoap_resp_init;
        case BPF_FUNC_BPF_COAP_OPT_FINISH:
            return &f12r_vm_coap_opt_finish;
        case BPF_FUNC_BPF_COAP_ADD_FORMAT:
            return &f12r_vm_coap_add_format;
        case BPF_FUNC_BPF_COAP_GET_PDU:
            return &f12r_vm_coap_get_pdu;
#endif
#if 0
#ifdef MODULE_FMT
        case BPF_FUNC_BPF_FMT_S16_DFP:
            return &f12r_vm_fmt_s16_dfp;
        case BPF_FUNC_BPF_FMT_U32_DEC:
            return &f12r_vm_fmt_u32_dec;
#endif
#endif

        case BPF_FUNC_BPF_ZTIMER_NOW:
            return &f12r_vm_ztimer_now;
        case BPF_FUNC_BPF_ZTIMER_PERIODIC_WAKEUP:
            return &f12r_vm_ztimer_periodic_wakeup;


        default:
            return NULL;
    }
}
