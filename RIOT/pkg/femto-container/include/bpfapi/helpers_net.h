/*
 * Copyright (C) 2020 Inria
 * Copyright (C) 2020 Koen Zandberg <koen@bergzand.net>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef BPF_BPFAPI_HELPERS_NET_H
#define BPF_BPFAPI_HELPERS_NET_H

#include <stdint.h>
#include "bpf/shared.h"
#include "phydat.h"
#include "net/gnrc.h"
//#include "net/gnrc/rpl.h"

#ifdef __cplusplus
extern "C" {
#endif

/*PKTBUF*/
// MALLOC
static void *(*bpf_gnrc_pktbuf_start_write_malloc)(void* pkt) = (void *) BPF_FUNC_BPF_GNRC_PKT_BUFF_START_WRITE_MALLOC;
static void *(*bpf_gnrc_pktbuf_release_malloc)(void* pkt) = (void *) BPF_FUNC_BPF_GNRC_PKT_BUFF_RELEASE_MALLOC;
static void *(*bpf_gnrc_pktbuf_mark_malloc)(void* pkt, uint32_t size, uint32_t type) = (void *) BPF_FUNC_BPF_GNRC_PKT_BUFF_MARK_MALLOC;

// STATIC
static void *(*bpf_gnrc_pktbuf_start_write)(void* pkt) = (void *) BPF_FUNC_BPF_GNRC_PKT_BUFF_START_WRITE_STATIC;
static void *(*bpf_gnrc_pktbuf_release)(void* pkt) = (void *) BPF_FUNC_BPF_GNRC_PKT_BUFF_RELEASE_STATIC;
static void *(*bpf_gnrc_pktbuf_mark)(void* pkt, uint32_t size, uint32_t type) = (void *) BPF_FUNC_BPF_GNRC_PKT_BUFF_MARK_STATIC;
static void *(*bpf_gnrc_pktbuf_add)(uintptr_t next, void *data, uint32_t size, int32_t type) = (void *) BPF_FUNC_BPF_GNRC_PKT_BUFF_ADD_STATIC;

/*PKT*/
static void *(*bpf_gnrc_pktsnip_search_type)(void* pkt, uint32_t type) = (void *) BPF_FUNC_BPF_GNRC_PKT_SEARCH_TYPE;
static void *(*bpf_gnrc_pktsnip_set_type)(void* pkt, uint32_t type) = (void *) BPF_FUNC_BPF_GNRC_PKT_SET_TYPE;
static void *(*bpf_gnrc_pktsnip_get_type)(void* pkt) = (void *) BPF_FUNC_BPF_GNRC_PKT_GET_TYPE;

static void *(*bpf_gnrc_pktsnip_set_next)(void* pkt, void* next) = (void *) BPF_FUNC_BPF_GNRC_PKT_SET_NEXT;
static void *(*bpf_gnrc_pktsnip_get_next)(void* pkt) = (void *) BPF_FUNC_BPF_GNRC_PKT_GET_NEXT;
static void *(*bpf_gnrc_pktsnip_get_size)(void* pkt) = (void *) BPF_FUNC_BPF_GNRC_PKT_GET_SIZE;
static void *(*bpf_gnrc_pktsnip_get_data)(void* pkt) = (void *) BPF_FUNC_BPF_GNRC_PKT_GET_DATA;

static void *(*bpf_gnrc_get_pkt_len)(void* pkt) = (void *) BPF_FUNC_BPF_GNRC_PKT_GET_PKT_LEN;

/*UDP*/
static void *(*bpf_gnrc_pktsnip_get_udp_hcsum)(void* udp_hdr) = (void *) BPF_FUNC_BPF_GNRC_PKT_GET_UDP_HCSUM;
static void *(*bpf_gnrc_udp_calc_csum)(void* hdr, void* pseudo_hdr) = (void *) BPF_FUNC_BPF_GNRC_CALC_UDP_CSUM;
static void *(*bpf_gnrc_pktsnip_get_udp_dst_port)(void* udp_hdr) = (void *) BPF_FUNC_BPF_GNRC_PKT_GET_UDP_DST_PORT;
static void *(*bpf_gnrc_pktsnip_set_udp_len)(void* udp_hdr, uint32_t size) = (void *) BPF_FUNC_BPF_GNRC_PKT_SET_UDP_LEN;


/*NETAPI*/
static void *(*bpf_gnrc_netapi_dispatch_send)(uint32_t type, uint32_t demux_ctx, void* pkt) = (void *) BPF_FUNC_BPF_GNRC_NETAPI_DISPATCH_SEND;
static void *(*bpf_gnrc_netapi_dispatch_receive)(uint32_t type, uint32_t demux_ctx, void* pkt) = (void *) BPF_FUNC_BPF_GNRC_NETAPI_DISPATCH_RX;

/*CROSS*/
static void *(*bpf_calc_csum)(void* hdr, void* pseudo_hdr, void* payload) = (void *) BPF_FUNC_BPF_CALC_CSUM;
static void *(*bpf_gnrc_icmpv6_build)(uintptr_t next, uint8_t type, uint8_t code, uint32_t size) = (void *) BPF_FUNC_BPF_ICMPV6_BUILD;

/* RPL */
static uintptr_t (*bpf_gnrc_rpl_get_instance_by_index)(uint32_t index) = (void *) BPF_FUNC_BPF_GNRC_RPL_GET_INSTANCE_BY_INDEX;
static uintptr_t (*bpf_gnrc_rpl_get_instance_by_id)(uint32_t id) = (void *) BPF_FUNC_BPF_GNRC_RPL_GET_INSTANCE_BY_ID;
//static uintptr_t (*bpf_gnrc_rpl_get_dodag_from_instance)(uintptr_t instance) = (void *) BPF_FUNC_BPF_GNRC_RPL_GET_DODAG_FROM_INST;
static bool (*bpf_gnrc_rpl_instance_add)(uint8_t instance_id, uintptr_t instance) = (void *) BPF_FUNC_BPF_GNRC_RPL_INSTANCE_ADD;
static bool (*bpf_gnrc_rpl_instance_remove)(uintptr_t instance) = (void *) BPF_FUNC_BPF_GNRC_RPL_INSTANCE_REM;
static bool (*bpf_gnrc_rpl_dodag_init)(uintptr_t instance, uintptr_t dodag_id, kernel_pid_t iface) = (void *) BPF_FUNC_BPF_GNRC_RPL_DODAG_INIT;
static void *(*bpf_gnrc_rpl_parent_add_by_addr)(uintptr_t dodag, uintptr_t addr, uintptr_t parent) = (void *) BPF_FUNC_BPF_GNRC_RPL_PARENT_ADD_ADDR;
static bool (*bpf_gnrc_rpl_parent_remove)(uintptr_t parent) = (void *) BPF_FUNC_BPF_GNRC_RPL_PARENT_REMOVE;
static void (*bpf_gnrc_rpl_parent_update)(uintptr_t dodag, uintptr_t parent) = (void *) BPF_FUNC_BPF_GNRC_RPL_PARENT_UPDATE;
static void (*bpf_gnrc_rpl_local_repair)(uintptr_t dodag) = (void *) BPF_FUNC_BPF_GNRC_RPL_LOCAL_REPAIR;
static void (*bpf_gnrc_rpl_delay_dao)(uintptr_t dodag, bool long_delay) = (void *) BPF_FUNC_BPF_GNRC_RPL_DELAY_DAO;
static void *(*bpf_gnrc_rpl_get_of_for_ocp)(uint16_t ocp) = (void *) BPF_FUNC_BPF_GNRC_RPL_GET_OF_FOR_OCP;
static void (*bpf_gnrc_rpl_send)(uintptr_t pkt, int16_t iface, uintptr_t src, uintptr_t dst, uintptr_t dodag_id) = (void *) BPF_FUNC_BPF_RPL_SEND;
static int16_t (*bpf_gnrc_rpl_init)(int16_t pid) = (void *) BPF_FUNC_BPF_RPL_INIT;
static int16_t (*bpf_gnrc_rpl_is_root)(bool set) = (void *)BPF_FUNC_BPF_RPL_SET_IS_ROOT;
static int8_t (*bpf_gnrc_rpl_mode)(bool set, int8_t mode) = (void *) BPF_FUNC_BPF_RPL_MODE;
static void *(*bpf_gnrc_rpl_root_dodag_id)(bool set, ipv6_addr_t *dodag_id) = (void *) BPF_FUNC_BPF_RPL_SET_ROOT_DODAG_ID;

/* SR */
static int (*bpf_gnrc_sr_delete_route)(ipv6_addr_t *dst_node, size_t dst_size) = (void *) BPF_FUNC_BPF_GNRC_SR_DELETE_ROUTE;
static int (*bpf_gnrc_sr_add_new_dst)(ipv6_addr_t *child, ipv6_addr_t *parent, kernel_pid_t sr_iface_id, 
                uint32_t sr_flags, uint32_t lifetime) = (void *) BPF_FUNC_BPF_GNRC_SR_ADD_NEW_DST;
static int (*bpf_gnrc_sr_initialize_table)(ipv6_addr_t *adrr, int16_t iface) = (void *) BPF_FUNC_BPF_GNRC_SR_INIIT_TABLE;
static int (*bpf_gnrc_sr_deinitialize_table)(void) = (void *) BPF_FUNC_BPF_GNRC_SR_DEINIIT_TABLE;
/*IPV6 */
static int (*bpf_ipv6_addr_is_multicast)(ipv6_addr_t* dst) = (void *) BPF_FUNC_BPF_IPV6_ADDR_IS_MULTICAST;
static int (*bpf_ipv6_addr_set_aiid)(ipv6_addr_t *addr, uint8_t *iid) = (void *) BPF_FUNC_BPF_IPV6_ADDR_SET_IID;
static int (*bpf_gnrc_ipv6_nib_pl_set)(unsigned iface, ipv6_addr_t *pfx, 
                        unsigned pfx_len, uint32_t valid_ltime, uint32_t pref_ltime) = (void *) BPF_FUNC_BPF_GNRC_IPV6_NIB_PL_SET;
static int (*bpf_gnrc_ipv6_nib_ft_del)(ipv6_addr_t *dst, unsigned dst_len) = (void *) BPF_FUNC_BPF_GNRC_IPV6_NIB_FT_DEL;
static int (*bpf_gnrc_ipv6_nib_ft_add)(ipv6_addr_t *dst, unsigned dst_len, 
                                    ipv6_addr_t *next_hop, unsigned iface, uint32_t lifetime) = (void *) BPF_FUNC_BPF_GNRC_IPV6_NIB_FT_ADD;
static bool (*bpf_gnrc_ipv6_nib_ft_iter)(ipv6_addr_t *next_hop, unsigned iface, void **state, uintptr_t fte) = (void *)BPF_FUNC_BPF_GNRC_IPV6_NIB_FT_ITER;
static bool (*bpf_gnrc_ipv6_nib_pl_iter)(unsigned iface, void **state, uintptr_t ple) = (void *) BPF_FUNC_BPF_GNRC_IPV6_NIB_PL_ITER;
static void (*bpf_ipv6_addr_init_prefix)(ipv6_addr_t *out, const ipv6_addr_t *prefix, uint8_t bits) = (void *) BPF_FUNC_BPF_IPV6_ADDR_INIT_PREIFX;
static uint8_t (*bpf_ipv6_addr_match_prefix)(ipv6_addr_t *a, ipv6_addr_t *b) = (void *) BPF_FUNC_BPF_IPV6_ADDR_MATCH_PREFIX;

static bool (*bpf_ipv6_addr_is_global)(ipv6_addr_t *addr) = (void *) BPF_FUNC_BPF_IPV6_ADDR_IS_GLOBAL;
static bool (*bpf_ipv6_addr_is_unspecified)(ipv6_addr_t *addr) = (void *) BPF_FUNC_BPF_IPV6_ADDR_NOT_SPECIF;
static bool (*bpf_ipv6_addr_equal)(ipv6_addr_t *addr1, ipv6_addr_t *addr2) = (void *) BPF_FUNC_BPF_IPV6_ADDR_EQUAL;
static int (*bpf_ipv6_nc_from_addr)(ipv6_addr_t *addr, int16_t iface) = (void *) BPF_FUNC_BPF_IPV6_NC_FROM_ADDR;
static void *(*bpf_ipv6_from_str)(const char *str) = (void *) BPF_FUNC_BPF_IPV6_ADDR_FROM_STR;


/* NETIF */
static void *(*bpf_gnrc_netif_get_by_pid)(kernel_pid_t pid) = (void *) BPF_FUNC_BPF_GNRC_NETIF_GET_BY_PID;
static void *(*bpf_gnrc_netif_get_by_prefix)(ipv6_addr_t *prefix) = (void *)BPF_FUNC_BPF_GNRC_NETIF_GET_BY_PREFIX;
static int (*bpf_gnrc_netif_ipv6_addr_add_internal)(gnrc_netif_t *netif, ipv6_addr_t *addr, 
            unsigned pfx_len, uint8_t flags) = (void *) BPF_FUNC_BPF_GNRC_NETIF_IPV6_ADDR_ADD_INTERNAL;
static int (*bpf_gnrc_netif_ipv6_get_iid)(gnrc_netif_t *netif, eui64_t *iid) = (void *) BPF_FUNC_BPF_GNRC_NETIF_IPV6_GET_IID;
static int (*bpf_gnrc_netif_ipv6_addr_match)(gnrc_netif_t *netif, ipv6_addr_t *addr) = (void *) BPF_FUNC_BPF_GNRC_NETIF_IPV6_ADDR_MATCH;
static void *(*find_interface_with_rpl_mcast)(void) = (void *) BPF_FUNC_BPF_FIND_INTERFACE_RPL_MCST;
static ipv6_addr_t *(*bpf_gnrc_netif_get_ipv6_addr_by_idx)(gnrc_netif_t *netif, uint32_t idx) = (void *) BPF_FUNC_BPF_GNRC_NETIF_GET_IPV6_ADDR_BY_IDX;
static void *(*bpf_gnrc_netif_get_by_ipv6_addr)(ipv6_addr_t *addr) = (void *) BPF_FUNC_BPF_GNRC_NETIF_GET_BY_IPV6;
static kernel_pid_t (*bpf_netif_get_pid)(gnrc_netif_t *netif) = (void *) BPF_FUNC_BPF_NETIF_GET_PID;


#ifdef __cplusplus

}
#endif
#endif /* BPF_APPLICATION_CALL_H */
