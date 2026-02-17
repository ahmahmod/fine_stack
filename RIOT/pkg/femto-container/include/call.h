/*
 * Copyright (C) 2020 Inria
 * Copyright (C) 2020 Koen Zandberg <koen@bergzand.net>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef BPF_CALL_H
#define BPF_CALL_H

#include <stdint.h>
#include "femtocontainer/femtocontainer.h"

#ifdef __cplusplus
extern "C" {
#endif


uint32_t f12r_vm_printf(f12r_t *bpf, uint32_t fmt, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);
uint32_t f12r_vm_memcpy(f12r_t *f12r, uint32_t dest_p, uint32_t src_p, uint32_t size, uint32_t a4, uint32_t a5);
uint32_t f12r_vm_memcmp(f12r_t *f12r, uint32_t dest_p, uint32_t src_p, uint32_t size, uint32_t a4, uint32_t a5);
uint32_t f12r_vm_memset(f12r_t *f12r, uint32_t dest_p, uint32_t value, uint32_t size, uint32_t a4, uint32_t a5);
uint32_t f12r_vm_malloc(f12r_t *bpf, uint32_t size, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);
uint32_t f12r_vm_free(f12r_t *bpf, uint32_t ptr, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);


uint32_t bpf_vm_printf(f12r_t *bpf, uint32_t fmt, uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4);
uint32_t bpf_vm_store_local(f12r_t *bpf, uint32_t fmt, uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4);
uint32_t bpf_vm_store_global(f12r_t *bpf, uint32_t fmt, uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4);
uint32_t bpf_vm_fetch_local(f12r_t *bpf, uint32_t fmt, uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4);
uint32_t bpf_vm_fetch_global(f12r_t *bpf, uint32_t fmt, uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4);
uint32_t bpf_vm_memcpy(f12r_t *bpf, uint32_t dest_p, uint32_t src_p, uint32_t size, uint32_t a4, uint32_t a5);
uint32_t bpf_vm_now_ms(f12r_t *bpf, uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);
uint32_t bpf_vm_saul_reg_find_nth(f12r_t *bpf, uint32_t nth, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);
uint32_t bpf_vm_saul_reg_find_type(f12r_t *bpf, uint32_t type, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);
uint32_t bpf_vm_saul_reg_read(f12r_t *bpf, uint32_t dev_p, uint32_t data_p, uint32_t a3, uint32_t a4, uint32_t a5);
uint32_t bpf_vm_gcoap_resp_init(f12r_t *bpf, uint32_t coap_ctx_p, uint32_t resp_code_u, uint32_t a3, uint32_t a4, uint32_t a5);
uint32_t bpf_vm_coap_opt_finish(f12r_t *bpf, uint32_t coap_ctx_p, uint32_t flags_u, uint32_t a3, uint32_t a4, uint32_t a5);
uint32_t bpf_vm_fmt_s16_dfp(f12r_t *bpf, uint32_t out_p, uint32_t val, uint32_t fp_digits, uint32_t a4, uint32_t a5);
uint32_t bpf_vm_fmt_u32_dec(f12r_t *bpf, uint32_t out_p, uint32_t val, uint32_t a3, uint32_t a4, uint32_t a5);
uint32_t bpf_vm_coap_add_format(f12r_t *bpf, uint32_t coap_ctx_p, uint32_t format, uint32_t a3, uint32_t a4, uint32_t a5);
uint32_t bpf_vm_coap_get_pdu(f12r_t *bpf, uint32_t coap_ctx_p, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);
uint32_t bpf_vm_ztimer_now(f12r_t *bpf, uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);
uint32_t bpf_vm_ztimer_periodic_wakeup(f12r_t *bpf, uint32_t last_wakeup_p, uint32_t period, uint32_t a3, uint32_t a4, uint32_t a5);


/***AHMAD***/
/* Aux */
uint32_t bpf_vm_pointer_get_element(f12r_t *bpf, uint32_t p, uint32_t offset, uint32_t size, uint32_t a4, uint32_t a5);
uint32_t bpf_vm_pointer_get_element_pointer(f12r_t *bpf, uint32_t p, uint32_t offset, uint32_t a3, uint32_t a4, uint32_t a5);
uint32_t bpf_vm_pointer_set_element(f12r_t *bpf, uint32_t p, uint32_t offset, uint32_t value, uint32_t len, uint32_t a5);

uint32_t bpf_byteorder_ntohs(f12r_t *bpf, uint32_t bytes, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);
uint32_t bpf_byteorder_htons(f12r_t *bpf, uint32_t bytes, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);
uint32_t bpf_byteorder_ntohl(f12r_t *bpf, uint32_t bytes, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);
uint32_t bpf_byteorder_htonl(f12r_t *bpf, uint32_t bytes, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);
uint32_t bpf_trigger_hook(f12r_t *bpf, uint32_t bytes, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);

/*Memory*/

/* Event Timer */
uint32_t bpf_evtimer_add_del(f12r_t *bpf, uint32_t evtimer, uint32_t event, uint32_t type, uint32_t a4, uint32_t a5);
uint32_t bpf_evtimer_add_msg(f12r_t *bpf, uint32_t evtimer, uint32_t event, uint32_t pid, uint32_t a4, uint32_t a5);

/*GNRC*/
//pktbuf_malloc.c
uint32_t bpf_gnrc_pktbuf_start_write_malloc(f12r_t *bpf, uint32_t pkt, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);
uint32_t bpf_gnrc_pktbuf_release_malloc(f12r_t *bpf, uint32_t pkt, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);
uint32_t bpf_gnrc_pktbuf_mark_malloc(f12r_t *bpf, uint32_t pkt, uint32_t size, uint32_t type, uint32_t a4, uint32_t a5);

//pktbuf_static.c
uint32_t bpf_gnrc_pktbuf_start_write(f12r_t *bpf, uint32_t pkt, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);
uint32_t bpf_gnrc_pktbuf_release(f12r_t *bpf, uint32_t pkt, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);
uint32_t bpf_gnrc_pktbuf_mark(f12r_t *bpf, uint32_t pkt, uint32_t size, uint32_t type, uint32_t a4, uint32_t a5);
uint32_t bpf_gnrc_pktbuf_add(f12r_t *bpf, uint32_t next, uint32_t data, uint32_t size, uint32_t type, uint32_t a5);

//gnrc_pkt.c
uint32_t bpf_gnrc_pktsnip_search_type(f12r_t *bpf, uint32_t pkt, uint32_t type, uint32_t a3, uint32_t a4, uint32_t a5);

uint32_t bpf_gnrc_pktsnip_get_type(f12r_t *bpf, uint32_t pkt, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);
uint32_t bpf_gnrc_pktsnip_set_type(f12r_t *bpf, uint32_t pkt, uint32_t type, uint32_t a3, uint32_t a4, uint32_t a5);

uint32_t bpf_gnrc_pktsnip_get_next(f12r_t *bpf, uint32_t pkt, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);
uint32_t bpf_gnrc_pktsnip_set_next(f12r_t *bpf, uint32_t pkt, uint32_t next, uint32_t a3, uint32_t a4, uint32_t a5);

uint32_t bpf_gnrc_pktsnip_get_data(f12r_t *bpf, uint32_t pkt, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);
uint32_t bpf_gnrc_pktsnip_get_size(f12r_t *bpf, uint32_t pkt, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);

uint32_t bpf_gnrc_pktsnip_get_udp_hcsum(f12r_t *bpf, uint32_t udp_hdr, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);
uint32_t bpf_gnrc_pktsnip_get_udp_dst_port(f12r_t *bpf, uint32_t udp_hdr, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);
uint32_t bpf_gnrc_pktsnip_set_udp_len(f12r_t *bpf, uint32_t udp_hdr, uint32_t size, uint32_t a3, uint32_t a4, uint32_t a5);

uint32_t bpf_gnrc_get_pkt_len(f12r_t *bpf, uint32_t pkt, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);

//cross layer
uint32_t bpf_gnrc_udp_calc_csum(f12r_t *bpf, uint32_t hdr, uint32_t pseudo_hdr, uint32_t a3, uint32_t a4, uint32_t a5);

uint32_t bpf_gnrc_netapi_dispatch_send(f12r_t *bpf, uint32_t type, uint32_t demux_ctx, uint32_t pkt, uint32_t a4, uint32_t a5);
uint32_t bpf_gnrc_netapi_dispatch_receive(f12r_t *bpf, uint32_t type, uint32_t demux_ctx, uint32_t pkt, uint32_t a4, uint32_t a5);

uint32_t bpf_calc_csum(f12r_t *bpf, uint32_t hdr, uint32_t pseudo_hdr, uint32_t payload, uint32_t a4, uint32_t a5);
uint32_t bpf_gnrc_icmpv6_build(f12r_t *bpf, uint32_t next, uint32_t type, uint32_t code, uint32_t size, uint32_t a5);

// RPL
uint32_t bpf_trickle_reset_timer(f12r_t *bpf, uint32_t trickle, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);
uint32_t bpf_trickle_increment_counter(f12r_t *bpf, uint32_t trickle, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);
uint32_t bpf_trickle_start_timer(f12r_t *bpf, uint32_t pid, uint32_t trickle, uint32_t Imin, uint32_t Imax, uint32_t k);
uint32_t bpf_gnrc_rpl_get_instance_by_index(f12r_t *bpf, uint32_t index, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);
uint32_t bpf_gnrc_rpl_get_instance_by_id(f12r_t *bpf, uint32_t id, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);
//uint32_t bpf_gnrc_rpl_get_dodag_from_instance(f12r_t *bpf, uint32_t instance, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);
uint32_t bpf_gnrc_rpl_instance_add(f12r_t *bpf, uint32_t instance_id, uint32_t inst, uint32_t a3, uint32_t a4, uint32_t a5);
uint32_t bpf_gnrc_rpl_instance_remove(f12r_t *bpf, uint32_t inst, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);
uint32_t bpf_gnrc_rpl_dodag_init(f12r_t *bpf, uint32_t inst, uint32_t dodag_id, uint32_t iface, uint32_t a4, uint32_t a5);
uint32_t bpf_gnrc_rpl_parent_add_by_addr(f12r_t *bpf, uint32_t dodag, uint32_t addr, uint32_t parent, uint32_t a4, uint32_t a5);
uint32_t bpf_gnrc_rpl_parent_remove(f12r_t *bpf, uint32_t parent, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);
uint32_t bpf_gnrc_rpl_parent_update(f12r_t *bpf, uint32_t dodag, uint32_t parent, uint32_t a3, uint32_t a4, uint32_t a5);
uint32_t bpf_gnrc_rpl_local_repair(f12r_t *bpf, uint32_t dodag, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);
uint32_t bpf_gnrc_rpl_delay_dao(f12r_t *bpf, uint32_t dodag, uint32_t long_delay, uint32_t a3, uint32_t a4, uint32_t a5);
uint32_t bpf_gnrc_rpl_get_of_for_ocp(f12r_t *bpf, uint32_t ocp, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);
uint32_t bpf_gnrc_rpl_send(f12r_t *bpf, uint32_t pkt, uint32_t iface, uint32_t src, uint32_t dst, uint32_t dodag_id);
uint32_t bpf_gnrc_rpl_init(f12r_t *bpf, uint32_t pid, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);
uint32_t bpf_gnrc_rpl_is_root(f12r_t *bpf, uint32_t set, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);
uint32_t bpf_gnrc_rpl_mode(f12r_t *bpf, uint32_t set, uint32_t mode, uint32_t a3, uint32_t a4, uint32_t a5);
uint32_t bpf_gnrc_rpl_root_dodag_id(f12r_t *bpf, uint32_t set, uint32_t dodag_id, uint32_t a3, uint32_t a4, uint32_t a5);

// IPv6
uint32_t bpf_ipv6_addr_is_multicast(f12r_t *bpf, uint32_t dst, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);
uint32_t bpf_ipv6_addr_set_aiid(f12r_t *bpf, uint32_t addr, uint32_t iid, uint32_t a3, uint32_t a4, uint32_t a5);
uint32_t bpf_gnrc_ipv6_nib_pl_set(f12r_t *bpf, uint32_t iface, uint32_t pfx, uint32_t pfx_len, uint32_t valid_ltime, uint32_t pref_ltime);
uint32_t bpf_gnrc_ipv6_nib_ft_del(f12r_t *bpf, uint32_t dst, uint32_t dst_len, uint32_t a3, uint32_t a4, uint32_t a5);
uint32_t bpf_gnrc_ipv6_nib_ft_add(f12r_t *bpf, uint32_t dst, uint32_t dst_len, uint32_t next_hop, uint32_t iface, uint32_t lifetime);
uint32_t bpf_gnrc_ipv6_nib_ft_iter(f12r_t *bpf, uint32_t next_hop, uint32_t iface, uint32_t state, uint32_t fte, uint32_t a5);
uint32_t bpf_gnrc_ipv6_nib_pl_iter(f12r_t *bpf, uint32_t iface, uint32_t state, uint32_t ple, uint32_t a4, uint32_t a5);
uint32_t bpf_gnrc_sr_delete_route(f12r_t *bpf, uint32_t dst_node, uint32_t dst_size, uint32_t a3, uint32_t a4, uint32_t a5);
uint32_t bpf_gnrc_sr_add_new_dst(f12r_t *bpf, uint32_t child, uint32_t parent, uint32_t sr_iface_id, uint32_t sr_flags, uint32_t lifetime);
uint32_t bpf_gnrc_sr_initialize_table(f12r_t *bpf, uint32_t addr, uint32_t iface, uint32_t a3, uint32_t a4, uint32_t a5);
uint32_t bpf_gnrc_sr_deinitialize_table(f12r_t *bpf, uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);
uint32_t bpf_ipv6_addr_init_prefix(f12r_t *bpf, uint32_t out, uint32_t prefix, uint32_t bits, uint32_t a4, uint32_t a5);
uint32_t bpf_ipv6_addr_match_prefix(f12r_t *bpf, uint32_t a, uint32_t b, uint32_t a3, uint32_t a4, uint32_t a5);
uint32_t bpf_ipv6_addr_is_global(f12r_t *bpf, uint32_t addr, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);
uint32_t bpf_ipv6_addr_is_unspecified(f12r_t *bpf, uint32_t addr, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);
uint32_t bpf_ipv6_addr_equal(f12r_t *bpf, uint32_t addr1, uint32_t addr2, uint32_t a3, uint32_t a4, uint32_t a5);
uint32_t bpf_ipv6_nc_from_addr(f12r_t *bpf, uint32_t str, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);

// NETIF
uint32_t bpf_gnrc_netif_get_by_pid(f12r_t *bpf, uint32_t pid, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);
uint32_t bpf_gnrc_netif_get_by_prefix(f12r_t *bpf, uint32_t prefix, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);
uint32_t bpf_gnrc_netif_ipv6_addr_add_internal(f12r_t *bpf, uint32_t netif, uint32_t addr, uint32_t pfx_len, uint32_t flags, uint32_t a5);
uint32_t bpf_gnrc_netif_ipv6_get_iid(f12r_t *bpf, uint32_t netif, uint32_t iid, uint32_t a3, uint32_t a4, uint32_t a5);
uint32_t bpf_gnrc_netif_ipv6_addr_match(f12r_t *bpf, uint32_t netif, uint32_t addr, uint32_t a3, uint32_t a4, uint32_t a5);
uint32_t find_interface_with_rpl_mcast(f12r_t *bpf, uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);
uint32_t bpf_gnrc_netif_get_ipv6_addr_by_idx(f12r_t *bpf, uint32_t netif, uint32_t idx, uint32_t a3, uint32_t a4, uint32_t a5);
uint32_t bpf_gnrc_netif_get_by_ipv6_addr(f12r_t *bpf, uint32_t addr, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);
uint32_t bpf_netif_get_pid(f12r_t *bpf, uint32_t netif, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);


/***AHMAD***/
uint32_t bpf_vm_ztimer_now(f12r_t *bpf, uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);
uint32_t bpf_vm_ztimer_periodic_wakeup(f12r_t *bpf, uint32_t last_wakeup_p, uint32_t period, uint32_t a3, uint32_t a4, uint32_t a5);

#ifdef __cplusplus
}
#endif
#endif /* BPF_CALL_H */

