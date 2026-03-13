/*
 * Copyright (C) 2024 Ahmad Mahmod <mahmod@unistra.fr>
 *
 */

/**
 * @defgroup    FCs hook for handiling UDP packets
 * @ingroup     sys
 * @brief       Provides hooking for FCs in the system for UDP
 *
 * The lib aims to enable the installation and initilization of the UDP send and recv hooks using FCs.
 *
 * @{
 *
 * @file
 * @brief       Femto Containers (FCs) hooking for UDP
 *
 * @author      Ahmad Mahmod <mahmod@unistra.fr>
 */


#ifndef RPL_FC_HOOK
#define RPL_FC_HOOK

#define USE_COMMON_RAM (0)

#include <stdint.h>
#include "femtocontainer/femtocontainer.h"
#include "net/gnrc/rpl.h"
#ifdef __cplusplus
 extern "C" {
#endif

typedef struct {
    gnrc_rpl_dis_t *dis; /* ptr to the DIS message */
    ipv6_hdr_t *src; /* ptr to src address */
    ipv6_hdr_t *dst; /* ptr to dst address */
    int16_t iface; /* iface number */
    uint16_t len;
} dis_rev_context_t;

typedef struct {
    void *dio; /* ptr to the DIO message */
    void *src; /* ptr to src address */
    void *dst; /* ptr to dst address */
    void *parent;
    void *inst;
    int16_t iface; /* iface number */
    int16_t gnrc_rpl_pid; /* rpl number */
    uint16_t len;
    int8_t ctx_res;
} dio_recv_context_t;

typedef struct {
    gnrc_rpl_dao_t * dao; /* ptr to the DAO message */
    ipv6_hdr_t * src; /* ptr to src address */
    ipv6_hdr_t * dst; /* ptr to dst address */
    int16_t iface; /* iface number */
    uint16_t len;
} dao_recv_context_t;

typedef struct {
    gnrc_rpl_instance_t *inst; /* ptr to the instance message */
    ipv6_addr_t *destination; /* ptr to destanation address */
    gnrc_ipv6_nib_ft_t *fte;
    gnrc_pktsnip_t *pkt;
    evtimer_msg_t *gnrc_rpl_evtimer;
    kernel_pid_t gnrc_pid;
    uint8_t lifetime;   /* liftime in seconds */
} dao_send_context_t;

typedef struct {
    gnrc_netif_t *netif;   /* ptr to netif to build RPL instance on */
    ipv6_addr_t *dodag_id;   /* ptr to dodag address */
    void (*rpl_trickle_send_dio_func_ptr)(void *); 
    kernel_pid_t netif_pid;
} root_init_context_t;

typedef struct {
    uintptr_t inst; /* ptr to the instance */
    uintptr_t destination; /* ptr to dst address */
    uintptr_t options; /* double-ptr to options */
    uint32_t num_opts; /* number of options */
} send_dis_context_t;

typedef struct {
    uintptr_t inst; /* ptr to the instance message */
    uintptr_t destination; /* ptr to destanation address */
} dio_send_context_t;


/**
 *  @brief  Execute a hook on event trigger
 */
uint32_t rpl_fc_execute_hook(void *ctx, uint32_t size, f12r_hook_trigger_t trigger);

/**
 *  @brief  Register a hook to a specific trigger
 */
void rpl_fc_add_hook(f12r_hook_t *hook, f12r_hook_trigger_t trigger, bool reset);

#ifdef __cplusplus
}
#endif

#endif /* SCHED_RBPF_H */
/** @} */

