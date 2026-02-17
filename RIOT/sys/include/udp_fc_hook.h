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


#ifndef UDP_FC_HOOK
#define UDP_FC_HOOK

#include <stdint.h>
#include "net/gnrc/pkt.h"
#include "femtocontainer/femtocontainer.h"

#ifdef __cplusplus
 extern "C" {
#endif


/**
 *  @brief  Execute the UDP packet sender application
 */
void udp_fc_send(gnrc_pktsnip_t* ctx);

/**
 *  @brief  Execute the UDP packet receiver application
 */
void udp_fc_recv(gnrc_pktsnip_t* ctx);

/*Add UDP hooks*/
/**
 *  @brief  Register the UDP send hook's application
 */
void udp_fc_send_add_hook(f12r_hook_t *hook);

/**
 *  @brief  Register the UDP receive hook's application
 */
void udp_fc_recv_add_hook(f12r_hook_t *hook);

#ifdef __cplusplus
}
#endif

#endif /* SCHED_RBPF_H */
/** @} */

