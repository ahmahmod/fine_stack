/*
 * Copyright (C) 2021 Inria
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     sys
 * @{
 *
 * @file
 * @brief       Scheduler rf12r hook implementation
 *
 * @author      Koen Zandberg <koen@bergzand.net>
 *
 * @}
 */

#include <stdio.h>

#include "irq.h"
#include "udp_fc_hook.h"
#include "femtocontainer/femtocontainer.h"


void udp_fc_send(gnrc_pktsnip_t* ctx)
{
    int64_t res;
    f12r_hook_execute(FC_HOOK_UDP_SEND, ctx, sizeof(*ctx), &res);
    printf("SEND  RES: %lld\n",res);
    //(void)res;
}

void udp_fc_recv(gnrc_pktsnip_t* ctx)
{
    int64_t res;
    f12r_hook_execute(FC_HOOK_UDP_RECV, ctx, sizeof(*ctx), &res);
    printf("RECV RES: %lld\n",res);
    //(void)res;
}

void udp_fc_send_add_hook(f12r_hook_t *hook)
{
    unsigned state = irq_disable();
    uint8_t _stack1[512] = { 0 };
    hook->application->stack = _stack1;
    hook->application->stack_size = sizeof(_stack1);
    f12r_setup(hook->application);
    f12r_hook_install(hook, FC_HOOK_UDP_SEND, 1);

    irq_restore(state);
}

void udp_fc_recv_add_hook(f12r_hook_t *hook)
{
    unsigned state = irq_disable();
    uint8_t _stack2[512] = { 0 };
    hook->application->stack = _stack2;
    hook->application->stack_size = sizeof(_stack2);
    f12r_setup(hook->application);
    f12r_hook_install(hook, FC_HOOK_UDP_RECV, 1);

    irq_restore(state);
}
