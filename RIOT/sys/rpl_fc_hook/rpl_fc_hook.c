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
#include "rpl_fc_hook.h"
#include "femtocontainer/femtocontainer.h"


uint32_t rpl_fc_execute_hook(void *ctx, uint32_t size, f12r_hook_trigger_t trigger)
{
    int64_t res;
    f12r_hook_execute(trigger, ctx, size, &res);
    //printf("Hook (%d) execution RES: %lld\n",res);
    return (uint32_t) res;
}

/* Assign every hook a dedicatde RAM memory (512 Bytes)*/
void rpl_fc_add_hook(f12r_hook_t *hook, f12r_hook_trigger_t trigger, bool reset)
{
    unsigned state = irq_disable();
    
#if USE_COMMON_RAM
    static uint8_t _stack1[512] = { 0 };
    hook->application->stack = _stack1;
    hook->application->stack_size = sizeof(_stack1);
#else
    hook->application->stack = malloc(FC_STACK_SIZE);
    hook->application->stack_size = FC_STACK_SIZE;
#endif

    f12r_setup(hook->application);
    f12r_hook_install(hook, trigger, reset);

    irq_restore(state);
}

// /* Assign all the hooks the same RAM memory (512 Bytes)*/
// void rpl_fc_add_hook(f12r_hook_t *hook, f12r_hook_trigger_t trigger, bool reset)
// {
//     unsigned state = irq_disable();

//     f12r_setup(hook->application);
//     f12r_hook_install(hook, trigger, reset);

//     irq_restore(state);
// }
