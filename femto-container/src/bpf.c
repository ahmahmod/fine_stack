/*
 * Copyright (C) 2020 Inria
 * Copyright (C) 2020 Koen Zandberg <koen@bergzand.net>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include "assert.h"

#include "femtocontainer/femtocontainer.h"
#include "femtocontainer/instruction.h"
#include "femtocontainer/config.h"
#include "mutex.h"

#define ENABLE_DEBUG 1

static bool installing_hook = false;

extern int f12r_run(f12r_t *femtoc, const void *ctx, int64_t *result);

static f12r_hook_t *_hooks[FC_HOOK_NUM] = { 0 };

static bool _continue(f12r_hook_t *hook, int64_t *res)
{
    switch(hook->policy) {
        case FC_POLICY_CONTINUE:
            return true;
        case FC_POLICY_SINGLE:
            return false;
        case FC_POLICY_ABORT_ON_NEGATIVE:
            return (*res < 0) ? false : true;
        case FC_POLICY_ABORT_ON_POSITIVE:
            return (*res > 0) ? false : true;
    }
    return true;
}

static int _execute(f12r_t *femtoc, void *ctx, int64_t *result)
{
    assert(femtoc->flags & FC_FLAG_SETUP_DONE);
    return f12r_run(femtoc, ctx, result);
}

int f12r_execute(f12r_t *femtoc, void *ctx, size_t ctx_len, int64_t *result)
{
    (void)ctx;
    (void)ctx_len;
    femtoc->arg_region.start = NULL;
    femtoc->arg_region.len = 0;

    return _execute(femtoc, ctx, result);
}

int f12r_execute_ctx(f12r_t *femtoc, void *ctx, size_t ctx_len, int64_t *result)
{
    femtoc->arg_region.start = ctx;
    femtoc->arg_region.len = ctx_len;
    femtoc->arg_region.flag = (FC_MEM_REGION_READ | FC_MEM_REGION_WRITE);

    return _execute(femtoc, ctx, result);
}

void f12r_setup(f12r_t *femtoc)
{
    femtoc->stack_region.start = femtoc->stack;
    femtoc->stack_region.len = femtoc->stack_size;
    femtoc->stack_region.flag = (FC_MEM_REGION_READ | FC_MEM_REGION_WRITE);
    femtoc->stack_region.next = &femtoc->data_region;

    femtoc->data_region.start = f12r_data(femtoc);
    femtoc->data_region.len = f12r_header(femtoc)->data_len;
    femtoc->data_region.flag = (FC_MEM_REGION_READ | FC_MEM_REGION_WRITE);
    femtoc->data_region.next = &femtoc->rodata_region;

    femtoc->rodata_region.start = f12r_rodata(femtoc);
    femtoc->rodata_region.len = f12r_header(femtoc)->rodata_len;
    femtoc->rodata_region.flag = FC_MEM_REGION_READ;
    femtoc->rodata_region.next = &femtoc->arg_region;

    femtoc->arg_region.next = NULL;
    femtoc->arg_region.start = NULL;
    femtoc->arg_region.len = 0;

    femtoc->flags |= FC_FLAG_SETUP_DONE;
}

void f12r_add_region(f12r_t *femtoc, f12r_mem_region_t *region,
                    void *start, size_t len, uint8_t flags)
{
    region->next = femtoc->arg_region.next;
    region->start = start;
    region->len = len;
    region->flag = flags;
    femtoc->arg_region.next = region;
}

// Added by Ahmad
void check_hook(void){
    
    for (int i = 0; i < FC_HOOK_NUM; i++) {
        if (_hooks[i] != NULL) {
            printf("Hook at trigger %d:\n", i);
            for (f12r_hook_t *hook = _hooks[i]; hook != NULL; hook = hook->next) {
                printf("  - Hook with application pointer: %p\n", (void*)hook->application);
                #ifdef BOARD_NATIVE
                    printf("  - Executions count: %u\n", hook->executions);
                #else
                    printf("  - Executions count: %lu\n", hook->executions);
                #endif
            }
        } else {
            printf("No hook installed at trigger %d\n", i);
        }
    }
}


static void _register(f12r_hook_t **install_hook, f12r_hook_t *new, uint32_t reset)
{
    /*
    Install the new hook in front of the old hook, make the old hook as next to the new hook.
    the new hook may have next called hooks, we make a while loop to append the old hook to the end of the new hook chain
    */
    if (reset){
        *install_hook = new;
    }

    else {
        f12r_hook_t *h = new;
        while (h->next != NULL) {
            h = h->next;
        }
        h->next = *install_hook;
        //}
        //new->next = *install_hook;

        *install_hook = new;
    }   
}

int f12r_hook_install(f12r_hook_t *hook, f12r_hook_trigger_t trigger, uint32_t reset) {
    installing_hook = true;
    assert(trigger < FC_HOOK_NUM);
    _register(&_hooks[trigger], hook, reset);
    installing_hook = false;
    return 0;
}

int f12r_hook_uninstall(f12r_hook_t *hook, f12r_hook_trigger_t trigger) {
    f12r_hook_t *h = _hooks[trigger];

    /*Check if it's the first*/
    if (h == hook){
        _hooks[trigger] = h->next;
        return 0;
    }

    while (h->next != hook){
        h = h->next;
    }
    h->next = h->next->next;
    
    return 0;
}

int f12r_check_hook(f12r_hook_trigger_t trigger){
    if (_hooks[trigger] != NULL){
        return 1;
    }
    else {
        return 0;
    }
}


int f12r_hook_execute(f12r_hook_trigger_t trigger, void *ctx, size_t ctx_size, int64_t *script_res)
{
    if (installing_hook) {
        return -1;  // Or delay, or spin, or skip
    }

    assert(trigger < FC_HOOK_NUM);
    int res = FC_OK;
    for (f12r_hook_t *h = _hooks[trigger]; h; h = h->next) {
        
        if (h != NULL){
            if(ENABLE_DEBUG){
                printf("Start hook: %d\n", trigger);
            }
            res = f12r_execute_ctx(h->application, ctx, ctx_size, script_res);

            if(ENABLE_DEBUG){
                printf("Hook: %d - res: %d - exe res: %d\n", trigger, res, (int)*script_res);
            }
            h->executions++;

            if ((res == FC_OK) && !_continue(h, script_res)) {
                break;
            }
        }   
    }

    return res;
}