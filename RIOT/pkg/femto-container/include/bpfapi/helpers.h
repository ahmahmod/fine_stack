/*
 * Copyright (C) 2020 Inria
 * Copyright (C) 2020 Koen Zandberg <koen@bergzand.net>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef BPF_BPFAPI_HELPERS_H
#define BPF_BPFAPI_HELPERS_H

#include <stdint.h>
#include "shared.h"
//#include "phydat.h"
//#include "trickle.h"

#ifdef __cplusplus
extern "C" {
#endif


//typedef signed ssize_t;

/**
 * Opaque dummy type saul registration
 */
typedef void bpf_saul_reg_t;

static void *(*f12r_vm_printf)(const char *fmt, ...) = (void *) BPF_FUNC_BPF_PRINTF;

/* STDLIB */
static int (*f12r_store_global)(uint32_t key, uint32_t  *value) = (void *) BPF_FUNC_BPF_STORE_GLOBAL;
static int (*f12r_store_local)(uint32_t key, uint32_t  *value) = (void *) BPF_FUNC_BPF_STORE_LOCAL;
static int (*f12r_fetch_global)(uint32_t key, uint32_t  *value) = (void *) BPF_FUNC_BPF_FETCH_GLOBAL;
static int (*f12r_fetch_local)(uint32_t key, uint32_t  *value) = (void *) BPF_FUNC_BPF_FETCH_LOCAL;
static uint32_t (*bpf_now_ms)(void) = (void *) BPF_FUNC_BPF_NOW_MS;

/* STDLIB */
static void *(*f12r_memcpy)(void *dest, const void *src, size_t n) = (void *) BPF_FUNC_BPF_MEMCPY;
static int (*f12r_memcmp)(void *dest, const void *src, size_t n) = (void *) BPF_FUNC_BPF_MEMCMP;
static int (*f12r_memset)(void *dest, uint32_t value, size_t n) = (void *) BPF_FUNC_BPF_MEMSET;

/*By Ahmad*/
static void *(*f12r_vm_malloc)(size_t n) = (void *) BPF_FUNC_BPF_MALLOC;
static int (*f12r_vm_free)(void *ptr) = (void *) BPF_FUNC_BPF_FREE;

static uint32_t (*bpf_vm_pointer_get_element)(uint8_t* p, uint32_t offset, uint32_t size) = (void *) BPF_FUNC_BPF_POINTER_GET_ELEMENT;
static void *(*bpf_vm_pointer_get_element_pointer)(uint8_t* p, uint32_t offset) = (void *) BPF_FUNC_BPF_POINTER_ELEMENT_POINTER;
static void (*bpf_vm_pointer_set_element)(uint8_t* p, uint32_t offset, uint32_t value, uint32_t len) = (void *) BPF_FUNC_BPF_POINTER_SET_ELEMENT;
static void (*bpf_trickle_reset_timer)(uintptr_t trickle) = (void *) BPF_FUNC_BPF_TRICKLE_RESET_TIMER;
static void (*bpf_trickle_increment_counter)(uintptr_t trickle) = (void *) BPF_FUNC_BPF_TRICKLE_INCRE_TIMER;
static void (*bpf_trickle_start_timer)(int16_t pid, uintptr_t trickle, uint32_t Imin, uint8_t Imax, uint8_t k) = (void *) BPF_FUNC_BPF_TRICKLE_START_TIMER;

static uint16_t (*bpf_byteorder_ntohs)(uint16_t bytes) = (void *) BPF_FUNC_BPF_BYTEORDER_NTOHS;
static uint16_t (*bpf_byteorder_htons)(uint16_t bytes) = (void *) BPF_FUNC_BPF_BYTEORDER_HTONS;
static uint32_t (*bpf_byteorder_ntohl)(uint32_t bytes) = (void *) BPF_FUNC_BPF_BYTEORDER_NTOHL;
static uint32_t (*bpf_byteorder_htonl)(uint32_t bytes) = (void *) BPF_FUNC_BPF_BYTEORDER_HTONL;

static int32_t (*bpf_trigger_hook)(uint32_t hook_trigger, uintptr_t ctx, uint32_t size_ctx) = (void *) BPF_FUNC_BPF_TRIGGER_HOOK;

/* Event Timer */
static void (*bpf_evtimer_add_del)(void *evtimer, void *evtimer_event, uint32_t type) = (void *) BPF_FUNC_BPF_EVTIMER_ADD_DEL;
static void (*bpf_evtimer_add_msg)(void *evtimer, void *evtimer_event, int16_t pid)= (void *) BPF_FUNC_BPF_EVTIMER_ADD_MSG;


/* ZTIMER calls */
static uint32_t (*bpf_ztimer_now)(void) = (void *) BPF_FUNC_BPF_ZTIMER_NOW;
static void (*bpf_ztimer_periodic_wakeup)(uint32_t *last_wakeup, uint32_t period) = (void *) BPF_FUNC_BPF_ZTIMER_PERIODIC_WAKEUP;

#ifdef __cplusplus

}
#endif
#endif /* BPF_APPLICATION_CALL_H */
