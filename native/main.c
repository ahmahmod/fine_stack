/*
 * Copyright (c) 2025 Ahmad Mahmod
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     FINE Stack
 * @{
 *
 * @file
 * @brief       Native RIOT Stack
 *
 * @author      Ahmad Mahmod <mahmod@unistra.fr>
 *
 * @}
 */

#include <stdio.h>

#include "fmt.h"
#include "thread.h"
#include "irq.h"
#include "net/nanocoap_sock.h"

#include "shell.h"
#include "msg.h"

#include "suit/transport/coap.h"
#ifdef MODULE_SUIT_STORAGE_FLASHWRITE
#include "riotboot/slot.h"
#endif

#include "suit/storage.h"
#include "suit/storage/ram.h"

#define COAP_INBUF_SIZE (256U)

/* Extend stacksize of nanocoap server thread */
static char _nanocoap_server_stack[2048];
#define NANOCOAP_SERVER_QUEUE_SIZE     (8)
static msg_t _nanocoap_server_msg_queue[NANOCOAP_SERVER_QUEUE_SIZE];

static void *_nanocoap_server_thread(void *arg)
{
    (void)arg;

    /* nanocoap_server uses gnrc sock which uses gnrc which needs a msg queue */
    msg_init_queue(_nanocoap_server_msg_queue, NANOCOAP_SERVER_QUEUE_SIZE);

    /* initialize nanocoap server instance */
    uint8_t buf[COAP_INBUF_SIZE];
    sock_udp_ep_t local = { .port=COAP_PORT, .family=AF_INET6 };
    nanocoap_server(&local, buf, sizeof(buf));

    return NULL;
}

#define MAIN_QUEUE_SIZE (8)
static msg_t _main_msg_queue[MAIN_QUEUE_SIZE];



int main(void)
{
    /* start suit coap updater thread */
    suit_coap_run();

    /* start nanocoap server thread */
    thread_create(_nanocoap_server_stack, sizeof(_nanocoap_server_stack),
                  THREAD_PRIORITY_MAIN - 1,
                  THREAD_CREATE_STACKTEST,
                  _nanocoap_server_thread, NULL, "nanocoap server");

    msg_init_queue(_main_msg_queue, MAIN_QUEUE_SIZE);
    
    return 0;
}
