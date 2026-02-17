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
 * @brief       SDN network with CoAP SUIT update example
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
#include "net/gnrc/ipv6.h"

#if USE_FC
#include "fc_array.h"
#endif

#define COAP_INBUF_SIZE (256U)
#define NUM_VF_POOL (2U)

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
extern kernel_pid_t gnrc_rpl_pid;

int main(void)
{

    #ifdef MODULE_SUIT_STORAGE_FLASHWRITE
        cmd_print_current_slot(0, NULL);
        cmd_print_riotboot_hdr(0, NULL);
    #endif
        /* start suit coap updater thread */
    suit_coap_run();

    #if USE_FC
        /* for the thread running the shell */
        printf("Initializing the array with capacity %u...\n", NUM_VF_POOL);

        if (fc_array_init(NUM_VF_POOL) < 0) {
            printf("Failed to initialize the array.\n");
            return -1;
        }
        check_hook();
    #endif

    /* start nanocoap server thread */
    thread_create(_nanocoap_server_stack, sizeof(_nanocoap_server_stack),
                  THREAD_PRIORITY_MAIN - 1,
                  THREAD_CREATE_STACKTEST,
                  _nanocoap_server_thread, NULL, "nanocoap server");
              

    msg_init_queue(_main_msg_queue, MAIN_QUEUE_SIZE);
    
    return 0;
}
