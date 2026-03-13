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
 * @brief       RPL network with CoAP SUIT update example
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

#include "net/gnrc/rpl.h"

#if USE_FC
#include "rpl_fc_hook.h"
#include "fc_array.h"

#if (USE_RPL && MODE)
#include "blob/sr_dao_recv/dao_recv.bin.h"
#include "blob/sr_dao_send/dao_send.bin.h"
#include "blob/sr_dao_send2/dao_send2.bin.h"
#include "blob/sr_root/root.bin.h"
#include "blob/dio_recv/dio_recv.bin.h"
#include "blob/dio_recv2/dio_recv2.bin.h"
#include "blob/dio_send/dio_send.bin.h"
#include "blob/dis_recv/dis_recv.bin.h"
#include "blob/dis_send/dis_send.bin.h"
#include "blob/ack_dao_recv/ack_dao_recv.bin.h"
#include "blob/ack_dao_send/ack_dao_send.bin.h"

#elif USE_RPL /* MODE */
#include "blob/dio_recv/dio_recv.bin.h"
#include "blob/dao_recv/dao_recv.bin.h"
#include "blob/dao_send/dao_send.bin.h"
#include "blob/dao_send2/dao_send2.bin.h"
#include "blob/root/root.bin.h"
#include "blob/dio_recv2/dio_recv2.bin.h"
#include "blob/dio_send/dio_send.bin.h"
#include "blob/dis_recv/dis_recv.bin.h"
#include "blob/dis_send/dis_send.bin.h"
#include "blob/ack_dao_recv/ack_dao_recv.bin.h"
#include "blob/ack_dao_send/ack_dao_send.bin.h"
#endif /* MODE */

#endif /* USE_FC */

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
// extern kernel_pid_t gnrc_rpl_pid;

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
        printf("Initializing the array with capacity %u...\n", MAX_BPF_VMS);

        if (fc_array_init(MAX_BPF_VMS) < 0) {
            printf("Failed to initialize the array.\n");
            return -1;
        }
    #endif
    #if USE_RPL
        bool install = true;
        /* ID, HOOK_TRIGGER, NEXT_VM_ID (-1 for no next), BINARY_POINTER, size of the FC, Reset the installed hooks on HOOK_TRIGGER? */
        fc_array_vm_install(0, FC_HOOK_RPL_SEND_DIS, -1, (uint8_t *) &dis_send_bin, sizeof(dis_send_bin), false, false, install);
        fc_array_vm_install(1, FC_HOOK_RPL_SEND_DIO, -1, (uint8_t *) &dio_send_bin, sizeof(dio_send_bin), false, false, install);
        fc_array_vm_install(2, FC_HOOK_RPL_SEND_DAO, -1, (uint8_t *) &dao_send2_bin, sizeof(dao_send2_bin), false, false, install);
        fc_array_vm_install(3, FC_HOOK_RPL_SEND_DAO, -1, (uint8_t *) &dao_send_bin, sizeof(dao_send_bin), false, false, install);
        fc_array_vm_install(4, FC_HOOK_RPL_SEND_DAO_ACK, -1, (uint8_t *) &ack_dao_send_bin, sizeof(ack_dao_send_bin), false, false, install);

        fc_array_vm_install(5, FC_HOOK_RPL_RECV_DIS, -1, (uint8_t *) &dis_recv_bin, sizeof(dis_recv_bin), false, false, install);
        fc_array_vm_install(7, FC_HOOK_RPL_RECV_DIO, -1, (uint8_t *) &dio_recv_bin, sizeof(dio_recv_bin), false, false, install);
        fc_array_vm_install(8, FC_HOOK_RPL_RECV_DAO, -1, (uint8_t *) &dao_recv_bin, sizeof(dao_recv_bin), false, false, install);
        fc_array_vm_install(9, FC_HOOK_RPL_RECV_DAO_ACK, -1, (uint8_t *) &ack_dao_recv_bin, sizeof(ack_dao_recv_bin), false, false, install);

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
