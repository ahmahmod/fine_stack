#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#include "femtocontainer/femtocontainer.h"
#include "call.h"
#include "net/gnrc.h"
#include "net/gnrc/pktbuf.h"
#include "net/gnrc/nettype.h"
#include "net/gnrc/pkt.h"
#include "net/gnrc/ipv6.h"
#include "net/gnrc/udp.h"
#include "net/gnrc/netreg.h"
#include "mbox.h"

#define ENABLE_DEBUG (1)
#include "debug.h"

static inline int _snd_rcv_mbox(mbox_t *mbox, uint16_t type, gnrc_pktsnip_t *pkt)
{
    msg_t msg;
    /* set the outgoing message's fields */
    msg.type = type;
    msg.content.ptr = (void *)pkt;
    /* send message */
    int ret = mbox_try_put(mbox, &msg);
    if (ret < 1) {
        DEBUG("gnrc_netapi: dropped message to %p (was full)\n", (void*)mbox);
    }
    return ret;
}

static int gnrc_netapi_dispatch1(gnrc_nettype_t type, uint32_t demux_ctx, uint16_t cmd, gnrc_pktsnip_t *pkt)
{
    int numof = gnrc_netreg_num(type, demux_ctx);
    //printf("numof: %d\n", numof);

    if (numof != 0) {
        gnrc_netreg_entry_t *sendto = gnrc_netreg_lookup(type, demux_ctx);

        gnrc_pktbuf_hold(pkt, numof - 1);

        while (sendto) {
#if defined(MODULE_GNRC_NETAPI_MBOX) || defined(MODULE_GNRC_NETAPI_CALLBACKS)
            uint32_t status = 0;
            switch (sendto->type) {
                case GNRC_NETREG_TYPE_DEFAULT:
                    if (_gnrc_netapi_send_recv(sendto->target.pid, pkt,
                                               cmd) < 1) {
                        /* unable to dispatch packet */
                        status = EIO;
                    }
                    break;
#ifdef MODULE_GNRC_NETAPI_MBOX
                case GNRC_NETREG_TYPE_MBOX:
                    if (_snd_rcv_mbox(sendto->target.mbox, cmd, pkt) < 1) {
                        /* unable to dispatch packet */
                        status = EIO;
                    }
                    break;
#endif
#ifdef MODULE_GNRC_NETAPI_CALLBACKS
                case GNRC_NETREG_TYPE_CB:
                    sendto->target.cbd->cb(cmd, pkt, sendto->target.cbd->ctx);
                    break;
#endif
                default:
                    /* unknown dispatch type */
                    status = ECANCELED;
                    break;
            }
            if (status != 0) {
                gnrc_pktbuf_release_error(pkt, status);
            }
#else
            if (_gnrc_netapi_send_recv(sendto->target.pid, pkt, cmd) < 1) {
                /* unable to dispatch packet */
                gnrc_pktbuf_release_error(pkt, EIO);
            }
#endif
            sendto = gnrc_netreg_getnext(sendto);
        }
    }

    return numof;
}



uint32_t bpf_gnrc_netapi_dispatch_send(f12r_t *bpf, uint32_t type, uint32_t demux_ctx, uint32_t pkt, uint32_t a4, uint32_t a5)
{
    (void)bpf;
    (void)a4;
    (void)a5;

    gnrc_pktsnip_t* pkt1 = (gnrc_pktsnip_t*)(uintptr_t)pkt;
    gnrc_nettype_t type1 = (gnrc_nettype_t)type;
    int res = gnrc_netapi_dispatch1(type1, demux_ctx, GNRC_NETAPI_MSG_TYPE_SND, pkt1);

    return  (uint32_t) res;
}

uint32_t bpf_gnrc_netapi_dispatch_receive(f12r_t *bpf, uint32_t type, uint32_t demux_ctx, uint32_t pkt, uint32_t a4, uint32_t a5)
{
    (void)bpf;
    (void)a4;
    (void)a5;

    gnrc_pktsnip_t* pkt1 = (gnrc_pktsnip_t*)(uintptr_t)pkt;
    gnrc_nettype_t type1 = (gnrc_nettype_t)type;
    int res = gnrc_netapi_dispatch1(type1, demux_ctx, GNRC_NETAPI_MSG_TYPE_RCV, pkt1);

    return  (uint32_t) res;
}

/*
static inline int gnrc_netapi_dispatch_send(gnrc_nettype_t type, uint32_t demux_ctx, gnrc_pktsnip_t *pkt)
{
    return gnrc_netapi_dispatch(type, demux_ctx, GNRC_NETAPI_MSG_TYPE_SND, pkt);
}

static inline int gnrc_netapi_dispatch_receive(gnrc_nettype_t type, uint32_t demux_ctx, gnrc_pktsnip_t *pkt)
{
    return gnrc_netapi_dispatch(type, demux_ctx, GNRC_NETAPI_MSG_TYPE_RCV, pkt);
}

static inline int gnrc_netapi_receive(kernel_pid_t pid, gnrc_pktsnip_t *pkt)
{
    return _gnrc_netapi_send_recv(pid, pkt, GNRC_NETAPI_MSG_TYPE_RCV);
}


static inline int gnrc_netapi_get(kernel_pid_t pid, netopt_t opt, uint16_t context, void *data, size_t max_len)
{
    return _gnrc_netapi_get_set(pid, opt, context, data, max_len,
                                GNRC_NETAPI_MSG_TYPE_GET);
}

static inline int gnrc_netapi_set(kernel_pid_t pid, netopt_t opt, uint16_t context, const void *data, size_t data_len)
{
    //disregard const pointer. This *should* be safe and any modification
    // * to `data` should be considered a bug
    return _gnrc_netapi_get_set(pid, opt, context, (void *)data, data_len, GNRC_NETAPI_MSG_TYPE_SET);
}
*/

