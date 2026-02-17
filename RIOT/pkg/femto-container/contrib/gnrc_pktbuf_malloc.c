#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#include "femtocontainer/femtocontainer.h"

#include "call.h"
#include "net/gnrc.h"
#include "net/gnrc/pktbuf.h"
#include "net/gnrc/nettype.h"
#include "net/gnrc/pkt.h"

#define ENABLE_DEBUG (1)
#include "debug.h"


uint32_t bpf_gnrc_pktbuf_release_malloc(f12r_t *bpf, uint32_t pkt, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5)
{
    (void)bpf;
    (void)a2;
    (void)a3;
    (void)a4;
    (void)a5;
    gnrc_pktsnip_t* pkt1 = (gnrc_pktsnip_t*)(uintptr_t)pkt;
    
    gnrc_pktbuf_release(pkt1);
    
    return 1;
}

uint32_t bpf_gnrc_pktbuf_start_write_malloc(f12r_t *bpf, uint32_t pkt, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5)
{
    (void)bpf;
    (void)a2;
    (void)a3;
    (void)a4;
    (void)a5;

    gnrc_pktsnip_t* pkt1 = (gnrc_pktsnip_t*)(uintptr_t)pkt;
    pkt1 = gnrc_pktbuf_start_write(pkt1);
    return (uintptr_t) pkt1;
}

uint32_t bpf_gnrc_pktbuf_mark_malloc(f12r_t *bpf, uint32_t pkt, uint32_t size, uint32_t type, uint32_t a4, uint32_t a5)
{
    (void)bpf;
    (void)a4;
    (void)a5;

    //printf("OK\n");
    gnrc_pktsnip_t* pkt1 = (gnrc_pktsnip_t*)(uintptr_t)pkt;
    gnrc_pktsnip_t *new;

    //mutex_lock(&_mutex);
    new = gnrc_pktbuf_mark(pkt1, size, type);
    //mutex_unlock(&_mutex);
    
    return (uintptr_t) new;
}