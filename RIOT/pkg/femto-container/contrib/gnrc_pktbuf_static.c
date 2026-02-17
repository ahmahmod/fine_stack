#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>

#include "femtocontainer/femtocontainer.h"

#include "mutex.h"
#include "od.h"
#include "utlist.h"
#include "net/gnrc/pktbuf.h"
#include "net/gnrc/nettype.h"
#include "net/gnrc/pkt.h"
//#include "tx_sync.h"


uint32_t bpf_gnrc_pktbuf_release(f12r_t *bpf, uint32_t pkt, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5)
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

uint32_t bpf_gnrc_pktbuf_start_write(f12r_t *bpf, uint32_t pkt, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5)
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



uint32_t bpf_gnrc_pktbuf_mark(f12r_t *bpf, uint32_t pkt, uint32_t size, uint32_t type, uint32_t a4, uint32_t a5)
{
    (void)bpf;
    (void)a4;
    (void)a5;

    
    gnrc_pktsnip_t* pkt1 = (gnrc_pktsnip_t*)(uintptr_t)pkt;
    size_t size1 = (size_t)size;
    gnrc_nettype_t type1 = (gnrc_nettype_t) type;
    
    return (uintptr_t) gnrc_pktbuf_mark(pkt1, size1, type1);
}

uint32_t bpf_gnrc_pktbuf_add(f12r_t *bpf, uint32_t next, uint32_t data, uint32_t size, uint32_t type, uint32_t a5)
{
    (void)bpf;
    (void)a5;

    
    gnrc_pktsnip_t* next1 = (gnrc_pktsnip_t*)(uintptr_t)next;
    void *data1 = (void *) data;
    size_t size1 = (size_t)size;
    gnrc_nettype_t type1 = (gnrc_nettype_t) type;

    //gnrc_pktbuf_add(next1, data1, size1, type1);

    return (uintptr_t) gnrc_pktbuf_add(next1, data1, size1, type1);
}