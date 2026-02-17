#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include "femtocontainer/femtocontainer.h"
#include "call.h"
#include "net/gnrc.h"
#include "net/gnrc/pktbuf.h"
#include "net/gnrc/nettype.h"
#include "net/gnrc/pkt.h"
#include "net/gnrc/udp.h"

#define ENABLE_DEBUG (1)
#include "debug.h"


uint32_t bpf_gnrc_pktsnip_search_type(f12r_t *bpf, uint32_t pkt, uint32_t type, uint32_t a3, uint32_t a4, uint32_t a5)
{
    (void)bpf;
    (void)a3;
    (void)a4;
    (void)a5;

    gnrc_nettype_t type1 = (gnrc_nettype_t) type;
    gnrc_pktsnip_t* pkt1 = (gnrc_pktsnip_t*)(uintptr_t)pkt;
    while ((pkt1 != NULL) && (pkt1->type != type1)) {
        pkt1 = pkt1->next;
    }
    return (uintptr_t) pkt1;
}

uint32_t bpf_gnrc_pktsnip_get_type(f12r_t *bpf, uint32_t pkt, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5)
{
    (void)bpf;
    (void)a2;
    (void)a3;
    (void)a4;
    (void)a5;

    gnrc_pktsnip_t* pkt1 = (gnrc_pktsnip_t*)(uintptr_t)pkt;
    //printf("Pkt Type from gnrc_pkt.c: %d", pkt1->type);

    return (uint32_t) pkt1->type;
}

uint32_t bpf_gnrc_pktsnip_set_type(f12r_t *bpf, uint32_t pkt, uint32_t type, uint32_t a3, uint32_t a4, uint32_t a5)
{
    (void)bpf;
    (void)a3;
    (void)a4;
    (void)a5;

    gnrc_pktsnip_t *pkt1 = (gnrc_pktsnip_t*)(uintptr_t)pkt;
    gnrc_nettype_t type1 = (gnrc_nettype_t)type;
    pkt1->type = type1;

    return (uint32_t) pkt1->type;
}

uint32_t bpf_gnrc_pktsnip_get_size(f12r_t *bpf, uint32_t pkt, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5)
{
    (void)bpf;
    (void)a2;
    (void)a3;
    (void)a4;
    (void)a5;

    gnrc_pktsnip_t* pkt1 = (gnrc_pktsnip_t*)(uintptr_t)pkt;

    return (uint32_t) pkt1->size;
}

uint32_t bpf_gnrc_pktsnip_get_next(f12r_t *bpf, uint32_t pkt, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5)
{
    (void)bpf;
    (void)a2;
    (void)a3;
    (void)a4;
    (void)a5;

    gnrc_pktsnip_t* pkt1 = (gnrc_pktsnip_t*)(uintptr_t)pkt;
    
    return (uintptr_t) pkt1->next;
}

uint32_t bpf_gnrc_pktsnip_set_next(f12r_t *bpf, uint32_t pkt, uint32_t next, uint32_t a3, uint32_t a4, uint32_t a5)
{
    (void)bpf;
    (void)a3;
    (void)a4;
    (void)a5;

    gnrc_pktsnip_t* pkt1 = (gnrc_pktsnip_t*)(uintptr_t)pkt;
    gnrc_pktsnip_t* next1 = (gnrc_pktsnip_t*)(uintptr_t)next;
    pkt1->next = next1;

    return (uint32_t) pkt1->next;
}


uint32_t bpf_gnrc_pktsnip_get_data(f12r_t *bpf, uint32_t pkt, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5)
{
    (void)bpf;
    (void)a2;
    (void)a3;
    (void)a4;
    (void)a5;

    gnrc_pktsnip_t* pkt1 = (gnrc_pktsnip_t*)(uintptr_t)pkt;
    //printf("%p\n", (void *)pkt1->data );
    
    return (uintptr_t) pkt1->data;
}

uint32_t bpf_gnrc_pktsnip_get_udp_hcsum(f12r_t *bpf, uint32_t udp_hdr, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5)
{
    (void)bpf;
    (void)a2;
    (void)a3;
    (void)a4;
    (void)a5;

    udp_hdr_t* hdr = (udp_hdr_t*)(uintptr_t) udp_hdr;

    
    return (uint32_t) byteorder_ntohs(hdr->checksum) ;
}

uint32_t bpf_gnrc_pktsnip_get_udp_dst_port(f12r_t *bpf, uint32_t udp_hdr, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5)
{
    (void)bpf;
    (void)a2;
    (void)a3;
    (void)a4;
    (void)a5;

    udp_hdr_t* hdr = (udp_hdr_t*)(uintptr_t) udp_hdr;

    return (uint32_t) byteorder_ntohs(hdr->dst_port);
}



uint32_t bpf_gnrc_pktsnip_set_udp_len(f12r_t *bpf, uint32_t udp_hdr, uint32_t size, uint32_t a3, uint32_t a4, uint32_t a5)
{
    (void)bpf;
    (void)a3;
    (void)a4;
    (void)a5;

    udp_hdr_t* hdr = (udp_hdr_t*)(uintptr_t) udp_hdr;
    hdr->length = byteorder_htons(size);

    
    return (uint32_t) 1;
}


static inline uint32_t _pkt_len(const gnrc_pktsnip_t *pkt)
{
    uint32_t len = 0;

    while (pkt != NULL) {
        len += pkt->size;
        pkt = pkt->next;
    }
    
    return len;
}

uint32_t bpf_gnrc_get_pkt_len(f12r_t *bpf, uint32_t pkt, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5)
{
    (void)bpf;
    (void)a2;
    (void)a3;
    (void)a4;
    (void)a5;

    gnrc_pktsnip_t* pkt1 = (gnrc_pktsnip_t*)(uintptr_t)pkt;
        
    return _pkt_len(pkt1);
}
