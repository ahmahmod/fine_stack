/*
 * Copyright (C) 2015 Cenk Gündoğan <cnkgndgn@gmail.com>
 * Copyright (C) 2018 Freie Universität Berlin
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @{
 *
 * @file
 * @author Cenk Gündoğan <cnkgndgn@gmail.com>
 * @author Martine Lenders <m.lenders@fu-berlin.de>
 */

#include <assert.h>
#include <string.h>
#include "net/gnrc/netif/internal.h"
#include "net/gnrc/ipv6/ext/rh.h"
#include "srh.h"
//#include "net/gnrc/rpl/sr_table.h"
#include "net/gnrc/pktbuf.h"
#include "net/gnrc/pkt.h"

#define ENABLE_DEBUG      1
#include "debug.h"

#define GNRC_RPL_SRH_PADDING(X)     ((X & 0xF0) >> 4)
#define GNRC_RPL_SRH_COMPRE(X)      (X & 0x0F)
#define GNRC_RPL_SRH_COMPRI(X)      ((X & 0xF0) >> 4)

#define MIN(X,Y) (((X)<(Y))?(X):(Y))

static char addr_str[IPV6_ADDR_MAX_STR_LEN];

/* checks if multiple addresses within the source routing header exist on my
 * interfaces */
static void *_contains_multiple_of_my_addr(const ipv6_addr_t *dst,
                                           const gnrc_rpl_srh_t *rh,
                                           unsigned num_addr,
                                           unsigned compri_addr_len)
{
    ipv6_addr_t addr;
    uint8_t *addr_vec = (uint8_t *) (rh + 1);
    bool found = false;
    uint8_t pref_elided = GNRC_RPL_SRH_COMPRI(rh->compr);
    uint8_t addr_len = compri_addr_len;
    uint8_t found_pos = 0;

    memcpy(&addr, dst, pref_elided);
    for (unsigned i = 0; i < num_addr; i++) {
        uint8_t *addr_vec_ptr = &addr_vec[i * compri_addr_len];

        if (i == num_addr - 1) {
            pref_elided = GNRC_RPL_SRH_COMPRE(rh->compr);
            addr_len = sizeof(ipv6_addr_t) - pref_elided;
        }
        memcpy(&addr.u8[pref_elided], addr_vec_ptr, addr_len);
        if (gnrc_netif_get_by_ipv6_addr(&addr) != NULL) {
            if (found && ((i - found_pos) > 1)) {
                DEBUG("RPL SRH: found multiple addresses that belong to me - "
                      "discard\n");
                return addr_vec_ptr;
            }
            found_pos = i;
            found = true;
        }
    }
    return NULL;
}

int ex_gnrc_rpl_srh_process(ipv6_hdr_t *ipv6, gnrc_rpl_srh_t *rh, void **err_ptr)
{
    ipv6_addr_t addr;
    uint8_t *addr_vec = (uint8_t *) (rh + 1), *current_address;
    uint8_t num_addr;
    uint8_t current_pos, pref_elided, addr_len, compri_addr_len;
    const uint8_t new_seg_left = rh->seg_left - 1;

    DEBUG("RPL SRH: Segment left: %d\n", new_seg_left);

    //assert(rh->seg_left > 0);
    if (new_seg_left == 0){
        return GNRC_IPV6_EXT_RH_AT_DST;
    }
    num_addr = (((rh->len * 8) - GNRC_RPL_SRH_PADDING(rh->pad_resv) -
                (16 - GNRC_RPL_SRH_COMPRE(rh->compr))) /
                (16 - GNRC_RPL_SRH_COMPRI(rh->compr))) + 1;

    DEBUG("RPL SRH: %u addresses in the routing header\n", (unsigned) num_addr);

    if (rh->seg_left > num_addr) {
        DEBUG("RPL SRH: number of segments left > number of addresses - "
              "discard\n");
        *err_ptr = &rh->seg_left;
        return GNRC_IPV6_EXT_RH_ERROR;
    }

    current_pos = num_addr - new_seg_left;
    pref_elided = (new_seg_left)
                ? GNRC_RPL_SRH_COMPRI(rh->compr)
                : GNRC_RPL_SRH_COMPRE(rh->compr);
    compri_addr_len = sizeof(ipv6_addr_t) - GNRC_RPL_SRH_COMPRI(rh->compr);
    addr_len = sizeof(ipv6_addr_t) - pref_elided;
    memcpy(&addr, &ipv6->dst, pref_elided);
    current_address = &addr_vec[(current_pos - 1) * compri_addr_len];
    memcpy(&addr.u8[pref_elided], current_address, addr_len);

    if (ipv6_addr_is_multicast(&ipv6->dst)) {
        DEBUG("RPL SRH: found a multicast destination address - discard\n");
        return GNRC_IPV6_EXT_RH_ERROR;
    }
    if (ipv6_addr_is_multicast(&addr)) {
        DEBUG("RPL SRH: found a multicast address in next address - discard\n");
        return GNRC_IPV6_EXT_RH_ERROR;
    }

    /* check if multiple addresses of my interface exist */
    if ((*err_ptr = _contains_multiple_of_my_addr(&ipv6->dst, rh, num_addr,
                                                  compri_addr_len))) {
        return GNRC_IPV6_EXT_RH_ERROR;
    }
    rh->seg_left = new_seg_left;
    memcpy(current_address, &ipv6->dst.u8[pref_elided], addr_len);

    DEBUG("RPL SRH: Next hop: %s at position %d\n",
          ipv6_addr_to_str(addr_str, &addr, sizeof(addr_str)), current_pos);

    memcpy(&ipv6->dst, &addr, sizeof(ipv6->dst));

    return GNRC_IPV6_EXT_RH_FORWARDED;
}




/******************************************************************************* */
// Mock function for getting the route
#define GNRC_SR_MAX_ROUTE_SIZE (10)
int ex_gnrc_sr_get_full_route(const ipv6_addr_t *dest_addr, ipv6_addr_t *route_buffer, size_t *route_length) {
    (void) dest_addr; 
    // Mock a route
    *route_length = 3;  // Example route length
    route_buffer[2] = (ipv6_addr_t){.u8 = {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                           0x22, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0xAA}};
                                           
    route_buffer[1] = (ipv6_addr_t){.u8 = {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                           0x11, 0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBB}};

    route_buffer[0] = (ipv6_addr_t){.u8 = {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                           0x33, 0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0xCC}};

    printf("Route reconstructed: ");
    for (size_t i = 0; i < *route_length; ++i) {
        printf("%s -> ",
               ipv6_addr_to_str(addr_str, (ipv6_addr_t *)&route_buffer[i],
                                sizeof(addr_str)));
    }
    printf("\n");
    //route_buffer[0] = *dest_addr;
    return 0;
}

static uint8_t _ipv6_addr_matching_bytes(const ipv6_addr_t *a, const ipv6_addr_t *b)
{
    if ((a == NULL) || (b == NULL)) {
        return 0;
    }

    if (a == b) {
        return 16;
    }

    for(size_t i = 0; i < sizeof(ipv6_addr_t); i++) {
        if(((uint8_t *)a)[i] != ((uint8_t *)b)[i]) {
        return i;
        }
    }
  return 16;
}

static uint8_t _get_compri(ipv6_addr_t *route_buffer, size_t route_length, ipv6_addr_t *dest_addr){
    uint8_t compri=15;
    for (uint8_t i=0; i<route_length; i++){
        compri = MIN(compri, _ipv6_addr_matching_bytes(&route_buffer[i], dest_addr));   
    }

    return compri;
}


//gnrc_pktsnip_t *gnrc_rpl_srh_insert(gnrc_pktsnip_t *ipv6, uint8_t nh, ipv6_addr_t *dest_addr)
gnrc_pktsnip_t *ex_gnrc_rpl_srh_insert(gnrc_pktsnip_t *pkt, ipv6_hdr_t *ipv6_hdr)
{    
    if (pkt == NULL || ipv6_hdr == NULL) {
        printf("RPL SRH: Unvalid Parameters\n");
        return NULL;
    }
    gnrc_pktsnip_t *srh_snip, *ipv6;
    gnrc_rpl_srh_t *srh;
    ipv6_addr_t *dest_addr = &ipv6_hdr->dst;
    ipv6_hdr_t *hdr;

    uint8_t ext_len = 0;
    uint8_t compri = 15, compre = 15; /* ComprI and ComprE fields of the RPL Source Routing Header. */
    uint8_t padding = 0;


    // Get the route to destination
    ipv6_addr_t route_buffer[GNRC_SR_MAX_ROUTE_SIZE];
    size_t route_length = 0;
    if (ex_gnrc_sr_get_full_route(dest_addr, route_buffer, &route_length) < 0){
        DEBUG("RPL SRH: Failed to get a route to destination %s.\n", 
            ipv6_addr_to_str(addr_str, dest_addr, sizeof(addr_str)));
        return NULL;
    }
    DEBUG("RPL SRH: A source route to %s has been found.\n", 
            ipv6_addr_to_str(addr_str, dest_addr, sizeof(addr_str)));
    // When route length = 0, this means that the destnation is a neighbor << no need for SRH >>.
    if(route_length == 0){
        DEBUG("RPL SRH: The destination %s is a child of the root.\n", 
            ipv6_addr_to_str(addr_str, dest_addr, sizeof(addr_str)));
        return pkt;
    }

    // Find compre and compri, supposing compre=compri
    compri = _get_compri(route_buffer, route_length, dest_addr);
    compre = compri;

    if (compri > 15 || route_length > GNRC_SR_MAX_ROUTE_SIZE) {
        DEBUG("RPL SRH: Invalid compression or route length\n");
        return NULL;
    }
    // Find SRH ext length
    ext_len = sizeof(gnrc_rpl_srh_t) + 
            (route_length - 1) * (16 - compri) + 
            (16 - compre);
    
    padding = ext_len % 8 == 0 ? 0 : (8 - (ext_len % 8));
    ext_len += padding;
    
    /* SRH is always after the ipv6 header */
    //next = ipv6->next;
    srh_snip = gnrc_pktbuf_add(pkt, NULL, ext_len, GNRC_NETTYPE_IPV6_EXT);
    if (srh_snip == NULL) {
        DEBUG("RPL SRH: No space in PKT Buffer\n");
        return NULL;
    }
    srh = (gnrc_rpl_srh_t *) srh_snip->data;
    
    /* Init the SRH */
    srh->nh = pkt->type;
    srh->len = (ext_len - 8) / 8;
    srh->type = GNRC_NETTYPE_IPV6_EXT;
    srh->seg_left = route_length;
    srh->compr = (compri << 4) + compre;
    srh->pad_resv = padding << 4;
    
    DEBUG("RPL SRH: A new SRH has been created: Len=%d, No. of Segments=%d, Compressed Bytes=%d, Padding Size=%d\n",\
            srh->len, srh->seg_left, (srh->compr & 0x0F), ((srh->pad_resv & 0xF0) >> 4));
    /* Route Compression */
    /*uint8_t *addr_vector = (uint8_t *)(srh + 1);
    for (uint8_t i = 0; i < route_length; i++){
        // Start from last to first of the (dst -> root) route
        memcpy(&addr_vector[(route_length - 1 - i) * (16 - compri)], ((uint8_t *) &route_buffer[i]) + compri, 16 - compri);
        //memcpy(addr_vector + (i) * (16 - compri), &route_buffer[i] + compri, 16 - compri);
    }*/
    
    uint8_t *addr_vector = (uint8_t *)(srh + 1);
    for (int i = route_length - 1; i >= 0; i--) {
        memcpy(addr_vector, ((uint8_t *) &route_buffer[i])+compri, 16 - compri);
        addr_vector += (16 - compri);
    }

    /*// write protect first header
    tmp = gnrc_pktbuf_start_write(pkt);
    if (tmp == NULL) {
        DEBUG("RPL SRH: unable to allocate packet\n");
        gnrc_pktbuf_release(ipv6);
        return NULL;
    }*/
    ipv6_addr_t *dst_addr = &route_buffer[(route_length - 1)];
    ipv6 = gnrc_pktbuf_add(srh_snip, NULL, sizeof(ipv6_hdr_t), GNRC_NETTYPE_IPV6);
    if (ipv6 == NULL) {
        DEBUG("ipv6_hdr: no space left in packet buffer\n");
        return NULL;
    }

    hdr = (ipv6_hdr_t *)ipv6->data;
    memcpy(&hdr->src, &ipv6_hdr->src, sizeof(ipv6_addr_t));
    memcpy(&hdr->dst, dst_addr, sizeof(ipv6_addr_t));
    /* Update the ipv6 packet length */
    hdr->len = byteorder_htons(byteorder_ntohs(ipv6_hdr->len) + ext_len);
    hdr->nh = PROTNUM_IPV6_EXT_RH;
    //hdr->next = srh_snip;
    
    printf("Route Buffer: %s.\n", 
            ipv6_addr_to_str(addr_str, &route_buffer[(route_length - 1)], sizeof(addr_str)));
    printf("Dest from the SRH INSERT: %s.\n", 
            ipv6_addr_to_str(addr_str, &hdr->dst, sizeof(addr_str)));

    return ipv6;

}
/** @} */