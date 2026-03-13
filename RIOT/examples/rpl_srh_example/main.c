/*
 * Copyright (C) 2015 Freie Universität Berlin
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     examples
 * @{
 *
 * @file
 * @brief       Example application for demonstrating the RIOT network stack
 *
 * @author      Hauke Petersen <hauke.petersen@fu-berlin.de>
 *
 * @}
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "shell.h"
#include "msg.h"
#include "net/gnrc/rpl/sr_table.h"
#include "srh.h"
#include "net/gnrc/pktbuf.h"
#include "net/gnrc/pkt.h"
#include "net/gnrc/nettype.h"

static char addr_str[IPV6_ADDR_MAX_STR_LEN];

// Main test function
int main(void) {
    // Initialize the packet buffer
    gnrc_pktsnip_t *tmp;
    gnrc_pktsnip_t *pkt = gnrc_pktbuf_add(NULL, "Hello", strlen("Hello"), GNRC_NETTYPE_UNDEF);
    assert(pkt != NULL);

    // Add an IPv6 header to the packet buffer
    ipv6_hdr_t ipv6_hdr;
    ipv6_hdr_t *hdr;
    memset(&ipv6_hdr, 0, sizeof(ipv6_hdr_t));
    ipv6_hdr.len = byteorder_htons(40);  // Example payload length
    ipv6_hdr.nh = GNRC_NETTYPE_UNDEF;  // No next header for simplicity
    ipv6_hdr.src = (ipv6_addr_t){.u8 = {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xAA}};
    ipv6_hdr.dst = (ipv6_addr_t){.u8 = {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11}};

    gnrc_pktsnip_t *ipv6_snip = gnrc_pktbuf_add(pkt, &ipv6_hdr, sizeof(ipv6_hdr_t), GNRC_NETTYPE_IPV6);
    assert(ipv6_snip != NULL);
    printf("BEFORE IPv6 LEN: %d\n", byteorder_ntohs(ipv6_hdr.len));
    
    // Set the destination address for the test
    //ipv6_addr_t dest_addr = {.u8 = {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x32, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03}};

    // Invoke the function to test
    tmp = ex_gnrc_rpl_srh_insert(pkt, &ipv6_hdr);
    hdr = (ipv6_hdr_t *) tmp->data;

    // Retrieve and validate the SRH
    gnrc_pktsnip_t *srh_snip = tmp->next;
    assert(srh_snip != NULL);
    gnrc_rpl_srh_t *srh = (gnrc_rpl_srh_t *)srh_snip->data;
    assert(srh != NULL);

    printf("Test passed: SRH generated successfully.\n");

    // Validate SRH fields
    assert(PROTNUM_IPV6_EXT_RH == hdr->nh);  // Should match the IPv6 next header field
    printf("1\n" );
    assert(srh->nh == pkt->type);  // Should match the IPv6 next header field
    printf("2\n");
    assert(srh->seg_left == 3);      // Example expected segments
    printf("3\n");
    printf("compr: %d\n", srh->compr>>4);
    assert(srh->compr == (8 << 4) + 8);  // ComprI and ComprE
    printf("4\n");

    printf("AFTER IPv6 LEN: %d\n", byteorder_ntohs(hdr->len));
    
    printf("Dst address: %s\n", ipv6_addr_to_str(addr_str,(ipv6_addr_t *) &hdr->dst, sizeof(addr_str)));
    
    // Validate IPv6 packet length update
    ipv6_hdr_t *final_hdr = (ipv6_hdr_t *)tmp->data;
    uint16_t new_length = byteorder_ntohs(final_hdr->len);
    assert(new_length == 40 + srh_snip->size);

    char *data = srh_snip->next->data;
    printf("Data: %s\n", data);

    /* Test Compressed Addresses*/
    uint8_t *addr_vector = (uint8_t *) (srh + 1);
    uint8_t comp_addr_size = (srh->compr >> 4);
    printf("Compressed Addresses: \n");
    for (uint8_t i = 0; i < (srh->seg_left); i++){

        for (uint8_t j=0; j < comp_addr_size; j++){
            printf("%x ", (uint8_t) addr_vector[i*comp_addr_size+j]);
        }

        printf("\n");
    }

    // Clean up
    gnrc_pktbuf_release(pkt);

    printf("All tests passed.\n");
    return 0;
}