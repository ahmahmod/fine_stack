#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#include "femtocontainer/femtocontainer.h"
#include "call.h"
#include "net/gnrc.h"
#include "net/gnrc/icmpv6.h"
#include "net/gnrc/pktbuf.h"
#include "net/gnrc/nettype.h"
#include "net/gnrc/pkt.h"
#include "net/gnrc/ipv6.h"
#include "net/gnrc/udp.h"

#define ENABLE_DEBUG (1)
#include "debug.h"


static uint16_t inet_csum_slice1(uint16_t sum, const uint8_t *buf, uint16_t len, size_t accum_len)
{
    uint32_t csum = sum;

    //DEBUG("inet_sum: sum = 0x%04" PRIx16 ", len = %" PRIu16 "\n", sum, len );

    if (len == 0)
        return csum;

    if (accum_len & 1) {      /* if accumulated length is odd */
        csum += *buf;         /* add first byte as bottom half of 16-byte word */
        buf++;
        len--;
        accum_len++;
    }

    for (unsigned i = 0; i < (len >> 1); buf += 2, i++) {
        csum += (uint16_t)(*buf << 8) + *(buf + 1); /* group bytes by 16-byte words */
                                                    /* and add them */
    }

    if ((accum_len + len) & 1)          /* if accumulated length is odd */
        csum += (uint16_t)(*buf << 8);  /* add last byte as top half of 16-byte word */

    while (csum >> 16) {
        uint16_t carry = csum >> 16;
        csum = (csum & 0xffff) + carry;
    }

    //DEBUG("inet_sum: new sum = 0x%04" PRIx32 "\n", csum);

    return csum;
}

static inline uint16_t inet_csum1(uint16_t sum, const uint8_t *buf, uint16_t len) {
    return inet_csum_slice1(sum, buf, len, 0);
}

static inline uint16_t ipv6_hdr_inet_csum1(uint16_t sum, ipv6_hdr_t *hdr,
                                          uint8_t prot_num, uint16_t len)
{
    if (((uint32_t)sum + len + prot_num) > 0xffff) {
        /* increment by one for overflow to keep it as 1's complement sum */
        sum++;
    }

    return inet_csum1(sum + len + prot_num, hdr->src.u8, (2 * sizeof(ipv6_addr_t)));
}

static uint16_t _calc_csum(gnrc_pktsnip_t *hdr, gnrc_pktsnip_t *pseudo_hdr, gnrc_pktsnip_t *payload)
{
    uint16_t csum = 0;
    uint16_t len = (uint16_t)hdr->size;

    /* process the payload */
    while (payload && payload != hdr && payload != pseudo_hdr) {
        csum = inet_csum_slice1(csum, (uint8_t *)(payload->data), payload->size, len);
        len += (uint16_t)payload->size;
        payload = payload->next;
    }
    /* process applicable UDP header bytes */
    csum = inet_csum1(csum, (uint8_t *)hdr->data, sizeof(udp_hdr_t));

    switch (pseudo_hdr->type) {
#ifdef MODULE_GNRC_IPV6
        case GNRC_NETTYPE_IPV6:
            csum = ipv6_hdr_inet_csum1(csum, pseudo_hdr->data, PROTNUM_UDP, len);
            break;
#endif
        default:
            (void)len;
            
            return 0;
    }
    
    /* return inverted results */
    if (csum == 0xFFFF) {
        /* https://tools.ietf.org/html/rfc8200#section-8.1
         * bullet 4
         * "if that computation yields a result of zero, it must be changed
         * to hex FFFF for placement in the UDP header."
         */
        return 0xFFFF;
    } else {
        return ~csum;
    }
}

uint32_t bpf_calc_csum(f12r_t *bpf, uint32_t hdr, uint32_t pseudo_hdr, uint32_t payload, uint32_t a4, uint32_t a5)
{
    (void)bpf;
    (void)a4;
    (void)a5;

    gnrc_pktsnip_t* hdr1 = (gnrc_pktsnip_t*)(uintptr_t)hdr;
    gnrc_pktsnip_t* pseudo_hdr1 = (gnrc_pktsnip_t*)(uintptr_t)pseudo_hdr;
    gnrc_pktsnip_t* payload1 = (gnrc_pktsnip_t*)(uintptr_t)payload;

    uint16_t csum = 0;
    csum = _calc_csum(hdr1, pseudo_hdr1, payload1);
    //uint16_t csum_target = 0xFFFF;


    return (uint32_t) csum;
}


uint32_t bpf_gnrc_udp_calc_csum(f12r_t *bpf, uint32_t hdr, uint32_t pseudo_hdr, uint32_t a3, uint32_t a4, uint32_t a5)
{
    (void)bpf;
    (void)a3;
    (void)a4;
    (void)a5;

    gnrc_pktsnip_t* hdr1 = (gnrc_pktsnip_t*)(uintptr_t)hdr;
    gnrc_pktsnip_t* pseudo_hdr1 = (gnrc_pktsnip_t*)(uintptr_t)pseudo_hdr;

    uint16_t csum = 0;
    
    if ((hdr1 == NULL) || (pseudo_hdr1 == NULL)) {
        printf("Csum Error: %d\n", 0);
        return 0;
    }
    
    if (hdr1->type != GNRC_NETTYPE_UDP) {
        printf("Csum Error: %d\n", 1);
        return 0;
    }
    

    csum = _calc_csum(hdr1, pseudo_hdr1, hdr1->next);

    if (csum == 0) {
        printf("Csum Error: %d\n", 2);
        return 0;
    }

    ((udp_hdr_t *)hdr1->data)->checksum = byteorder_htons(csum);

    uint16_t csum1 = byteorder_htons(csum).u16;
    

    return  (uint32_t) csum1;
}

uint32_t bpf_gnrc_icmpv6_build(f12r_t *bpf, uint32_t next, uint32_t type, uint32_t code, uint32_t size, uint32_t a5)
{
    (void)bpf;
    (void)a5;

    gnrc_pktsnip_t *next1 = (gnrc_pktsnip_t *) next; 
    uint8_t type1 = (uint8_t) type;
    uint8_t code1 = (uint8_t) code; 
    size_t size1 = (size_t) size;

    return (uintptr_t) gnrc_icmpv6_build(next1, type1, code1, size1);
}