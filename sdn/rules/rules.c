
#include <stdint.h>

#include "bpfapi/helpers.h"
#include "bpfapi/helpers_net.h"
#include "net/gnrc.h"
#include "net/gnrc/ipv6.h"
#include "ztimer.h"
#include "msg.h"
#include "evtimer_msg.h"

/* return values*/
enum{
    ERROR = -1,
    OK = 0,
};

#define SWAP32(x) ( \
    (((x) & 0x000000FFU) << 24) | \
    (((x) & 0x0000FF00U) <<  8) | \
    (((x) & 0x00FF0000U) >>  8) | \
    (((x) & 0xFF000000U) >> 24) )
    
#define FT_LIFETIME (300)  // seconds
#define NUM_ENTRIES (7)

/********************************************************************** */
int32_t switch_a(void *ctx)
{
     int8_t res = OK;
    /************************************** Fill NIB FT Table ****************************************************************//************************************** Fill the SRH Table ****************************************************************/
    ipv6_addr_t *dest = NULL;
    ipv6_addr_t *next = NULL;

    uint32_t destinations[8];
    next = (ipv6_addr_t *) &destinations[0];  // B_local
    dest = (ipv6_addr_t *) &destinations[4];

    // Address next hop: 
    destinations[0]  = SWAP32(0xfe800000);
    destinations[1]  = SWAP32(0x00000000);
    destinations[2] = SWAP32(0x645a0770);
    destinations[3] = SWAP32(0xc53f9375);

    // Address destination:
    destinations[4] = SWAP32(0x20010660);
    destinations[5] = SWAP32(0x44030480);
    destinations[6] = SWAP32(0x645a0770);
    destinations[7] = SWAP32(0xc53f9375);
    gnrc_netif_t *netif = bpf_gnrc_netif_get_by_prefix(dest);
    if (netif == NULL) {
        res = -2;
        goto end;
    }
    
    kernel_pid_t pid =  bpf_netif_get_pid(netif);

    if (bpf_gnrc_ipv6_nib_ft_add(dest, 128, next, pid, FT_LIFETIME) != 0) res = ERROR;
    
    // default route
    destinations[2] = SWAP32(0xe48d5fb6);
    destinations[3] = SWAP32(0xcf9afb5a);
    bpf_gnrc_ipv6_nib_ft_del(NULL, 0);
    if (bpf_gnrc_ipv6_nib_ft_add(NULL, 0, next, pid, 0) != 0) res = ERROR;

end:
    return res;
}