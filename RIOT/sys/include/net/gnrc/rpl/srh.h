/*
 * Copyright (C) 2015 Martine Lenders <mlenders@inf.fu-berlin.de>
 * Copyright (C) 2025 Ahmad Mahmod <mahmod@unistra.fr>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @defgroup    net_gnrc_rpl_srh RPL source routing header extension
 * @ingroup     net_gnrc_rpl
 * @brief       Implementation of RPL source routing extension headers
 * @see <a href="https://tools.ietf.org/html/rfc6554">
 *          RFC 6554
 *      </a>
 * @{
 *
 * @file
 * @brief       Definititions for RPL source routing extension headers
 *
 * @author  Martine Lenders <mlenders@inf.fu-berlin.de>
 */
#ifndef NET_GNRC_RPL_SRH_H
#define NET_GNRC_RPL_SRH_H

#include "net/ipv6/hdr.h"
#include "net/ipv6/addr.h"
#include "net/gnrc/pkt.h"

#ifdef __cplusplus
extern "C" {
#endif


/* Need for FC-based RPL only */
int8_t gnrc_rpl_set_mode(int8_t mode);
int8_t gnrc_rpl_get_mode(void);

/**
 * @brief Get the root dodag id needed for SRH in ipv6 thread for src address.
 *
 * @param[in] void
 * @return  A pointer to the root dodag id.
 */
 ipv6_addr_t *gnrc_rpl_get_root_dodag_id(void);

 /**
  * @brief Set the root dodag id needed for SRH in ipv6 thread for src address.
  *
  * @param[in] dodag_id       Id of the DODAG
  * @return  A pointer to the root dodag id.
  */
 ipv6_addr_t *gnrc_rpl_set_root_dodag_id(ipv6_addr_t *dodag_id);

/**
 * @brief   Set the node as root for SRH.
 *
 */
void set_is_root(void);

/**
 * @brief   get if the node is root for SRH.
 *
 * @return  true, if the node is root
 * @return  false, if the node is not root
 */
bool get_is_root(void);

/**
 * @brief   The RPL Source routing header.
 *
 * @see <a href="https://tools.ietf.org/html/rfc6554">
 *          RFC 6554
 *      </a>
 *
 * @extends ipv6_ext_rh_t
 */
typedef struct __attribute__((packed)) {
    uint8_t nh;         /**< next header */
    uint8_t len;        /**< length in 8 octets without first octet */
    uint8_t type;       /**< identifier of a particular routing header type */
    uint8_t seg_left;   /**< number of route segments remaining */
    uint8_t compr;      /**< number of prefix octets (comprI and comprE) */
    uint8_t pad_resv;   /**< padding and reserved */
    uint16_t resv;      /**< reserved */
} gnrc_rpl_srh_t;

/**
 * @brief   Process the RPL source routing header.
 *
 * @pre `rh->seq_left > 0`; The 0 case means the destination is reached and
 *      common among all routing headers, so it should be handled by an
 *      external routing header handler.
 *
 * @param[in, out] ipv6 The IPv6 header of the incoming packet.
 * @param[in] rh        A RPL source routing header.
 * @param[out] err_ptr  A pointer to an erroneous octet within @p rh when
 *                      return value is @ref GNRC_IPV6_EXT_RH_ERROR. For any
 *                      other return value than @ref GNRC_IPV6_EXT_RH_ERROR the
 *                      value of `err_ptr` is not defined.
 *
 * @return  @ref GNRC_IPV6_EXT_RH_AT_DST, on success
 * @return  @ref GNRC_IPV6_EXT_RH_FORWARDED, when @p pkt *should be* forwarded
 * @return  @ref GNRC_IPV6_EXT_RH_ERROR, on error
 */
int gnrc_rpl_srh_process(ipv6_hdr_t *ipv6, gnrc_rpl_srh_t *rh, void **err_ptr);

/**
 * @brief   Insert RPL source routing header.
 *
 * @param[in, out] pkt        The data contained in the IPv6 packet.
 * @param[in, out] ipv6_hdr   IPv6 header.
 *
 * @return  @ref pkt after adding the header and ready for sending, on success
 * @return  @ref NULL, on error
 */
gnrc_pktsnip_t *gnrc_rpl_srh_insert(gnrc_pktsnip_t *pkt, ipv6_hdr_t *ipv6_hdr);

#ifdef __cplusplus
}
#endif

#endif /* NET_GNRC_RPL_SRH_H */
/** @} */