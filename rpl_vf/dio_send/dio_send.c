#include <stdint.h>

#include "bpfapi/helpers.h"
#include "bpfapi/helpers_net.h"
#include "net/gnrc.h"
#include "net/gnrc/ipv6.h"
//#include "net/gnrc/rpl.h"
#include "ztimer.h"
#include "msg.h"
#include "evtimer_msg.h"
#include "byteorder.h"

#define GNRC_RPL_PREFIX_AUTO_ADDRESS_BIT    (1 << 6)
#define GNRC_NETIF_IPV6_ADDRS_FLAGS_STATE_VALID            (0x10U)

/* return values*/
enum{
    ERROR = -1,
    OK = 0,
};

#define TYPEOF_POINTER(ptr) typeof(*(ptr))
#define SIZEOF_MEMBER(type, member) sizeof(((type *)0)->member)
#define TYPEOF_MEMBER(type, member) typeof(((type *)0)->member)

#define _GET_ELEMENT(ptr, member) \
    ((TYPEOF_MEMBER(TYPEOF_POINTER(ptr), member)) \
        (*(uint32_t *)((uint8_t *)(ptr) + offsetof(TYPEOF_POINTER(ptr), member))))

    
#define _GET_ELEMENT_POINTER(ptr, member) \
    (uintptr_t) ((uint8_t *) ptr + (offsetof(TYPEOF_POINTER(ptr), member)))
    // bpf_vm_pointer_get_element_pointer((uint8_t *)ptr, offsetof(TYPEOF_POINTER(ptr), member))
        

#define _SET_ELEMENT(ptr, member, value) \
    (*(typeof(((TYPEOF_POINTER(ptr) *)0)->member) *)((uint8_t *)(ptr) + offsetof(TYPEOF_POINTER(ptr), member)) \
    = (typeof(((TYPEOF_POINTER(ptr) *)0)->member))(value))


#define GNRC_RPL_OPT_DODAG_CONF_LEN         (14)
#define GNRC_RPL_OPT_PREFIX_INFO_LEN        (30)
#define GNRC_RPL_OPT_TARGET_LEN             (18)
#define GNRC_RPL_OPT_TRANSIT_INFO_LEN       (4)

#define GNRC_RPL_REQ_DIO_OPT_DODAG_CONF_SHIFT       (0)
#define GNRC_RPL_REQ_DIO_OPT_DODAG_CONF             (1)
#define GNRC_RPL_REQ_DIO_OPT_PREFIX_INFO_SHIFT      (1)
#define GNRC_RPL_REQ_DIO_OPT_PREFIX_INFO            (1 << GNRC_RPL_REQ_DIO_OPT_PREFIX_INFO_SHIFT)

/* RPL OPTIONS */
#define GNRC_RPL_OPT_DODAG_CONF           (4)
#define GNRC_RPL_OPT_PREFIX_INFO          (8)

#define GNRC_RPL_INSTANCES_NUMOF            (1)
#define GNRC_RPL_LEAF_NODE (2)
#define GNRC_RPL_ICMPV6_CODE_DIO (0x01)
#define GNRC_RPL_MOP_SHIFT                  (3)
#define GNRC_RPL_SHIFTED_MOP_MASK           (0x7)
#define GNRC_RPL_GROUNDED_SHIFT             (7)
#define GNRC_RPL_PRF_MASK                   (0x7)
#define GNRC_RPL_MSG_TYPE_TRICKLE_MSG         (0x0901)
#define GNRC_RPL_INFINITE_RANK (0xFFFF)

#define ICMPV6_RPL_CTRL     (155)   /**< RPL control message */

/* Describe the needed structs */
/******************************************************************************************************/
typedef struct gnrc_rpl_dodag gnrc_rpl_dodag_t;
typedef struct gnrc_rpl_parent gnrc_rpl_parent_t;
typedef struct gnrc_rpl_instance gnrc_rpl_instance_t;

typedef struct {
    void (*func)(void *);       /**< callback function pointer */
    void *args;                 /**< callback function arguments */
} trickle_callback_t;

typedef struct{
    uint8_t k;
    uint8_t Imax;
    uint16_t c;
    uint32_t Imin;
    uint32_t I;
    uint32_t t;
    
    kernel_pid_t pid;
    trickle_callback_t callback;

    msg_t msg;
    ztimer_t msg_timer;
} trickle_t;


typedef struct __attribute__((packed)) {
    uint8_t type;       /**< Option Type */
    uint8_t length;     /**< Option Length, does not include the first two byte */
} gnrc_rpl_opt_t;

typedef struct __attribute__((packed)) {
    uint8_t instance_id;        /**< id of the instance */
    uint8_t version_number;     /**< version number of the DODAG */
    uint16_t rank;              /**< rank of the parent emitting the DIO */
    uint8_t g_mop_prf;          /**< grounded, MOP, preferred flags */
    uint8_t dtsn;               /**< Destination Advertisement Trigger Sequence Number */
    uint8_t flags;              /**< unused */
    uint8_t reserved;           /**< reserved */
    ipv6_addr_t dodag_id;       /**< id of the dodag */
} gnrc_rpl_dio_t;

typedef struct __attribute__((packed)) {
    uint8_t type;                       /**< Option Type: 0x04 */
    uint8_t length;                     /**< length of option, not including first two bytes */
    uint8_t flags_a_pcs;                /**< flags */
    uint8_t dio_int_doubl;              /**< trickle Imax parameter */
    uint8_t dio_int_min;                /**< trickle Imin parameter */
    uint8_t dio_redun;                  /**< trickle k parameter */
    uint16_t max_rank_inc;      /**< allowable increase in rank */
    uint16_t min_hop_rank_inc;  /**< DAGRank(rank) = floor(rank/MinHopRankIncrease) */
    uint16_t ocp;               /**< Objective Code Point */
    uint8_t reserved;                   /**< reserved */
    uint8_t default_lifetime;           /**< lifetime of RPL routes (lifetime * lifetime_unit) */
    uint16_t lifetime_unit;     /**< unit in seconds */
} gnrc_rpl_opt_dodag_conf_t;

typedef struct __attribute__((packed)) {
    uint8_t flags;      /**< unused */
    uint8_t reserved;   /**< reserved */
} gnrc_rpl_dis_t;

typedef struct __attribute__((packed)) {
    uint8_t type;               /**< Option Type: 0x07 */
    uint8_t length;             /**< Option Length: 19 bytes*/
    uint8_t instance_id;        /**< id of the instance */
    uint8_t VID_flags;          /**< V|I|D predicate options followed by 5 bit unused flags */
    ipv6_addr_t dodag_id;       /**< DODAG ID predicate */
    uint8_t version_number;     /**< version number of the DODAG */
} gnrc_rpl_opt_dis_solicited_t;

typedef struct __attribute__((packed)) {
    uint8_t instance_id;        /**< id of the instance */
    uint8_t k_d_flags;          /**< K and D flags */
    uint8_t reserved;           /**< reserved */
    uint8_t dao_sequence;       /**< sequence of the DAO, needs to be used for DAO-ACK */
} gnrc_rpl_dao_t;

typedef struct __attribute__((packed)) {
    uint8_t instance_id;        /**< id of the instance */
    uint8_t d_reserved;         /**< if set, indicates that the DODAG id should be included */
    uint8_t dao_sequence;       /**< sequence must be equal to the sequence from the DAO object */
    uint8_t status;             /**< indicates completion */
} gnrc_rpl_dao_ack_t;

typedef struct __attribute__((packed)) {
    uint8_t type;               /**< option type */
    uint8_t length;             /**< option length without the first two bytes */
    uint8_t flags;              /**< unused */
    uint8_t prefix_length;      /**< number of valid leading bits in the IPv6 prefix */
    ipv6_addr_t target;         /**< IPv6 prefix, address or multicast group */
} gnrc_rpl_opt_target_t;

typedef struct __attribute__((packed)) {
    uint8_t type;               /**< option type */
    uint8_t length;             /**< option length without the first two bytes */
    uint8_t e_flags;            /**< external flag indicates external routes */
    uint8_t path_control;       /**< limits the number of DAO parents */
    uint8_t path_sequence;      /**< increased value for route updates */
    uint8_t path_lifetime;      /**< lifetime of routes */
} gnrc_rpl_opt_transit_t;

typedef struct __attribute__((packed)) {
    uint8_t type;                       /**< option type */
    uint8_t length;                     /**< option length without the first
                                         *   two bytes */
    uint8_t prefix_len;                 /**< prefix length */
    uint8_t LAR_flags;                  /**< flags and resereved */
    uint32_t valid_lifetime;    /**< valid lifetime */
    uint32_t pref_lifetime;     /**< preferred lifetime */
    uint32_t reserved;                  /**< reserved */
    ipv6_addr_t prefix;                 /**< prefix used for Stateless Address
                                         *   Autoconfiguration */
} gnrc_rpl_opt_prefix_info_t;

struct gnrc_rpl_parent {
    gnrc_rpl_parent_t *next;        /**< pointer to the next parent */
    uint8_t state;                  /**< see @ref gnrc_rpl_parent_states */
    ipv6_addr_t addr;               /**< link-local IPv6 address of this parent */
    uint8_t dtsn;                   /**< last seen dtsn of this parent */
    uint16_t rank;                  /**< rank of the parent */
    gnrc_rpl_dodag_t *dodag;        /**< DODAG the parent belongs to */
    double link_metric;             /**< metric of the link */
    uint8_t link_metric_type;       /**< type of the metric */
    /**
     * @brief Parent timeout events (see @ref GNRC_RPL_MSG_TYPE_PARENT_TIMEOUT)
     */
    evtimer_msg_event_t timeout_event;
};

typedef struct {
    uint16_t ocp;   
    uint16_t (*calc_rank)(gnrc_rpl_dodag_t *dodag, uint16_t base_rank);
    int (*parent_cmp)(gnrc_rpl_parent_t *parent1, gnrc_rpl_parent_t *parent2);
    gnrc_rpl_dodag_t *(*which_dodag)(gnrc_rpl_dodag_t *, gnrc_rpl_dodag_t *); /**< compare for dodags */
    void (*reset)(gnrc_rpl_dodag_t *dodag);
    void (*parent_state_callback)(gnrc_rpl_parent_t *, int, int); /**< retrieves the state of a parent*/
    void (*init)(gnrc_rpl_dodag_t *dodag);
    void (*process_dio)(void);  /**< DIO processing callback (acc. to OF0 spec, chpt 5) */
} gnrc_rpl_of_t;


struct gnrc_rpl_dodag {
    ipv6_addr_t dodag_id;           /**< id of the DODAG */
    gnrc_rpl_parent_t *parents;     /**< pointer to the parents list of this DODAG */
    gnrc_rpl_instance_t *instance;  /**< pointer to the instance that this dodag is part of */
    uint8_t dtsn;                   /**< DAO Trigger Sequence Number */
    uint8_t prf;                    /**< preferred flag */
    uint8_t dio_interval_doubl;     /**< trickle Imax parameter */
    uint8_t dio_min;                /**< trickle Imin parameter */
    uint8_t dio_redun;              /**< trickle k parameter */
    uint8_t default_lifetime;       /**< lifetime of routes (lifetime * unit) */
    uint16_t lifetime_unit;         /**< unit in seconds of the lifetime */
    kernel_pid_t iface;             /**< interface PID this DODAG operates on */
    uint8_t version;                /**< version of this DODAG */
    uint8_t grounded;               /**< grounded flag */
    uint16_t my_rank;               /**< rank/position in the DODAG */
    uint8_t node_status;            /**< leaf, normal, or root node */
    uint8_t dao_seq;                /**< dao sequence number */
    uint8_t dao_counter;            /**< amount of retried DAOs */
    bool dao_ack_received;          /**< flag to check for DAO-ACK */
    uint8_t dio_opts;               /**< options in the next DIO
                                         (see @ref GNRC_RPL_REQ_DIO_OPTS "DIO Options") */
    evtimer_msg_event_t dao_event;  /**< DAO TX events (see @ref GNRC_RPL_MSG_TYPE_DODAG_DAO_TX) */
    trickle_t trickle;              /**< trickle representation */
};

struct gnrc_rpl_instance {
    uint8_t id;                     /**< id of the instance */
    uint8_t state;                  /**< 0 for unused, 1 for used */
    gnrc_rpl_dodag_t dodag;         /**< DODAG of this instance */
    uint8_t mop;                    /**< configured Mode of Operation */
    gnrc_rpl_of_t *of;              /**< configured Objective Function */
    uint16_t min_hop_rank_inc;      /**< minimum hop rank increase */
    uint16_t max_rank_inc;          /**< max increase in the rank */
    /**
     * @brief Instance cleanup events (see @ref GNRC_RPL_MSG_TYPE_INSTANCE_CLEANUP)
     */
    evtimer_msg_event_t cleanup_event;
};
/*********************************************************************************************** */
static gnrc_pktsnip_t *_dio_prefix_info_build(gnrc_pktsnip_t *pkt, gnrc_rpl_dodag_t *dodag)
{
    gnrc_ipv6_nib_pl_t ple;
    gnrc_rpl_opt_prefix_info_t *prefix_info;
    gnrc_pktsnip_t *opt_snip;

    if ((opt_snip = bpf_gnrc_pktbuf_add((uintptr_t)pkt, NULL, sizeof(gnrc_rpl_opt_prefix_info_t),
                                    GNRC_NETTYPE_UNDEF)) == NULL) {
        // const char msg[] = "RPL-DIO: BUILD PREFIX INFO - no space left in packet buffer\n";
        // f12r_vm_printf(msg);
        bpf_gnrc_pktbuf_release(pkt);
        return NULL;
    }
    prefix_info = _GET_ELEMENT(opt_snip, data);
    _SET_ELEMENT(prefix_info, type, GNRC_RPL_OPT_PREFIX_INFO);
    _SET_ELEMENT(prefix_info, length, GNRC_RPL_OPT_PREFIX_INFO_LEN);
    /* auto-address configuration */
    _SET_ELEMENT(prefix_info, LAR_flags, GNRC_RPL_PREFIX_AUTO_ADDRESS_BIT);
    _SET_ELEMENT(prefix_info, prefix_len, 64);

    /***********_get_pl_entry************* */
    void *state = NULL;
    bool pl_entry_found = false;
    uint8_t i=2; // max 3 prefixes
    while (bpf_gnrc_ipv6_nib_pl_iter(_GET_ELEMENT(dodag, iface), &state, (uintptr_t)&ple) && (i>=0)) {
        if (bpf_ipv6_addr_match_prefix(&ple.pfx,(ipv6_addr_t *) _GET_ELEMENT_POINTER(dodag, dodag_id)) >= _GET_ELEMENT(prefix_info, prefix_len)) {
            pl_entry_found = true;
            break;
        }
        i--;
    }

    if (pl_entry_found) {
        uint32_t now = (uint32_t)bpf_ztimer_now() * 1000;

        uint32_t valid_ltime = (ple.valid_until < UINT32_MAX) ?
                               (ple.valid_until - now) / 1000 : UINT32_MAX;
        uint32_t pref_ltime = (ple.pref_until < UINT32_MAX) ?
                              (ple.pref_until - now) / 1000 : UINT32_MAX;

        _SET_ELEMENT(prefix_info, valid_lifetime, bpf_byteorder_htonl(valid_ltime));
        _SET_ELEMENT(prefix_info, pref_lifetime, bpf_byteorder_htonl(pref_ltime));
    }
    else {
        // const char msg[] = "RPL-DIO: Prefix of DODAG-ID not in prefix list\n";
        // f12r_vm_printf(msg);
        bpf_gnrc_pktbuf_release(pkt);
        return NULL;
    }
    _SET_ELEMENT(prefix_info, reserved, 0);
    f12r_memcpy((void *)_GET_ELEMENT_POINTER(prefix_info, prefix), (void *)_GET_ELEMENT_POINTER(dodag, dodag_id), _GET_ELEMENT(prefix_info, prefix_len)/8);
    return opt_snip;
}


static gnrc_pktsnip_t *_dio_dodag_conf_build(gnrc_pktsnip_t *pkt, gnrc_rpl_dodag_t *dodag)
{
    gnrc_rpl_opt_dodag_conf_t *dodag_conf;
    gnrc_pktsnip_t *opt_snip;

    if ((opt_snip = bpf_gnrc_pktbuf_add((uintptr_t)pkt, NULL, sizeof(gnrc_rpl_opt_dodag_conf_t),
                                    GNRC_NETTYPE_UNDEF)) == NULL) {
        // const char msg[] = "RPL-DIO: BUILD DODAG CONF - no space left in packet buffer\n";
        // f12r_vm_printf(msg);
        bpf_gnrc_pktbuf_release(pkt);
        return NULL;
    }
    dodag_conf = _GET_ELEMENT(opt_snip, data);
    _SET_ELEMENT(dodag_conf, type, GNRC_RPL_OPT_DODAG_CONF);
    _SET_ELEMENT(dodag_conf, length, GNRC_RPL_OPT_DODAG_CONF_LEN);
    _SET_ELEMENT(dodag_conf, flags_a_pcs, 0);
    _SET_ELEMENT(dodag_conf, dio_int_doubl, _GET_ELEMENT(dodag, dio_interval_doubl));
    _SET_ELEMENT(dodag_conf, dio_int_min, _GET_ELEMENT(dodag, dio_min));
    _SET_ELEMENT(dodag_conf, dio_redun, _GET_ELEMENT(dodag, dio_redun));
    _SET_ELEMENT(dodag_conf, max_rank_inc, bpf_byteorder_htons(_GET_ELEMENT(_GET_ELEMENT(dodag, instance), max_rank_inc)));
    _SET_ELEMENT(dodag_conf, min_hop_rank_inc, bpf_byteorder_htons(_GET_ELEMENT(_GET_ELEMENT(dodag, instance), min_hop_rank_inc)));
    _SET_ELEMENT(dodag_conf, length, bpf_byteorder_htons(_GET_ELEMENT(_GET_ELEMENT(_GET_ELEMENT(dodag, instance), of), ocp)));
    _SET_ELEMENT(dodag_conf, reserved, 0);
    _SET_ELEMENT(dodag_conf, default_lifetime, _GET_ELEMENT(dodag, default_lifetime));
    _SET_ELEMENT(dodag_conf, lifetime_unit, bpf_byteorder_htons(_GET_ELEMENT(dodag, lifetime_unit)));

    return opt_snip;
}

typedef struct {
    uintptr_t inst; /* ptr to the instance message */
    uintptr_t destination; /* ptr to destanation address */
} dio_send_context_t;

/**
 * @brief   Receive the DIO message in FC-based RPL protocol.
 * @pre @p  pkt != NULL
 *
 * @param[in] pkt       A gnrc_pktsnip_t pointer to the pkt sent by the application.
 *                      It represents the context of the FC.
 *                      
 *
 * @return  OK, in case of successful handling
 * @return  ERROR, in case of any error which stop the processing
 */
#define CONFIG_GNRC_RPL_WITHOUT_PIO (0)

int32_t dio_send(dio_send_context_t *ctx)
{   
    gnrc_rpl_instance_t *inst = (gnrc_rpl_instance_t *) ctx->inst;
    ipv6_addr_t *destination = (ipv6_addr_t *)ctx->destination;
    int8_t res = OK;

    if (inst == NULL) {
        // const char msg[] = "RPL-DIO: No matching of dodag id\n";
        // f12r_vm_printf(msg);
        res = ERROR;
        goto end;
    }

    gnrc_rpl_dodag_t *dodag = ( gnrc_rpl_dodag_t *) _GET_ELEMENT_POINTER(inst, dodag);
    gnrc_pktsnip_t *pkt = NULL, *tmp;
    gnrc_rpl_dio_t *dio;

    if ((dodag->dio_opts & GNRC_RPL_REQ_DIO_OPT_DODAG_CONF)) {
        pkt = _dio_dodag_conf_build(pkt, dodag);
        if (pkt == NULL){
            res = ERROR;
            goto end;
        }
        _SET_ELEMENT(dodag, dio_opts, _GET_ELEMENT(dodag, dio_opts) & ~GNRC_RPL_REQ_DIO_OPT_DODAG_CONF);
    }

    if ((!CONFIG_GNRC_RPL_WITHOUT_PIO)  && (_GET_ELEMENT(dodag, dio_opts) & GNRC_RPL_REQ_DIO_OPT_PREFIX_INFO)){
        pkt = _dio_prefix_info_build(pkt, dodag);
        if (pkt == NULL){
            res = ERROR;
            goto end;
        }
    }

    if ((tmp = bpf_gnrc_pktbuf_add((uintptr_t)pkt, NULL, sizeof(gnrc_rpl_dio_t), GNRC_NETTYPE_UNDEF)) == NULL) {
        // const char msg[] = "RPL-DIO: Send DIO - no space left in packet buffer\n";
        // f12r_vm_printf(msg);
        bpf_gnrc_pktbuf_release(pkt);
        res = ERROR;
        goto end;
    }

    pkt = tmp;
    dio = _GET_ELEMENT(pkt, data);
    _SET_ELEMENT(dio, instance_id, _GET_ELEMENT(inst, id));
    _SET_ELEMENT(dio, version_number, _GET_ELEMENT(dodag, version));
    /* a leaf node announces an INFINITE_RANK */
    _SET_ELEMENT(dio, rank, ((dodag->node_status == GNRC_RPL_LEAF_NODE) ?
                 bpf_byteorder_htons(GNRC_RPL_INFINITE_RANK) : bpf_byteorder_htons(_GET_ELEMENT(dodag, my_rank))));
    _SET_ELEMENT(dio, g_mop_prf, (_GET_ELEMENT(dodag, grounded) << GNRC_RPL_GROUNDED_SHIFT) |
                (_GET_ELEMENT(inst, mop) << GNRC_RPL_MOP_SHIFT) | _GET_ELEMENT(dodag, prf));

    _SET_ELEMENT(dio, dtsn, _GET_ELEMENT(dodag, dtsn));
    _SET_ELEMENT(dio, flags, 0);
    _SET_ELEMENT(dio, reserved, 0);
    f12r_memcpy((void *) _GET_ELEMENT_POINTER(dio, dodag_id), (void *)_GET_ELEMENT_POINTER(dodag, dodag_id), sizeof(ipv6_addr_t));

    if ((tmp = bpf_gnrc_icmpv6_build((uintptr_t)pkt, ICMPV6_RPL_CTRL, GNRC_RPL_ICMPV6_CODE_DIO, sizeof(icmpv6_hdr_t))) == NULL) {
        // const char msg[] = "RPL-DIO: Send DIO - no space left in packet buffer\n";
        // f12r_vm_printf(msg);
        bpf_gnrc_pktbuf_release(pkt);
        res = ERROR;
        goto end;
    }
    pkt = tmp;

    bpf_gnrc_rpl_send((uintptr_t)pkt, _GET_ELEMENT(dodag, iface), (uintptr_t)NULL, 
                        (uintptr_t)destination,  (uintptr_t)_GET_ELEMENT_POINTER(dodag, dodag_id));

    end:
        return res;
}