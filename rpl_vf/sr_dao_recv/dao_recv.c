#include <stdint.h>

#include "bpfapi/helpers.h"
#include "bpfapi/helpers_net.h"
#include "net/gnrc.h"
#include "net/gnrc/ipv6.h"
//#include "net/gnrc/rpl.h"
#include "ztimer.h"
#include "msg.h"
#include "evtimer_msg.h"

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
    


#define GNRC_RPL_DAO_D_BIT                  (1 << 6)
#define GNRC_RPL_DAO_K_BIT                  (1 << 7)


/* RPL OPTIONS */
#define GNRC_RPL_OPT_PAD1                 (0)
#define GNRC_RPL_OPT_PADN                 (1)
#define GNRC_RPL_OPT_TARGET               (5)
#define GNRC_RPL_OPT_TRANSIT              (6)


#define GNRC_RPL_LEAF_NODE (2)
#define GNRC_RPL_ICMPV6_CODE_DAO (0x02)

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
    uint8_t k_d_flags;          /**< K and D flags */
    uint8_t reserved;           /**< reserved */
    uint8_t dao_sequence;       /**< sequence of the DAO, needs to be used for DAO-ACK */
} gnrc_rpl_dao_t;


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
    ipv6_addr_t parent;
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
/******************************************************************************************************/
#define FIB_FLAG_RPL_ROUTE (1)
/******************************************************************************************************/
static bool parse_options(int msg_type, gnrc_rpl_instance_t *inst, gnrc_rpl_opt_t *opt,
                           uint16_t len, ipv6_addr_t *src, uint32_t *included_opts)
{
    /* Variables */
    uint16_t len_parsed = 0;
    uint32_t parsed_opts = 0;
    gnrc_rpl_opt_target_t *first_target = NULL;
    gnrc_rpl_dodag_t *dodag = (gnrc_rpl_dodag_t *) _GET_ELEMENT_POINTER(inst, dodag);
    eui64_t iid;
    
    bpf_vm_pointer_set_element((uint8_t *)included_opts, 0, 0, sizeof(uint32_t));

    // const char msg1[] = "RPL-Parse Options: PAD1 option parsed\n";
    // const char msg2[] = "RPL-Parse Options: PADN option parsed\n";
    // const char msg6[] = "RPL-Parse Options: RPL TARGET INFO DAO option parsed\n";
    // const char msg7[] = "RPL-Parse Options: RPL TRANSIT INFO DAO option parsed\n";

    while (len_parsed < len) {
        switch (_GET_ELEMENT(opt, type)){
            case (GNRC_RPL_OPT_PAD1):
                // f12r_vm_printf(msg1);
                parsed_opts |= ((uint32_t)1) << GNRC_RPL_OPT_PAD1;
                len_parsed += 1;
                opt = (gnrc_rpl_opt_t *)(((uint8_t *)opt) + 1);
                continue; 
            
            case (GNRC_RPL_OPT_PADN):
                // f12r_vm_printf(msg2);
                parsed_opts |= ((uint32_t)1) << GNRC_RPL_OPT_PADN;
                break;
            
            case (GNRC_RPL_OPT_TARGET):
                // f12r_vm_printf(msg6);
                parsed_opts |= ((uint32_t)1) << GNRC_RPL_OPT_TARGET;
                gnrc_rpl_opt_target_t *target = (gnrc_rpl_opt_target_t *)opt;
                if (first_target == NULL) {
                    first_target = target;
                }

                bpf_gnrc_sr_delete_route((ipv6_addr_t *)_GET_ELEMENT_POINTER(target, target), sizeof(ipv6_addr_t));
                break;

            case (GNRC_RPL_OPT_TRANSIT):
                // f12r_vm_printf(msg7);
                parsed_opts |= ((uint32_t)1) << GNRC_RPL_OPT_TRANSIT;
                gnrc_rpl_opt_transit_t *transit = (gnrc_rpl_opt_transit_t *)opt;
                
                if (first_target == NULL) {
                    break;
                }

                if (!bpf_ipv6_addr_equal((ipv6_addr_t *)_GET_ELEMENT_POINTER(first_target, target), (ipv6_addr_t *)_GET_ELEMENT_POINTER(transit, parent))){
                    bpf_gnrc_sr_delete_route((ipv6_addr_t *)_GET_ELEMENT_POINTER(first_target, target), sizeof(ipv6_addr_t));
                    bpf_gnrc_sr_add_new_dst((ipv6_addr_t *)_GET_ELEMENT_POINTER(first_target, target),(ipv6_addr_t *)_GET_ELEMENT_POINTER(transit, parent), 
                                            _GET_ELEMENT(dodag, iface), FIB_FLAG_RPL_ROUTE,
                                            _GET_ELEMENT(transit, path_lifetime) * _GET_ELEMENT(dodag, lifetime_unit));
                }
                
                first_target = NULL;
                break;
        }
        len_parsed += _GET_ELEMENT(opt, length) + sizeof(gnrc_rpl_opt_t);
        opt = (gnrc_rpl_opt_t *)(((uint8_t *)(opt + 1)) + _GET_ELEMENT(opt, length));
    }
    *included_opts = parsed_opts;
    
    return true;
   
}



#define GNRC_RPL_INSTANCE_ID_MSB      (1 << 7)
#define GNRC_RPL_ICMPV6_CODE_DAO_ACK (0x03)

#define FC_HOOK_RPL_SEND_DAO_ACK (9)
#define FC_HOOK_RPL_PARSE_OPTIONS (10)


/**
 * @brief   Receive the DAO message in FC-based RPL protocol.
 * @pre @p  pkt != NULL
 *
 * @param[in] pkt       A gnrc_pktsnip_t pointer to the pkt sent by the application.
 *                      It represents the context of the FC.
 *                      
 *
 * @return  OK, in case of successful handling
 * @return  ERROR, in case of any error which stop the processing
 */
typedef struct {
    uintptr_t inst; /* ptr to the instance */
    uintptr_t destination; /* ptr to dst address */
    uint8_t seq; /* seq number */
} send_dao_ack_context_t;

typedef struct {
    uintptr_t dao; /* ptr to the DIS message */
    uintptr_t src; /* ptr to src address */
    uintptr_t dst; /* ptr to dst address */
    int16_t iface; /* iface number */
    uint16_t len;
} dao_recv_context_t;

int32_t dao_recv(dao_recv_context_t *ctx)
{  
    kernel_pid_t iface = (kernel_pid_t) ctx->iface;
    gnrc_rpl_dao_t *dao = (gnrc_rpl_dao_t *)ctx->dao;
    ipv6_addr_t *src = (ipv6_addr_t *)ctx->src;
    ipv6_addr_t *dst = (ipv6_addr_t *)ctx->dst;
    uint16_t len = ctx->len;
    int8_t res = OK;

    gnrc_rpl_instance_t *inst = NULL;
    gnrc_rpl_dodag_t *dodag = NULL;

    gnrc_rpl_opt_t *opts = (gnrc_rpl_opt_t *)(dao + 1);

    if ((inst = (gnrc_rpl_instance_t *) bpf_gnrc_rpl_get_instance_by_id(_GET_ELEMENT(dao, instance_id))) == NULL) {
        // const char msg[] = "RPL: DAO with unknown instance id received\n";
        // f12r_vm_printf(msg);
        res = ERROR;
        goto end;
    }

    dodag = (gnrc_rpl_dodag_t *)_GET_ELEMENT_POINTER(inst, dodag);
    len -= (sizeof(gnrc_rpl_dao_t) + sizeof(icmpv6_hdr_t));
    
    /* check if the D flag is set before accessing the DODAG id */
    if ((_GET_ELEMENT(dao, k_d_flags) & GNRC_RPL_DAO_D_BIT)) {
        if (f12r_memcmp((ipv6_addr_t *)_GET_ELEMENT_POINTER(dodag, dodag_id), (ipv6_addr_t *)(dao + 1), sizeof(ipv6_addr_t)) != 0) {
            // const char msg[] = "RPL: DAO with unknown DODAG id\n";
            // f12r_vm_printf(msg);
            res = ERROR;
            goto end;
        }

        opts = (gnrc_rpl_opt_t *)(((uint8_t *)opts) + sizeof(ipv6_addr_t));
        len -= sizeof(ipv6_addr_t);
    }

    /* a leaf node should not parse DAOs */
    if (_GET_ELEMENT(dodag, node_status) == GNRC_RPL_LEAF_NODE) {
        goto end;
    }

    uint32_t included_opts = 0;
    
    if(!parse_options(GNRC_RPL_ICMPV6_CODE_DAO, inst, opts, len, src, &included_opts)) {
        // const char msg[] = "RPL: Error encountered during DAO option parsing - ignore DAO\n";
        // f12r_vm_printf(msg);
        res = ERROR;
        goto end;
    }

    /* send a DAO-ACK if K flag is set */
    if (_GET_ELEMENT(dao, k_d_flags) & GNRC_RPL_DAO_K_BIT) {
        send_dao_ack_context_t send_dao_ack_ctx = {.inst= (uintptr_t)inst, .destination= (uintptr_t)src, 
                                    .seq= _GET_ELEMENT(dao, dao_sequence)};
        bpf_trigger_hook(FC_HOOK_RPL_SEND_DAO_ACK, (uintptr_t)&send_dao_ack_ctx, sizeof(send_dao_ack_ctx));
    }

    bpf_gnrc_rpl_delay_dao((uintptr_t)dodag, false);

    end:
        return res;
}