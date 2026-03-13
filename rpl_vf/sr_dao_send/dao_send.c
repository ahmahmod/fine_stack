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
 

/* RPL OPTIONS */
#define GNRC_RPL_OPT_TARGET               (5)
#define GNRC_RPL_OPT_TRANSIT              (6)

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
    uintptr_t next;        /**< pointer to the next parent */
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
/******************************************************************************************************/
#define GNRC_RPL_OPT_TRANSIT_E_FLAG_SHIFT   (7)

static gnrc_pktsnip_t *_dao_transit_build(gnrc_pktsnip_t *pkt, uint8_t lifetime, ipv6_addr_t *parent, bool external)
{
    gnrc_rpl_opt_transit_t *transit;
    gnrc_pktsnip_t *opt_snip;

    if ((opt_snip = bpf_gnrc_pktbuf_add((uintptr_t)pkt, NULL, sizeof(gnrc_rpl_opt_transit_t), GNRC_NETTYPE_UNDEF)) == NULL) {
        // const char msg[] = "RPL-DAO Send: no space left in packet buffer.\n";
        // f12r_vm_printf(msg);
        bpf_gnrc_pktbuf_release(pkt);
        return NULL;
    }
    transit = _GET_ELEMENT(opt_snip, data);
    _SET_ELEMENT(transit, type, GNRC_RPL_OPT_TRANSIT);

    _SET_ELEMENT(transit, length, sizeof(_GET_ELEMENT(transit, e_flags)) + sizeof(_GET_ELEMENT(transit, path_control)) +
                      sizeof(_GET_ELEMENT(transit, path_sequence)) + sizeof(_GET_ELEMENT(transit, path_lifetime)) + sizeof(ipv6_addr_t));
    f12r_memcpy((void *) _GET_ELEMENT_POINTER(transit, parent), parent, sizeof(ipv6_addr_t));
    _SET_ELEMENT(transit, e_flags, (external) << GNRC_RPL_OPT_TRANSIT_E_FLAG_SHIFT);
    _SET_ELEMENT(transit, path_control, 0);
    _SET_ELEMENT(transit, path_sequence, 0);
    _SET_ELEMENT(transit, path_lifetime, lifetime);

    // const char msg[] = "RPL-DAO Send: Transit Option built.\n";
    // f12r_vm_printf(msg);

    return opt_snip;
}

static gnrc_pktsnip_t *_dao_target_build(gnrc_pktsnip_t *pkt, ipv6_addr_t *addr, uint8_t prefix_length)
{
    gnrc_rpl_opt_target_t *target;
    gnrc_pktsnip_t *opt_snip;

    if ((opt_snip = bpf_gnrc_pktbuf_add((uintptr_t)pkt, NULL, sizeof(gnrc_rpl_opt_target_t), GNRC_NETTYPE_UNDEF)) == NULL) {
        // const char msg[] = "RPL-DAO Send: no space left in packet buffer.\n";
        // f12r_vm_printf(msg);
        bpf_gnrc_pktbuf_release(pkt);
        return NULL;
    }
    target = _GET_ELEMENT(opt_snip, data);
    _SET_ELEMENT(target, type, GNRC_RPL_OPT_TARGET);
    _SET_ELEMENT(target, length, sizeof(_GET_ELEMENT(target, flags)) + sizeof(_GET_ELEMENT(target, prefix_length)) + sizeof(ipv6_addr_t));
    _SET_ELEMENT(target, flags, 0);
    _SET_ELEMENT(target, prefix_length, prefix_length);
    f12r_memcpy((void *) _GET_ELEMENT_POINTER(target, target), addr, sizeof(ipv6_addr_t));

    // const char msg[] = "RPL-DAO Send: Target Option built.\n";
    // f12r_vm_printf(msg);

    return opt_snip;
}


typedef struct {
    uintptr_t inst; /* ptr to the instance message */
    uintptr_t destination; /* ptr to destanation address */
    uintptr_t fte;
    uintptr_t pkt;
    uintptr_t gnrc_rpl_evtimer;
    int16_t gnrc_rpl_pid;
    uint8_t lifetime;   /* liftime in seconds */
} dao_send_context_t;

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
#define GNRC_RPL_ROOT_NODE (1)
#define GNRC_RPL_INSTANCE_ID_MSB      (1 << 7)
#define GNRC_RPL_ICMPV6_CODE_DAO (0x02)
#define CONFIG_GNRC_RPL_DAO_SEND_RETRIES   (4)

int32_t dao_send(dao_send_context_t *ctx)
{
    gnrc_rpl_instance_t *inst = (gnrc_rpl_instance_t *) ctx->inst;
    ipv6_addr_t *destination = (ipv6_addr_t *)ctx->destination;
    gnrc_ipv6_nib_ft_t *fte = ( gnrc_ipv6_nib_ft_t *)ctx->fte;
    gnrc_pktsnip_t *pkt = (gnrc_pktsnip_t *) ctx->pkt;
    evtimer_msg_t *gnrc_rpl_evtimer = (evtimer_msg_t *) ctx->gnrc_rpl_evtimer;
    kernel_pid_t gnrc_rpl_pid = (kernel_pid_t) ctx->gnrc_rpl_pid;
    uint8_t lifetime = ctx->lifetime;
    int8_t res = OK;

    ipv6_addr_t *parent_addr;
    gnrc_rpl_parent_t *parent;

    if (inst == NULL) {
        // const char msg[] = "RPL-DAO Send: trying to send DAO without being part of a dodag.\n";
        // f12r_vm_printf(msg);
        res = ERROR;
        goto end;
    }

    gnrc_rpl_dodag_t *dodag = (gnrc_rpl_dodag_t *)_GET_ELEMENT_POINTER(inst, dodag);
    if (_GET_ELEMENT(dodag, node_status) == GNRC_RPL_ROOT_NODE) {
        // const char msg[] = "RPL-DAO Send: Root.\n";
        // f12r_vm_printf(msg);
        goto end;
    }
    
    if (_GET_ELEMENT(dodag, dao_ack_received) == false && (_GET_ELEMENT(dodag, dao_counter) >= CONFIG_GNRC_RPL_DAO_SEND_RETRIES)) {
        // const char msg[] = "RPL-DAO Send: Long delay.\n";
        // f12r_vm_printf(msg);
        bpf_gnrc_rpl_delay_dao((uintptr_t) dodag, true); //true: long delay
        goto end;
    }
    if (_GET_ELEMENT(dodag, parents) == NULL) {
        // const char msg[] = "RPL-DAO Send: No prefered parent\n";
        // f12r_vm_printf(msg);
        res = ERROR;
        goto end;
    }
    parent = (gnrc_rpl_parent_t *) _GET_ELEMENT(dodag, parents);
    parent_addr = (ipv6_addr_t *) _GET_ELEMENT_POINTER(parent, addr);
    /* Add the prefix to include the parent's global IP address. */

    destination =(ipv6_addr_t *) _GET_ELEMENT_POINTER(dodag, dodag_id);
    f12r_memcpy(parent_addr, destination, 8);

    _SET_ELEMENT(dodag, dao_counter, _GET_ELEMENT(dodag, dao_counter)+1);

    gnrc_pktsnip_t *tmp = NULL;

    /* add external and RPL FT entries */
    /* TODO: nib: dropped support for external transit options for now */
    void *ft_state = NULL;

    /* Send the Transit options*/
    if ((pkt = _dao_transit_build(pkt, lifetime, parent_addr, false)) == NULL) {
        // const char msg[] = "RPL-DAO Send - TRANSIT BUILD: no space left in packet buffer\n";
        // f12r_vm_printf(msg);
        res = ERROR;
        goto end;
    }


end:
    _SET_ELEMENT(ctx, pkt, (uintptr_t)pkt);
    _SET_ELEMENT(ctx, destination, (uintptr_t)destination);
    return res;

}