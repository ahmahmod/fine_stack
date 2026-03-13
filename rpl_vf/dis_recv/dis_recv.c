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


/* RPL OPTIONS */
#define GNRC_RPL_OPT_PAD1                 (0)
#define GNRC_RPL_OPT_PADN                 (1)
#define GNRC_RPL_OPT_SOLICITED_INFO       (7)

#define GNRC_RPL_DIS_SOLICITED_INFO_LENGTH  (19)
#define GNRC_RPL_DIS_SOLICITED_INFO_FLAG_V  (1 << 7)
#define GNRC_RPL_DIS_SOLICITED_INFO_FLAG_I  (1 << 6)
#define GNRC_RPL_DIS_SOLICITED_INFO_FLAG_D  (1 << 5)

#define GNRC_RPL_LEAF_NODE (2)
#define GNRC_RPL_ICMPV6_CODE_DIS (0x00)

#define GNRC_RPL_REQ_DIO_OPT_DODAG_CONF_SHIFT       (0)
#define GNRC_RPL_REQ_DIO_OPT_DODAG_CONF             (1)
#define GNRC_RPL_REQ_DIO_OPT_PREFIX_INFO_SHIFT      (1)
#define GNRC_RPL_REQ_DIO_OPT_PREFIX_INFO            (1 << GNRC_RPL_REQ_DIO_OPT_PREFIX_INFO_SHIFT)
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

#define CONFIG_GNRC_RPL_DEFAULT_INSTANCE (0)
/******************************************************************************************************/
static bool parse_options(int msg_type, gnrc_rpl_instance_t *inst, gnrc_rpl_opt_t *opt,
                           uint16_t len, ipv6_addr_t *src, uint32_t *included_opts)
{
    /* Variables */
    uint16_t len_parsed = 0;
    uint32_t parsed_opts = 0;
    gnrc_rpl_dodag_t *dodag = (gnrc_rpl_dodag_t *) _GET_ELEMENT_POINTER(inst, dodag);
    eui64_t iid;

    /* *included_opts = 0; */
    bpf_vm_pointer_set_element((uint8_t *)included_opts, 0, 0, sizeof(uint32_t));

    // const char msg1[] = "RPL-Parse Options: PAD1 option parsed\n";
    // const char msg2[] = "RPL-Parse Options: PADN option parsed\n";
    // const char msg5[] = "RPL-Parse Options: SOLICITED INFO option parsed\n";

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
            
            case (GNRC_RPL_OPT_SOLICITED_INFO):
                // f12r_vm_printf(msg5);
                parsed_opts |= ((uint32_t)1) << GNRC_RPL_OPT_SOLICITED_INFO;
                gnrc_rpl_opt_dis_solicited_t *sol = (gnrc_rpl_opt_dis_solicited_t *)opt;

                /* check expected length */
                if (_GET_ELEMENT(sol, length) != GNRC_RPL_DIS_SOLICITED_INFO_LENGTH) {
                    return false;
                }

                /* check the DODAG Version */
                if ((_GET_ELEMENT(sol, VID_flags) & GNRC_RPL_DIS_SOLICITED_INFO_FLAG_V) && 
                    (_GET_ELEMENT(sol, version_number) != _GET_ELEMENT(dodag, version))){
                    return false;
                }

                /* check the Instance ID */
                if ((_GET_ELEMENT(sol, VID_flags) & GNRC_RPL_DIS_SOLICITED_INFO_FLAG_I) &&
                    (((uint8_t)_GET_ELEMENT(sol, instance_id)) != ((uint8_t)_GET_ELEMENT(inst, id))) ){
                    return false;
                }

                /* check the DODAG ID */
                if (_GET_ELEMENT(sol, VID_flags) & GNRC_RPL_DIS_SOLICITED_INFO_FLAG_D){
                    if (f12r_memcmp((void *)_GET_ELEMENT_POINTER(sol, dodag_id), (void *)_GET_ELEMENT_POINTER(dodag, dodag_id),
                        sizeof(ipv6_addr_t)) != 0){
                        return false;
                    }
                }
                break;
        }

        len_parsed += _GET_ELEMENT(opt, length) + sizeof(gnrc_rpl_opt_t);
        opt = (gnrc_rpl_opt_t *)(((uint8_t *)(opt + 1)) + _GET_ELEMENT(opt, length));
    }

    *included_opts = parsed_opts;
    
    return true;
   
}
/******************************************************************************************************/
typedef struct {
    uintptr_t inst; /* ptr to the instance message */
    uintptr_t destination; /* ptr to destanation address */
} send_dio_context_t;

typedef struct {
    uintptr_t dis; /* ptr to the DIS message */
    uintptr_t src; /* ptr to src address */
    uintptr_t dst; /* ptr to dst address */
    int16_t iface; /* iface number */
    uint16_t len;
} dis_recv_context_t;


#define FC_HOOK_RPL_SEND_DIO (7)
/**
 * @brief   Receive the DIS message in FC-based RPL protocol.
 * @pre @p  pkt != NULL
 *
 * @param[in] pkt       A gnrc_pktsnip_t pointer to the pkt sent by the application.
 *                      It represents the context of the FC.
 *                      
 *
 * @return  OK, in case of successful handling
 * @return  ERROR, in case of any error which stop the processing
 */

int32_t dis_recv(dis_recv_context_t *ctx)
{
    kernel_pid_t iface = (kernel_pid_t) ctx->iface;
    gnrc_rpl_dis_t *dis = (gnrc_rpl_dis_t *)ctx->dis;
    ipv6_addr_t *src = (ipv6_addr_t *)ctx->src;
    ipv6_addr_t *dst = (ipv6_addr_t *)ctx->dst;

    uint16_t len = ctx->len - sizeof(gnrc_rpl_dis_t) - sizeof(icmpv6_hdr_t);
    gnrc_rpl_dodag_t *dodag;
    gnrc_rpl_instance_t *instance;
    int8_t res = OK;

    if (bpf_ipv6_addr_is_multicast(dst)){
        trickle_t *trickle;
        // Assume we have only one DODAG instance
        instance = (gnrc_rpl_instance_t *)bpf_gnrc_rpl_get_instance_by_index(CONFIG_GNRC_RPL_DEFAULT_INSTANCE);
        dodag = (gnrc_rpl_dodag_t *)_GET_ELEMENT_POINTER(instance, dodag);
        if ((_GET_ELEMENT(instance, state) != 0)
            // a leaf node should only react to unicast DIS
            && (_GET_ELEMENT(dodag, node_status) != GNRC_RPL_LEAF_NODE)) {
                trickle = ( trickle_t *)_GET_ELEMENT_POINTER(dodag, trickle);
                bpf_trickle_reset_timer((uintptr_t)trickle);
        }
    }
    else {
        // Assume we have only one DODAG instance
        instance = (gnrc_rpl_instance_t *)bpf_gnrc_rpl_get_instance_by_index(CONFIG_GNRC_RPL_DEFAULT_INSTANCE);
        dodag = (gnrc_rpl_dodag_t *)_GET_ELEMENT_POINTER(instance, dodag);

        gnrc_rpl_opt_t *opts = (gnrc_rpl_opt_t *) (dis + 1);
        uint32_t included_opts = 0;
        if (_GET_ELEMENT(instance, state) != 0){       
            if(!parse_options(GNRC_RPL_ICMPV6_CODE_DIS, instance, opts, len, src, &included_opts)) {
                // const char msg[] = "RPL-DIS: DIS option parsing error - skip processing the DIS\n";
                // f12r_vm_printf(msg);
                res = ERROR;
                goto end;
            }

            uint8_t dio_opts = (uint8_t)_GET_ELEMENT(dodag, dio_opts);
            _SET_ELEMENT(dodag, dio_opts, dio_opts | GNRC_RPL_REQ_DIO_OPT_DODAG_CONF);

            send_dio_context_t dio_send_ctx = {.inst = (uintptr_t)instance, .destination= (uintptr_t)src};
            bpf_trigger_hook(FC_HOOK_RPL_SEND_DIO, (uintptr_t)&dio_send_ctx, sizeof(dio_send_ctx));
        }
    }

    end:
        return res;
}