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

#define ICMPV6_RPL_CTRL     (155)   /**< RPL control message */

#define GNRC_RPL_DIS_SOLICITED_INFO_LENGTH  (19)
#define GNRC_RPL_DIS_SOLICITED_INFO_FLAG_V  (1 << 7)
#define GNRC_RPL_DIS_SOLICITED_INFO_FLAG_I  (1 << 6)
#define GNRC_RPL_DIS_SOLICITED_INFO_FLAG_D  (1 << 5)

#define GNRC_RPL_ICMPV6_CODE_DIS (0x00)

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

typedef struct {
    uint8_t type;       /**< Option Type */
    uint8_t length;     /**< Option Length, does not include the first two byte */
} gnrc_rpl_internal_opt_t;

typedef struct  {
    uint8_t type;                /**< Option Type: 0x07 */
    uint8_t length;              /**< Option Length: 19 bytes*/
    uint8_t instance_id;         /**< id of the instance */
    uint8_t VID_flags;           /**< V|I|D predicate options followed by 5 bit unused flags */
    ipv6_addr_t dodag_id;        /**< DODAG ID predicate */
    uint8_t version_number;      /**< version number of the DODAG */
} gnrc_rpl_internal_opt_dis_solicited_t;
/******************************************************************************************************/
static gnrc_pktsnip_t *_dis_solicited_opt_build(gnrc_pktsnip_t *pkt,
                                                gnrc_rpl_internal_opt_dis_solicited_t *opt)
{
    gnrc_pktsnip_t *opt_snip;
    size_t snip_size = sizeof(gnrc_rpl_opt_dis_solicited_t);

    if ((opt_snip = bpf_gnrc_pktbuf_add((uintptr_t)pkt, NULL, snip_size,
                                    GNRC_NETTYPE_UNDEF)) == NULL) {
        // const char msg[] = "RPL-DIS: BUILD SOLICITED OPT - no space left in packet buffer\n";
        // f12r_vm_printf(msg);
        bpf_gnrc_pktbuf_release(pkt);
        return NULL;
    }

    gnrc_rpl_opt_dis_solicited_t *solicited_information;
    solicited_information = _GET_ELEMENT(opt_snip, data);
    _SET_ELEMENT(solicited_information, type, GNRC_RPL_OPT_SOLICITED_INFO);
    _SET_ELEMENT(solicited_information, length, GNRC_RPL_DIS_SOLICITED_INFO_LENGTH);
    _SET_ELEMENT(solicited_information, instance_id, _GET_ELEMENT(opt, instance_id));
    _SET_ELEMENT(solicited_information, VID_flags, _GET_ELEMENT(opt, VID_flags));
    f12r_memcpy((void *)_GET_ELEMENT_POINTER(solicited_information, dodag_id),(void *) _GET_ELEMENT_POINTER(opt, dodag_id), sizeof(ipv6_addr_t));
    _SET_ELEMENT(solicited_information, version_number, _GET_ELEMENT(opt, version_number));

    return opt_snip;
}

/**
 * @brief   Send a DIS message in FC-based RPL protocol.
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
    uintptr_t options; /* double-ptr to options */
    uint32_t num_opts; /* number of options */
} dis_send_context_t;

int32_t send_dio(dis_send_context_t *ctx)
{
    gnrc_rpl_instance_t *inst = (gnrc_rpl_instance_t *) ctx->inst;
    ipv6_addr_t *destination = (ipv6_addr_t *)ctx->destination;
    gnrc_rpl_internal_opt_t **options = (gnrc_rpl_internal_opt_t **)ctx->options;

    gnrc_pktsnip_t *pkt = NULL, *tmp;
    gnrc_rpl_dis_t *dis;

    int8_t res = OK;   

    /* No options provided to be attached to the DIS, so we PadN 2 bytes */
    if (options == NULL || ctx->num_opts == 0) {
        gnrc_pktsnip_t *opt_snip;
        uint32_t snip_size = 0;
        /* The DIS is too small so that wireshark complains about an incorrect
            * ethernet frame check sequence.
            * To trick it we PadN 2 additional bytes, i.e. 4 bytes in sum. */
        uint8_t padding[] = {
            GNRC_RPL_OPT_PADN,  /* Option Type */
            0x02,               /* Number of extra padding bytes */
            0x00, 0x00
        };

        snip_size = sizeof(padding);
        if ((opt_snip = bpf_gnrc_pktbuf_add((uintptr_t) NULL, NULL, snip_size,
                                        GNRC_NETTYPE_UNDEF)) == NULL) {
            // const char msg[] = "RPL-DIS: BUILD PadN OPT - no space left in packet buffer\n";
            // f12r_vm_printf(msg);
            bpf_gnrc_pktbuf_release(pkt);
            res = ERROR;
            goto end;
        }
        f12r_memcpy(opt_snip->data, padding, snip_size);
        pkt = opt_snip;
    }
    else {
        if (options == NULL){
            res = ERROR;
            goto end;
        }
        for (size_t i = 0; i < ctx->num_opts; ++i) {
            if (options[i]->type == GNRC_RPL_OPT_SOLICITED_INFO) {
                if ((pkt = _dis_solicited_opt_build(pkt, (gnrc_rpl_internal_opt_dis_solicited_t *)options[i])) == NULL) {
                    // const char msg[] = "RPL-DIS: Send DIS - Can't build option\n";
                    // f12r_vm_printf(msg); 
                    res = ERROR;
                    goto end;
                }
            }
        }
    }

    if ((tmp = bpf_gnrc_pktbuf_add((uintptr_t)pkt, NULL, sizeof(gnrc_rpl_dis_t), GNRC_NETTYPE_UNDEF)) == NULL) {
        // const char msg[] = "RPL-DIS: Send DIS - no space left in packet buffer\n";
        // f12r_vm_printf(msg);
        bpf_gnrc_pktbuf_release(pkt);
        res = ERROR;
        goto end;
    }
    pkt = tmp;
    dis = (gnrc_rpl_dis_t *)_GET_ELEMENT(pkt,data);
    _SET_ELEMENT(dis, flags, 0);
    _SET_ELEMENT(dis, reserved, 0);

    if ((tmp = bpf_gnrc_icmpv6_build((uintptr_t) pkt, ICMPV6_RPL_CTRL, GNRC_RPL_ICMPV6_CODE_DIS,
                                 sizeof(icmpv6_hdr_t))) == NULL) {
        // const char msg[] = "RPL-DIS: Send DIS - no space left in packet buffer\n";
        // f12r_vm_printf(msg);
        bpf_gnrc_pktbuf_release(pkt);
        res = ERROR;
        goto end;
    }
    pkt = tmp;
    gnrc_rpl_dodag_t *dodag = (gnrc_rpl_dodag_t *)_GET_ELEMENT_POINTER(inst, dodag);
    bpf_gnrc_rpl_send((uintptr_t)pkt, KERNEL_PID_UNDEF, (uintptr_t)NULL, 
                    (uintptr_t)destination, 
                    (uintptr_t) (inst? (ipv6_addr_t *)_GET_ELEMENT_POINTER(dodag, dodag_id): NULL));

    end:
        return res;
    
}