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
    ((TYPEOF_MEMBER(TYPEOF_POINTER(ptr), member)*) \
    (uintptr_t) ((uint8_t *) ptr + (offsetof(TYPEOF_POINTER(ptr), member))) )   

#define _SET_ELEMENT(ptr, member, value) \
    (*(typeof(((TYPEOF_POINTER(ptr) *)0)->member) *)((uint8_t *)(ptr) + offsetof(TYPEOF_POINTER(ptr), member)) \
    = (typeof(((TYPEOF_POINTER(ptr) *)0)->member))(value))


/* Describe the needed structs */
/******************************************************************************************************/
typedef struct gnrc_rpl_dodag gnrc_rpl_dodag_t;
typedef struct gnrc_rpl_parent gnrc_rpl_parent_t;
typedef struct gnrc_rpl_instance gnrc_rpl_instance_t;

#define GNRC_RPL_OPT_DODAG_CONF_LEN         (14)
#define GNRC_RPL_OPT_PREFIX_INFO_LEN        (30)
#define GNRC_RPL_OPT_TARGET_LEN             (18)
#define GNRC_RPL_OPT_TRANSIT_INFO_LEN       (4)
/** @} */

#define GNRC_RPL_DAO_D_BIT                  (1 << 6)
#define GNRC_RPL_DAO_K_BIT                  (1 << 7)
/** @} */

#define GNRC_RPL_DAO_ACK_D_BIT              (1 << 7)
/** @} */

#define GNRC_RPL_REQ_DIO_OPT_DODAG_CONF_SHIFT       (0)
#define GNRC_RPL_REQ_DIO_OPT_DODAG_CONF             (1)
#define GNRC_RPL_REQ_DIO_OPT_PREFIX_INFO_SHIFT      (1)
#define GNRC_RPL_REQ_DIO_OPT_PREFIX_INFO            (1 << GNRC_RPL_REQ_DIO_OPT_PREFIX_INFO_SHIFT)

/* RPL OPTIONS */
#define GNRC_RPL_OPT_PAD1                 (0)
#define GNRC_RPL_OPT_PADN                 (1)
#define GNRC_RPL_OPT_DAG_METRIC_CONTAINER (2)
#define GNRC_RPL_OPT_ROUTE_INFO           (3)
#define GNRC_RPL_OPT_DODAG_CONF           (4)
#define GNRC_RPL_OPT_TARGET               (5)
#define GNRC_RPL_OPT_TRANSIT              (6)
#define GNRC_RPL_OPT_SOLICITED_INFO       (7)
#define GNRC_RPL_OPT_PREFIX_INFO          (8)
#define GNRC_RPL_OPT_TARGET_DESC          (9)

/*
 * @brief DIS Solicited Information option (numbers)
 * @see <a href="https://tools.ietf.org/html/rfc6550#section-6.7.9">
 *          RFC6550, section 6.7.9, Solicited Information
 *      </a>
 *  @{
 */
#define GNRC_RPL_DIS_SOLICITED_INFO_LENGTH  (19)
#define GNRC_RPL_DIS_SOLICITED_INFO_FLAG_V  (1 << 7)
#define GNRC_RPL_DIS_SOLICITED_INFO_FLAG_I  (1 << 6)
#define GNRC_RPL_DIS_SOLICITED_INFO_FLAG_D  (1 << 5)

#define GNRC_RPL_INSTANCES_NUMOF            (1)
#define GNRC_RPL_LEAF_NODE (2)
#define GNRC_RPL_ICMPV6_CODE_DIO (0x01)
#define GNRC_RPL_INFINITE_RANK (0xFFFF)
#define GNRC_RPL_MOP_SHIFT                  (3)
#define GNRC_RPL_SHIFTED_MOP_MASK           (0x7)
#define GNRC_RPL_GROUNDED_SHIFT             (7)
#define GNRC_RPL_PRF_MASK                   (0x7)
#define GNRC_RPL_MSG_TYPE_TRICKLE_MSG         (0x0901)


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


#define CONFIG_GNRC_RPL_WITHOUT_PIO (0)
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

    /* *included_opts = 0; */
    bpf_vm_pointer_set_element((uint8_t *)included_opts, 0, 0, sizeof(uint32_t));

    // const char msg1[] = "RPL-Parse Options: PAD1 option parsed\n";
    // const char msg2[] = "RPL-Parse Options: PADN option parsed\n";
    // const char msg3[] = "RPL-Parse Options: DODAG CONF DIO option parsed\n";
    // const char msg4[] = "RPL-Parse Options: PREFIX INFO option parsed\n";

    while (len_parsed < len) {
        switch (_GET_ELEMENT(opt, type)){
            case (GNRC_RPL_OPT_PAD1):
                // DEBUG("RPL: PAD1 option parsed\n");
                // f12r_vm_printf(msg1);
                parsed_opts |= ((uint32_t)1) << GNRC_RPL_OPT_PAD1;
                len_parsed += 1;
                opt = (gnrc_rpl_opt_t *)(((uint8_t *)opt) + 1);
                continue; 
            
            case (GNRC_RPL_OPT_PADN):
                // DEBUG("RPL: PADN option parsed\n");
                // f12r_vm_printf(msg2);
                parsed_opts |= ((uint32_t)1) << GNRC_RPL_OPT_PADN;
                break;
            
            case (GNRC_RPL_OPT_DODAG_CONF):
                // DEBUG("RPL: DODAG CONF DIO option parsed\n");
                // f12r_vm_printf(msg3);
                parsed_opts |= ((uint32_t)1) << GNRC_RPL_OPT_DODAG_CONF;

                // dodag->dio_opts |= GNRC_RPL_REQ_DIO_OPT_DODAG_CONF;
                _SET_ELEMENT(dodag, dio_opts, _GET_ELEMENT(dodag, dio_opts) | GNRC_RPL_REQ_DIO_OPT_DODAG_CONF);           
                
                gnrc_rpl_opt_dodag_conf_t *dc = (gnrc_rpl_opt_dodag_conf_t *)opt;
                gnrc_rpl_of_t *of = bpf_gnrc_rpl_get_of_for_ocp(bpf_byteorder_ntohs(_GET_ELEMENT(dc, ocp)));
                if (of != NULL) {
                    //inst->of = of;
                    _SET_ELEMENT(inst, of, (uintptr_t) of);
                }
                else {
                    //DEBUG("RPL: Unsupported OCP 0x%02x\n", byteorder_ntohs(dc->ocp));
                    // inst->of = bpf_gnrc_rpl_get_of_for_ocp(GNRC_RPL_DEFAULT_OCP);
                    _SET_ELEMENT(inst, of, (uintptr_t) bpf_gnrc_rpl_get_of_for_ocp(0)); // Default OCP
                }
                
                // dodag->dio_interval_doubl = dc->dio_int_doubl;
                _SET_ELEMENT(dodag, dio_interval_doubl, _GET_ELEMENT(dc, dio_int_doubl));
                // dodag->dio_min = dc->dio_int_min;
                _SET_ELEMENT(dodag, dio_min, _GET_ELEMENT(dc, dio_int_min));
                // dodag->dio_redun = dc->dio_redun;
                _SET_ELEMENT(dodag, dio_redun, _GET_ELEMENT(dc, dio_redun));
                // inst->max_rank_inc = byteorder_ntohs(dc->max_rank_inc);
                uint16_t max_rank_inc1 = bpf_byteorder_ntohs(_GET_ELEMENT(dc, dio_redun));
                _SET_ELEMENT(inst, max_rank_inc, max_rank_inc1);
                // inst->min_hop_rank_inc = byteorder_ntohs(dc->min_hop_rank_inc);
                uint16_t min_hop_rank_inc1 = bpf_byteorder_ntohs(_GET_ELEMENT(dc, min_hop_rank_inc));
                _SET_ELEMENT(inst, min_hop_rank_inc, min_hop_rank_inc1);
                // dodag->default_lifetime = dc->default_lifetime;
                _SET_ELEMENT(dodag, default_lifetime, _GET_ELEMENT(dc, default_lifetime));
                // dodag->lifetime_unit = byteorder_ntohs(dc->lifetime_unit);
                uint16_t lifetime_unit1 = bpf_byteorder_ntohs(_GET_ELEMENT(dc, lifetime_unit));
                _SET_ELEMENT(dodag, lifetime_unit, lifetime_unit1);
                // dodag->trickle.Imin = (1 << dodag->dio_min);
                _SET_ELEMENT((trickle_t *)_GET_ELEMENT_POINTER(dodag, trickle), Imin, ((1 << _GET_ELEMENT(dodag, dio_min))));
                // dodag->trickle.Imax = dodag->dio_interval_doubl;
                _SET_ELEMENT((trickle_t *)_GET_ELEMENT_POINTER(dodag, trickle), Imax, _GET_ELEMENT(dodag, dio_interval_doubl));
                // dodag->trickle.k = dodag->dio_redun;
                _SET_ELEMENT((trickle_t *)_GET_ELEMENT_POINTER(dodag, trickle), k, _GET_ELEMENT(dodag, dio_redun));
                break;

            case (GNRC_RPL_OPT_PREFIX_INFO):
                // f12r_vm_printf(msg4);
                parsed_opts |= ((uint32_t)1) << GNRC_RPL_OPT_PREFIX_INFO;
                gnrc_rpl_opt_prefix_info_t *pi = (gnrc_rpl_opt_prefix_info_t *)opt;

                if (!CONFIG_GNRC_RPL_WITHOUT_PIO) {
                    //dodag->dio_opts |= GNRC_RPL_REQ_DIO_OPT_PREFIX_INFO;
                    _SET_ELEMENT(dodag, dio_opts, _GET_ELEMENT(dodag, dio_opts) | GNRC_RPL_REQ_DIO_OPT_PREFIX_INFO);
                }

                /* check for the auto address-configuration flag */
                //gnrc_netif_t *netif = gnrc_netif_get_by_pid(dodag->iface);
                gnrc_netif_t *netif = (gnrc_netif_t *) bpf_gnrc_netif_get_by_pid(_GET_ELEMENT(dodag, iface));
                if (netif == NULL){
                    // f12r_vm_printf(msga);
                    return false;
                }

                if ((bpf_gnrc_netif_ipv6_get_iid(netif, &iid) < 0) && !(_GET_ELEMENT(pi, LAR_flags) & GNRC_RPL_PREFIX_AUTO_ADDRESS_BIT)){
                    // f12r_vm_printf(msgb);
                    break;
                }
                
                //ipv6_addr_set_aiid(&pi->prefix, iid.uint8);
                bpf_ipv6_addr_set_aiid(_GET_ELEMENT_POINTER(pi, prefix), iid.uint8);
                /* TODO: find a way to do this with DAD (i.e. state != VALID) */
                bpf_gnrc_netif_ipv6_addr_add_internal(netif, _GET_ELEMENT_POINTER(pi, prefix), _GET_ELEMENT(pi, prefix_len), 
                                                        GNRC_NETIF_IPV6_ADDRS_FLAGS_STATE_VALID);
                
                /* set lifetimes */
                uint32_t valid_lifetime = _GET_ELEMENT(pi, valid_lifetime);
                uint32_t pref_lifetime = _GET_ELEMENT(pi, pref_lifetime);
                bpf_gnrc_ipv6_nib_pl_set(_GET_ELEMENT(netif, pid),  _GET_ELEMENT_POINTER(pi, prefix), _GET_ELEMENT(pi, prefix_len),
                                        1000 * bpf_byteorder_ntohl(valid_lifetime),
                                        1000 * bpf_byteorder_ntohl(pref_lifetime));
                
                break;
        }
        
        len_parsed += _GET_ELEMENT(opt, length) + sizeof(gnrc_rpl_opt_t);
        opt = (gnrc_rpl_opt_t *)(((uint8_t *)(opt + 1)) + _GET_ELEMENT(opt, length));
    }

    *included_opts = parsed_opts;
    
    return true;
   
}
/******************************************************************************************************/

#define GNRC_RPL_COUNTER_MAX                 (255)
#define GNRC_RPL_COUNTER_LOWER_REGION        (127)
#define GNRC_RPL_COUNTER_SEQ_WINDOW          (16)
#define GNRC_RPL_COUNTER_INIT                (GNRC_RPL_COUNTER_MAX - GNRC_RPL_COUNTER_SEQ_WINDOW + 1)

static inline bool GNRC_RPL_COUNTER_GREATER_THAN_LOCAL(uint8_t A, uint8_t B)
{
    return (((A < B) && (GNRC_RPL_COUNTER_LOWER_REGION + 1 - B + A < GNRC_RPL_COUNTER_SEQ_WINDOW))
            || ((A > B) && (A - B < GNRC_RPL_COUNTER_SEQ_WINDOW)));
}

static inline bool GNRC_RPL_COUNTER_GREATER_THAN(uint8_t A, uint8_t B)
{
    return ((A > GNRC_RPL_COUNTER_LOWER_REGION) ? ((B > GNRC_RPL_COUNTER_LOWER_REGION) ?
                GNRC_RPL_COUNTER_GREATER_THAN_LOCAL(A, B) : 0) :
            ((B > GNRC_RPL_COUNTER_LOWER_REGION) ? 1 : GNRC_RPL_COUNTER_GREATER_THAN_LOCAL(A, B)));
}

static inline uint8_t GNRC_RPL_COUNTER_INCREMENT(uint8_t counter)
{
    return ((counter > GNRC_RPL_COUNTER_LOWER_REGION) ?
            ((counter == GNRC_RPL_COUNTER_MAX) ? counter = 0 : ++counter) :
            ((counter == GNRC_RPL_COUNTER_LOWER_REGION) ? counter = 0 : ++counter));
}



#define FC_HOOK_RPL_PARSE_OPTIONS (10)
#define FC_HOOK_RPL_SEND_DIS (6)
#define CONFIG_GNRC_RPL_DODAG_CONF_OPTIONAL_ON_JOIN (0)

typedef struct {
    uintptr_t inst; /* ptr to the instance */
    uintptr_t destination; /* ptr to dst address */
    uintptr_t options; /* double-ptr to options */
    uint32_t num_opts; /* number of options */
} send_dis_context_t;

typedef struct {
    uintptr_t dio; /* ptr to the DIS message */
    uintptr_t src; /* ptr to src address */
    uintptr_t dst; /* ptr to dst address */
    uintptr_t parent;
    uintptr_t inst;
    int16_t iface; /* iface number */
    int16_t gnrc_rpl_pid; /* rpl number */
    uint16_t len;
    int8_t ctx_res;
} dio_recv_context_t;


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

int32_t dio_recv(dio_recv_context_t *ctx)
{   
    gnrc_rpl_dio_t *dio = (gnrc_rpl_dio_t *)ctx->dio;
    ipv6_addr_t *src = (ipv6_addr_t *)ctx->src;
    ipv6_addr_t *dst = (ipv6_addr_t *)ctx->dst;
    gnrc_rpl_instance_t *inst = (gnrc_rpl_instance_t *) ctx->inst;
    gnrc_rpl_parent_t **ctx_parent = (gnrc_rpl_parent_t **) ctx->parent;
    int16_t iface = ctx->iface;
    int16_t gnrc_rpl_pid = ctx->gnrc_rpl_pid;
    uint16_t len = ctx->len;

    gnrc_rpl_dodag_t *dodag = NULL;
    gnrc_rpl_parent_t *parent = NULL;
    len -= (sizeof(gnrc_rpl_dio_t) + sizeof(icmpv6_hdr_t));
    int8_t res = OK;

    /********************************Add a neigh entry for the sender ***************************************************** */
    /* dst variable is not used, so use it to build the entry for the neigh (for storing mode is not neccessary) */
    //f12r_memcpy(dst, src, sizeof(ipv6_addr_t));
    f12r_memset(dst, 0, sizeof(ipv6_addr_t));
    bpf_ipv6_nc_from_addr(dst, iface);
    /********************************END ***************************************************** */
    
    if (bpf_gnrc_rpl_instance_add(_GET_ELEMENT(dio, instance_id), (uintptr_t)&inst)) {
        /* Change the instance to the new one for the next FC in the hook */
        // _SET_ELEMENT(ctx, inst, (uintptr_t)inst);
        ctx->inst = (uintptr_t)inst;

        gnrc_netif_t *netif;
        /* new instance and DODAG */
        if (bpf_byteorder_ntohs(_GET_ELEMENT(dio, rank)) == GNRC_RPL_INFINITE_RANK) {
            //DEBUG("RPL: ignore INFINITE_RANK DIO when we are not yet part of this DODAG\n");
            // const char msg[] = "RPL-DIO: ignore INFINITE_RANK DIO when we are not yet part of this DODAG\n";
            // f12r_vm_printf(msg);
            bpf_gnrc_rpl_instance_remove((uintptr_t)inst);
            res = ERROR;
            goto end;
        }

        //inst->mop = (dio->g_mop_prf >> GNRC_RPL_MOP_SHIFT) & GNRC_RPL_SHIFTED_MOP_MASK;
        _SET_ELEMENT(inst, mop, (_GET_ELEMENT(dio, g_mop_prf) >> GNRC_RPL_MOP_SHIFT & GNRC_RPL_SHIFTED_MOP_MASK));
        //inst->of = gnrc_rpl_get_of_for_ocp(GNRC_RPL_DEFAULT_OCP);
        _SET_ELEMENT(inst, of, (uintptr_t)bpf_gnrc_rpl_get_of_for_ocp(0)); // Default OCP
        bpf_gnrc_rpl_mode(1, _GET_ELEMENT(inst, mop)); /*1: set (0 :get), 1: for non-storing (0 for Storing)*/

        if (iface == KERNEL_PID_UNDEF) {
            // const char msg[] = "RPL-DIO: multicast state\n";
            // f12r_vm_printf(msg);
            netif = (gnrc_netif_t *)find_interface_with_rpl_mcast();
        }
        else {
            // const char msg[] = "RPL-DIO: non-multicast state\n";
            // f12r_vm_printf(msg);
            netif = (gnrc_netif_t *)bpf_gnrc_netif_get_by_pid(iface);
        }

        if (netif == NULL){
            // const char msg[] = "RPL-DIO: NULL netif\n";
            // f12r_vm_printf(msg);
            res = ERROR;
            goto end;
        }

        bool dodag_res = bpf_gnrc_rpl_dodag_init((uintptr_t)inst, (uintptr_t)_GET_ELEMENT_POINTER(dio, dodag_id), iface);
        if (!dodag_res){
            // const char msg[] = "RPL-DIO: Failed to init a dodag.\n";
            // f12r_vm_printf(msg);
            bpf_gnrc_rpl_instance_remove((uintptr_t)inst);
            res = ERROR;
            goto end;
        }

        dodag = _GET_ELEMENT_POINTER(inst, dodag);     

        parent = bpf_gnrc_rpl_parent_add_by_addr((uintptr_t)dodag, (uintptr_t)src, (uintptr_t)ctx_parent);
        if (!parent) {
            //DEBUG("RPL: Could not allocate new parent.\n");
            // const char msg[] = "RPL-DIO: Could not allocate new parent.\n";
            // f12r_vm_printf(msg);
            bpf_gnrc_rpl_instance_remove((uintptr_t)inst);
            res = ERROR;
            goto end;
        }
        
        //dodag->version = dio->version_number;
        _SET_ELEMENT(dodag, version, _GET_ELEMENT(dio, version_number));
        //dodag->grounded = dio->g_mop_prf >> GNRC_RPL_GROUNDED_SHIFT;
        _SET_ELEMENT(dodag, grounded, _GET_ELEMENT(dio, g_mop_prf) >> GNRC_RPL_GROUNDED_SHIFT);
        //dodag->prf = dio->g_mop_prf & GNRC_RPL_PRF_MASK;
        _SET_ELEMENT(dodag, prf, _GET_ELEMENT(dio, g_mop_prf) & GNRC_RPL_PRF_MASK);

        //parent->rank = byteorder_ntohs(dio->rank);
        _SET_ELEMENT(parent, rank, bpf_byteorder_ntohs(_GET_ELEMENT(dio, rank)));

        uint32_t included_opts = 0;
        gnrc_rpl_opt_t *opts = (gnrc_rpl_opt_t *)(dio + 1);

        if(!parse_options(GNRC_RPL_ICMPV6_CODE_DIO, inst, opts, len, src, &included_opts)) {
            //DEBUG("RPL: Error encountered during DIO option parsing - remove DODAG\n");
            // const char msg[] = "RPL-DIO: Error encountered during DIO option parsing - remove DODAG\n";
            // f12r_vm_printf(msg);
            bpf_gnrc_rpl_instance_remove((uintptr_t)inst);
            res = ERROR;
            goto end;
        }

        if (!(included_opts & (((uint32_t)1) << GNRC_RPL_OPT_DODAG_CONF))) {
            if (!CONFIG_GNRC_RPL_DODAG_CONF_OPTIONAL_ON_JOIN) {
                //DEBUG("RPL: DIO without DODAG_CONF option - remove DODAG and request new DIO\n");
                // const char msg[] = "RPL-DIO: DIO without DODAG_CONF option - remove DODAG and request new DIO\n";
                // f12r_vm_printf(msg);
                bpf_gnrc_rpl_instance_remove((uintptr_t)inst);
                /***************************************************************/
                send_dis_context_t send_dis_ctx = {.inst= (uintptr_t)NULL, .destination=(uintptr_t)src, .options=(uintptr_t)NULL,
                                                        .num_opts=0};
                bpf_trigger_hook(FC_HOOK_RPL_SEND_DIS, (uintptr_t)&send_dis_ctx, sizeof(send_dis_ctx));
                /***************************************************************/
                res = ERROR;
                goto end;   
            }
            else {
                //DEBUG("RPL: DIO without DODAG_CONF option - use default trickle parameters\n");
                // const char msg[] = "RPL-DIO: DIO without DODAG_CONF option - use default trickle parameters\n";
                // f12r_vm_printf(msg);
                /***************************************************************/
                send_dis_context_t send_dis_ctx = {.inst= (uintptr_t)NULL, .destination=(uintptr_t)src, 
                                                   .options=(uintptr_t)NULL,.num_opts=0};
                bpf_trigger_hook(FC_HOOK_RPL_SEND_DIS, (uintptr_t)&send_dis_ctx, sizeof(send_dis_ctx));
                /***************************************************************/
            }
        }

        /* if there was no address created manually or by a PIO on the interface,
         * leave this DODAG */
        if (bpf_gnrc_netif_ipv6_addr_match(netif, _GET_ELEMENT_POINTER(dodag, dodag_id)) < 0) {
            // const char msg[] = "RPL-DIO: no IPv6 address configured on interface to match the given dodag id.\n";
            // f12r_vm_printf(msg);
            bpf_gnrc_rpl_instance_remove((uintptr_t)inst);
            res = ERROR;
            goto end;
        }
        bpf_gnrc_rpl_delay_dao((uintptr_t) dodag, false);
        bpf_trickle_start_timer(gnrc_rpl_pid, (uintptr_t)_GET_ELEMENT_POINTER(dodag, trickle),
                        (1 << _GET_ELEMENT(dodag, dio_min)), _GET_ELEMENT(dodag, dio_interval_doubl), _GET_ELEMENT(dodag, dio_redun));
        
        bpf_gnrc_rpl_parent_update((uintptr_t)dodag, (uintptr_t)parent);
        ctx->ctx_res = ERROR;
        goto end;
    }
    else if (inst == NULL) {
        //DEBUG("RPL: Could not allocate a new instance.\n");
        // const char msg[] = "RPL-DIO: Could not allocate a new instance.\n";
        // f12r_vm_printf(msg);
        res = ERROR;
        goto end;
    }
    else {
        dodag = (gnrc_rpl_dodag_t *) _GET_ELEMENT_POINTER(inst, dodag);
        if (f12r_memcmp(_GET_ELEMENT_POINTER(dodag, dodag_id), _GET_ELEMENT_POINTER(dio, dodag_id), sizeof(ipv6_addr_t)) != 0) {
            //DEBUG("RPL: DIO received from another DODAG, but same instance - ignore\n");
            // const char msg[] = "RPL-DIO: DIO received from another DODAG, but same instance - ignore\n";
            // f12r_vm_printf(msg);
            res = ERROR;
            ctx->ctx_res = ERROR;
            goto end;
        }
        // _SET_ELEMENT(ctx, inst, (uintptr_t) inst); // Set the result to OK to continue the processing in the second FC (The result is initially -1)
        // _SET_ELEMENT(ctx, ctx_res, OK); // Set the result to OK to continue the processing in the second FC (The result is initially -1)
    }
    ctx->inst = (uintptr_t)inst;
    ctx->ctx_res = OK; // Set the result to OK to continue the processing in the second FC (The result is initially -1)
    
    end:
        return res;
        //return (uintptr_t) netif;
}