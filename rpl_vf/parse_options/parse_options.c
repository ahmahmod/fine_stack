#include <stdint.h>

#include "bpfapi/helpers.h"
#include "bpfapi/helpers_net.h"
#include "net/gnrc.h"
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

#define _GET_ELEMENT(ptr, member) \
    ((typeof(((TYPEOF_POINTER(ptr)*)0)->member)) \
        bpf_vm_pointer_get_element((uint8_t *)ptr, \
            offsetof(TYPEOF_POINTER(ptr), member), \
            SIZEOF_MEMBER(TYPEOF_POINTER(ptr), member)))

#define _GET_ELEMENT_POINTER(ptr, member) \
    bpf_vm_pointer_get_element_pointer((uint8_t *)ptr, offsetof(TYPEOF_POINTER(ptr), member))
    //((uint8_t *) (uintptr_t)ptr + (offsetof(TYPEOF_POINTER(ptr), member)))

 #define _GET_NET_ELEMENT(ptr, member) \
    bpf_vm_pointer_get_element((uint8_t *)ptr, offsetof(TYPEOF_POINTER(ptr), member), SIZEOF_MEMBER(TYPEOF_POINTER(ptr), member))

#define _SET_ELEMENT(ptr, member, value) \
    bpf_vm_pointer_set_element((uint8_t *)ptr, offsetof(TYPEOF_POINTER(ptr), member), value, SIZEOF_MEMBER(TYPEOF_POINTER(ptr), member))


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
#define GNRC_RPL_INFINITE_RANK (0xFFFF)


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
/******************************************************************************************************/

typedef struct {
    uint32_t msg_type;   /* Type of Control message */
    uintptr_t inst;   /* ptr to src address */
    uintptr_t opt;   /* ptr to message's options */
    uintptr_t src;   /* ptr to src address */
    uintptr_t included_opts;  /* ptr to options */
    uint16_t len;   /* Message length*/
} context_t;


int32_t parse_options(context_t *ctx)
{
    /* Context */
    gnrc_rpl_instance_t *inst = (gnrc_rpl_instance_t *)ctx->inst;
    gnrc_rpl_opt_t *opt = (gnrc_rpl_opt_t *)ctx->opt;     
    ipv6_addr_t *src = (ipv6_addr_t *)ctx->src;
    uint32_t *included_opts = (uint32_t *)ctx->included_opts;

    /* Variables */
    uint16_t len_parsed = 0;
    uint32_t parsed_opts = 0;
    gnrc_rpl_opt_target_t *first_target = NULL;
    gnrc_rpl_dodag_t *dodag = (gnrc_rpl_dodag_t *) _GET_ELEMENT_POINTER(inst, dodag);
    eui64_t iid;

    /* *included_opts = 0; */
    bpf_vm_pointer_set_element((uint8_t *)included_opts, 0, 0, sizeof(uint32_t));

    const char msg1[] = "RPL-Parse Options: PAD1 option parsed\n";
    const char msg2[] = "RPL-Parse Options: PADN option parsed\n";
    const char msg3[] = "RPL-Parse Options: DODAG CONF DIO option parsed\n";
    const char msg4[] = "RPL-Parse Options: PREFIX INFO option parsed\n";
    const char msg5[] = "RPL-Parse Options: SOLICITED INFO option parsed\n";
    const char msg6[] = "RPL-Parse Options: RPL TARGET INFO DAO option parsed\n";
    const char msg7[] = "RPL-Parse Options: RPL TRANSIT INFO DAO option parsed\n";
    const char msga[] = "ERROR netif\n"; 
    const char msgb[] = "ERROR iid\n";         

    while (len_parsed < ctx->len) {
        switch (_GET_ELEMENT(opt, type)){
            case (GNRC_RPL_OPT_PAD1):
                //DEBUG("RPL: PAD1 option parsed\n");
                f12r_vm_printf(msg1);
                parsed_opts |= ((uint32_t)1) << GNRC_RPL_OPT_PAD1;
                len_parsed += 1;
                opt = (gnrc_rpl_opt_t *)(((uint8_t *)opt) + 1);
                continue; 
            
            case (GNRC_RPL_OPT_PADN):
                //DEBUG("RPL: PADN option parsed\n");
                f12r_vm_printf(msg2);
                parsed_opts |= ((uint32_t)1) << GNRC_RPL_OPT_PADN;
                break;
            
            case (GNRC_RPL_OPT_DODAG_CONF):
                // DEBUG("RPL: DODAG CONF DIO option parsed\n");
                f12r_vm_printf(msg3);
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
                f12r_vm_printf(msg4);
                parsed_opts |= ((uint32_t)1) << GNRC_RPL_OPT_PREFIX_INFO;
                gnrc_rpl_opt_prefix_info_t *pi = (gnrc_rpl_opt_prefix_info_t *)opt;

                // if (!IS_ACTIVE(CONFIG_GNRC_RPL_WITHOUT_PIO)) {
                //     dodag->dio_opts |= GNRC_RPL_REQ_DIO_OPT_PREFIX_INFO;
                // }

                /* check for the auto address-configuration flag */
                //gnrc_netif_t *netif = gnrc_netif_get_by_pid(dodag->iface);
                gnrc_netif_t *netif = (gnrc_netif_t *) bpf_gnrc_netif_get_by_pid(_GET_ELEMENT(dodag, iface));
                if (netif == NULL){
                    f12r_vm_printf(msga);
                    return false;
                }

                if ((bpf_gnrc_netif_ipv6_get_iid(netif, &iid) < 0) && !(_GET_ELEMENT(pi, LAR_flags) & GNRC_RPL_PREFIX_AUTO_ADDRESS_BIT)){
                    f12r_vm_printf(msgb);
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
            
            case (GNRC_RPL_OPT_SOLICITED_INFO):
                f12r_vm_printf(msg5);
                parsed_opts |= ((uint32_t)1) << GNRC_RPL_OPT_SOLICITED_INFO;
                gnrc_rpl_opt_dis_solicited_t *sol = (gnrc_rpl_opt_dis_solicited_t *)opt;

                /* check expected length */
                if (_GET_ELEMENT(sol, length) != GNRC_RPL_DIS_SOLICITED_INFO_LENGTH) {
                    //DEBUG("RPL: RPL SOLICITED INFO option, unexpected length: %d\n", sol->length);
                    return false;
                }

                /* check the DODAG Version */
                if ((_GET_ELEMENT(sol, VID_flags) & GNRC_RPL_DIS_SOLICITED_INFO_FLAG_V) && 
                    (_GET_ELEMENT(sol, version_number) != _GET_ELEMENT(dodag, version))){
                    //DEBUG("RPL: RPL SOLICITED INFO option, ignore DIS cause: DODAG Version mismatch\n");
                    return false;
                }

                /* check the Instance ID */
                //if ((sol->VID_flags & GNRC_RPL_DIS_SOLICITED_INFO_FLAG_I) && (sol->instance_id != inst->id)) {
                if ((_GET_ELEMENT(sol, VID_flags) & GNRC_RPL_DIS_SOLICITED_INFO_FLAG_I) &&
                    (((uint8_t)_GET_ELEMENT(sol, instance_id)) != ((uint8_t)_GET_ELEMENT(inst, id))) ){
                    //DEBUG("RPL: RPL SOLICITED INFO option, ignore DIS cause: InstanceID mismatch\n")
                    return false;
                }

                /* check the DODAG ID */
                //if (sol->VID_flags & GNRC_RPL_DIS_SOLICITED_INFO_FLAG_D) {
                if (_GET_ELEMENT(sol, VID_flags) & GNRC_RPL_DIS_SOLICITED_INFO_FLAG_D){
                    //if (memcmp(&sol->dodag_id, &inst->dodag.dodag_id, sizeof(ipv6_addr_t)) != 0) {
                    if (f12r_memcmp(_GET_ELEMENT_POINTER(sol, dodag_id), _GET_ELEMENT_POINTER(dodag, dodag_id),
                        sizeof(ipv6_addr_t)) != 0){
                        //DEBUG("RPL: RPL SOLICITED INFO option, ignore DIS cause: DODAGID mismatch\n");
                        return false;
                    }
                }
                break;
            case (GNRC_RPL_OPT_TARGET):
                //DEBUG("RPL: RPL TARGET DAO option parsed\n");
                f12r_vm_printf(msg6);
                parsed_opts |= ((uint32_t)1) << GNRC_RPL_OPT_TARGET;
                gnrc_rpl_opt_target_t *target = (gnrc_rpl_opt_target_t *)opt;
                if (first_target == NULL) {
                    first_target = target;
                }

                /*DEBUG("RPL: adding FT entry %s/%d\n",
                    ipv6_addr_to_str(addr_str, &(target->target), (unsigned)sizeof(addr_str)),
                    target->prefix_length);*/

                /*gnrc_ipv6_nib_ft_del(&(target->target), target->prefix_length);*/
                bpf_gnrc_ipv6_nib_ft_del(_GET_ELEMENT_POINTER(target, target), _GET_ELEMENT(target, prefix_length));
                bpf_gnrc_ipv6_nib_ft_add(_GET_ELEMENT_POINTER(target, target), _GET_ELEMENT(target, prefix_length),
                                        src, _GET_ELEMENT(dodag, iface), 
                                        _GET_ELEMENT(dodag, default_lifetime) * _GET_ELEMENT(dodag, lifetime_unit));
                break;

            case (GNRC_RPL_OPT_TRANSIT):
                //DEBUG("RPL: RPL TRANSIT INFO DAO option parsed\n");
                f12r_vm_printf(msg7);
                parsed_opts |= ((uint32_t)1) << GNRC_RPL_OPT_TRANSIT;
                gnrc_rpl_opt_transit_t *transit = (gnrc_rpl_opt_transit_t *)opt;
                
                if (first_target == NULL) {
                    break;
                }

                do {
                    bpf_gnrc_ipv6_nib_ft_del(_GET_ELEMENT_POINTER(first_target, target), _GET_ELEMENT(first_target, prefix_length));
                    bpf_gnrc_ipv6_nib_ft_add(_GET_ELEMENT_POINTER(first_target, target), _GET_ELEMENT(first_target, prefix_length),
                                            src, _GET_ELEMENT(dodag, iface), 
                                            _GET_ELEMENT(transit, path_lifetime) * _GET_ELEMENT(dodag, lifetime_unit));

                    first_target = (gnrc_rpl_opt_target_t *)(((uint8_t *)(first_target)) +
                                                            sizeof(gnrc_rpl_opt_t) +
                                                            first_target->length);
                } while (_GET_ELEMENT(first_target, type) == GNRC_RPL_OPT_TARGET);

                first_target = NULL;
                break;
        }
        len_parsed += _GET_ELEMENT(opt, length) + sizeof(gnrc_rpl_opt_t);
        opt = (gnrc_rpl_opt_t *)(((uint8_t *)(opt + 1)) + _GET_ELEMENT(opt, length));
    }

    //parsed_opts |= bpf_vm_pointer_get_element((uint8_t *)included_opts, 0, sizeof(uint32_t));
    bpf_vm_pointer_set_element((uint8_t *)included_opts, 0, parsed_opts, sizeof(uint32_t));
    //included_opts |= parse_options;
    
    return true;
   
}