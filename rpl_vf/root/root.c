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

#define GNRC_RPL_REQ_DIO_OPT_DODAG_CONF_SHIFT       (0)
#define GNRC_RPL_REQ_DIO_OPT_DODAG_CONF             (1)
#define GNRC_RPL_REQ_DIO_OPT_PREFIX_INFO_SHIFT      (1)
#define GNRC_RPL_REQ_DIO_OPT_PREFIX_INFO            (1 << GNRC_RPL_REQ_DIO_OPT_PREFIX_INFO_SHIFT)
#define GNRC_RPL_INSTANCES_NUMOF            (1)
#define GNRC_RPL_INFINITE_RANK (0xFFFF)
#define GNRC_RPL_INFINITE_RANK (0xFFFF)

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
#define CONFIG_GNRC_RPL_DEFAULT_INSTANCE (0)
#define CONFIG_GNRC_RPL_DEFAULT_MAX_RANK_INCREASE (0)
#define CONFIG_GNRC_RPL_DEFAULT_MIN_HOP_RANK_INCREASE (256)
#define GNRC_RPL_DEFAULT_OCP (0)

#define GNRC_RPL_COUNTER_MAX                 (255)
#define GNRC_RPL_COUNTER_LOWER_REGION        (127)
#define GNRC_RPL_COUNTER_SEQ_WINDOW          (16)
#define GNRC_RPL_COUNTER_INIT                (GNRC_RPL_COUNTER_MAX - GNRC_RPL_COUNTER_SEQ_WINDOW + 1)

#define CONFIG_GNRC_RPL_DEFAULT_LIFETIME (5)
#define CONFIG_GNRC_RPL_LIFETIME_UNIT (60)

/**
 * @name Node Status
 * @{
 */
#define GNRC_RPL_NORMAL_NODE (0)
#define GNRC_RPL_ROOT_NODE (1)
#define GNRC_RPL_LEAF_NODE (2)
/** @} */

/**
 * @name Trickle parameters
 * @see <a href="https://tools.ietf.org/html/rfc6550#section-8.3.1">
 *          Trickle Parameters
 *      </a>
 * @{
 */
#define CONFIG_GNRC_RPL_DEFAULT_DIO_INTERVAL_DOUBLINGS (20)
#define CONFIG_GNRC_RPL_DEFAULT_DIO_INTERVAL_MIN (3)
#define CONFIG_GNRC_RPL_DEFAULT_DIO_REDUNDANCY_CONSTANT (10)
/** @} */

#define GNRC_RPL_MSG_TYPE_DODAG_DAO_TX        (0x0906)

#define GNRC_RPL_DEFAULT_MOP (0)

#define GNRC_RPL_GROUNDED (1)
#define CONFIG_GNRC_RPL_WITHOUT_PIO (0)
#define FC_HOOK_RPL_SEND_DIO (7)
#define GNRC_NETIF_FLAGS_IPV6_FORWARDING     (0x00000002U)

/********************************************************************** */

typedef union {
    void *ptr;
    uint32_t value;
} content; /* msg_t content union */

typedef struct {
    uintptr_t inst; /* ptr to the instance message */
    uintptr_t destination; /* ptr to destanation address */
} context_dio_send_t;

typedef struct {
    uintptr_t netif;   /* ptr to netif to build RPL instance on */
    uintptr_t dodag_id;   /* ptr to dodag address */
    uintptr_t rpl_trickle_send_dio_func_ptr;
    int16_t netif_pid;
} root_init_context_t;

static bool bpf_ipv6_addr_is_unique_local_unicast(ipv6_addr_t *addr)
{
    uint8_t first_byte = bpf_vm_pointer_get_element((uint8_t *)addr, 0, 1);
    return ((first_byte == 0xfc) || (first_byte == 0xfd));
}

int32_t root(root_init_context_t *ctx)
{
    /* Context */
    gnrc_netif_t *netif = (gnrc_netif_t *)(uintptr_t)ctx->netif;
    ipv6_addr_t *dodag_id = (ipv6_addr_t *)(uintptr_t)ctx->dodag_id;
    void *rpl_trickle_send_dio_func_ptr = (void *) (uintptr_t) ctx->rpl_trickle_send_dio_func_ptr;
    kernel_pid_t netif_pid = (kernel_pid_t) ctx->netif_pid;
    int8_t res = OK;

    kernel_pid_t rpl_pid = bpf_gnrc_rpl_init(netif_pid);

    gnrc_rpl_instance_t *inst = (gnrc_rpl_instance_t *)bpf_gnrc_rpl_get_instance_by_index(CONFIG_GNRC_RPL_DEFAULT_INSTANCE);
    if (inst) {
        bpf_gnrc_rpl_instance_remove((uintptr_t)inst);
    }
    /***********************************End Root Instance init (gnrc_rpl_root_instance_init)*************************************** */
    if (rpl_pid == KERNEL_PID_UNDEF) {
        // const char msg1[] = "KERNEL_PID_UNDEF\n";
        // f12r_vm_printf(msg1);
        res = ERROR;
        goto end;
    }

    if (!(bpf_ipv6_addr_is_global(dodag_id) || bpf_ipv6_addr_is_unique_local_unicast(dodag_id))) {
        // const char msg1[] = "bpf_ipv6_addr_is_global\n";
        // f12r_vm_printf(msg1);
        res = ERROR;
        goto end;
    }

    netif = bpf_gnrc_netif_get_by_ipv6_addr(dodag_id);
    if (netif == NULL) {
        // const char msg1[] = "netif\n";
        // f12r_vm_printf(msg1);
        res = ERROR;
        goto end;
    }

    if (!bpf_gnrc_rpl_instance_add(CONFIG_GNRC_RPL_DEFAULT_INSTANCE, (uintptr_t)&inst)) {
        // const char msg1[] = "instance\n";
        // f12r_vm_printf(msg1);
        res = ERROR;
        goto end;
    }

    _SET_ELEMENT(inst, of, bpf_gnrc_rpl_get_of_for_ocp(GNRC_RPL_DEFAULT_OCP));
    _SET_ELEMENT(inst, mop, GNRC_RPL_DEFAULT_MOP);
    _SET_ELEMENT(inst, min_hop_rank_inc, CONFIG_GNRC_RPL_DEFAULT_MIN_HOP_RANK_INCREASE);
    _SET_ELEMENT(inst, max_rank_inc, CONFIG_GNRC_RPL_DEFAULT_MAX_RANK_INCREASE);

    /***********************************Start DODAG Configuration (gnrc_rpl_dodag_init)*************************************** */
    gnrc_rpl_dodag_t *dodag = (gnrc_rpl_dodag_t *)_GET_ELEMENT_POINTER(inst, dodag);
    trickle_t *trickle = (trickle_t *)_GET_ELEMENT_POINTER(dodag, trickle);
    evtimer_msg_event_t *dao_event = (evtimer_msg_event_t *)_GET_ELEMENT_POINTER(dodag, dao_event);
    msg_t *msg = (msg_t *)_GET_ELEMENT_POINTER(dao_event, msg);

    f12r_memcpy((void *)_GET_ELEMENT_POINTER(dodag, dodag_id), dodag_id, sizeof(ipv6_addr_t));
    _SET_ELEMENT(dodag, my_rank, GNRC_RPL_INFINITE_RANK);

    trickle_callback_t *trickle_callback = (trickle_callback_t *)_GET_ELEMENT_POINTER(trickle, callback);
    _SET_ELEMENT(trickle_callback, func, rpl_trickle_send_dio_func_ptr);
    _SET_ELEMENT(trickle_callback, args, inst);

    _SET_ELEMENT(dodag, dio_interval_doubl, CONFIG_GNRC_RPL_DEFAULT_DIO_INTERVAL_DOUBLINGS);
    _SET_ELEMENT(dodag, dio_min, CONFIG_GNRC_RPL_DEFAULT_DIO_INTERVAL_MIN);
    _SET_ELEMENT(dodag, dio_redun, CONFIG_GNRC_RPL_DEFAULT_DIO_REDUNDANCY_CONSTANT);
    _SET_ELEMENT(dodag, default_lifetime, CONFIG_GNRC_RPL_DEFAULT_LIFETIME);
    _SET_ELEMENT(dodag, lifetime_unit, CONFIG_GNRC_RPL_LIFETIME_UNIT);
    _SET_ELEMENT(dodag, node_status, GNRC_RPL_NORMAL_NODE);
    _SET_ELEMENT(dodag, dao_seq, GNRC_RPL_COUNTER_INIT);
    _SET_ELEMENT(dodag, dtsn, 0);
    _SET_ELEMENT(dodag, dao_ack_received, false);
    _SET_ELEMENT(dodag, dao_counter, 0);
    _SET_ELEMENT(dodag, instance, inst);
    _SET_ELEMENT(dodag, iface, netif_pid);
    _SET_ELEMENT((content *)_GET_ELEMENT_POINTER(msg, content), ptr, inst);
    _SET_ELEMENT(msg, type, GNRC_RPL_MSG_TYPE_DODAG_DAO_TX);
    
    if ((netif != NULL) && !(_GET_ELEMENT(netif, flags) & GNRC_NETIF_FLAGS_IPV6_FORWARDING)) {

        _SET_ELEMENT(dodag, node_status, GNRC_RPL_LEAF_NODE);
        context_dio_send_t dio_send_ctx = {.inst = (uintptr_t)inst, .destination= (uintptr_t)NULL};
        bpf_trigger_hook(FC_HOOK_RPL_SEND_DIO, (uintptr_t)&dio_send_ctx, sizeof(dio_send_ctx));
    }

    /***********************************End DODAG Configuration (gnrc_rpl_dodag_init)*************************************** */

    dodag = (gnrc_rpl_dodag_t *)_GET_ELEMENT_POINTER(inst, dodag);
    _SET_ELEMENT(dodag, instance, inst);
    /***********************************End Root Instance init (gnrc_rpl_root_instance_init)*************************************** */
    _SET_ELEMENT(dodag, dtsn, 1);
    _SET_ELEMENT(dodag, prf, 0);
    _SET_ELEMENT(dodag, dio_interval_doubl, CONFIG_GNRC_RPL_DEFAULT_DIO_INTERVAL_DOUBLINGS);
    _SET_ELEMENT(dodag, dio_min, CONFIG_GNRC_RPL_DEFAULT_DIO_INTERVAL_MIN);
    _SET_ELEMENT(dodag, dio_redun, CONFIG_GNRC_RPL_DEFAULT_DIO_REDUNDANCY_CONSTANT);
    _SET_ELEMENT(dodag, default_lifetime, CONFIG_GNRC_RPL_DEFAULT_LIFETIME);
    _SET_ELEMENT(dodag, lifetime_unit, CONFIG_GNRC_RPL_LIFETIME_UNIT);
    _SET_ELEMENT(dodag, version, GNRC_RPL_COUNTER_INIT);
    _SET_ELEMENT(dodag, grounded, GNRC_RPL_GROUNDED);
    _SET_ELEMENT(dodag, node_status, GNRC_RPL_ROOT_NODE);
    _SET_ELEMENT(dodag, my_rank, CONFIG_GNRC_RPL_DEFAULT_MIN_HOP_RANK_INCREASE);
    uint8_t dio_opts = 0;
    _SET_ELEMENT(dodag, dio_opts, dio_opts | GNRC_RPL_REQ_DIO_OPT_DODAG_CONF);
    
    if (!CONFIG_GNRC_RPL_WITHOUT_PIO) {
        dio_opts = _GET_ELEMENT(dodag, dio_opts);
        _SET_ELEMENT(dodag, dio_opts, dio_opts | GNRC_RPL_REQ_DIO_OPT_PREFIX_INFO);
    }
    
    bpf_trickle_start_timer(rpl_pid, (uintptr_t)_GET_ELEMENT_POINTER(dodag, trickle), (1 << _GET_ELEMENT(dodag, dio_min)), 
                    _GET_ELEMENT(dodag, dio_interval_doubl), _GET_ELEMENT(dodag, dio_redun));
    
    bpf_gnrc_rpl_mode(1,0); /*1: set (0 :get), 1: for non-storing (0 for Storing)*/
    

end:
    return res;
}