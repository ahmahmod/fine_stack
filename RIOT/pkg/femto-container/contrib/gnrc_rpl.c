#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#include "femtocontainer/femtocontainer.h"
#include "call.h"
#include "net/gnrc.h"
#include "net/gnrc/rpl.h"
#include "net/gnrc/rpl/srh.h"


#define ENABLE_DEBUG (1)
#include "debug.h"

// static char addr_str[IPV6_ADDR_MAX_STR_LEN];

uint32_t bpf_gnrc_rpl_get_instance_by_index(f12r_t *bpf, uint32_t index, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5){
    (void)bpf;
    (void)a2;
    (void)a3;
    (void)a4;
    (void)a5;

    return (uintptr_t) &gnrc_rpl_instances[index];
}

uint32_t bpf_gnrc_rpl_get_instance_by_id(f12r_t *bpf, uint32_t id, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5){
    (void)bpf;
    (void)a2;
    (void)a3;
    (void)a4;
    (void)a5;

    return (uintptr_t) gnrc_rpl_instance_get((uint8_t) id);
}

uint32_t bpf_gnrc_rpl_instance_add(f12r_t *bpf, uint32_t instance_id, uint32_t inst, uint32_t a3, uint32_t a4, uint32_t a5){
    (void)bpf;
    (void)a3;
    (void)a4;
    (void)a5;

    uint8_t instance_id1 = (uint8_t) instance_id;
    gnrc_rpl_instance_t **inst1 = (gnrc_rpl_instance_t **)inst;
    return  gnrc_rpl_instance_add(instance_id1, inst1);
}

uint32_t bpf_gnrc_rpl_instance_remove(f12r_t *bpf, uint32_t inst, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5){
    (void)bpf;
    (void)a2;
    (void)a3;
    (void)a4;
    (void)a5;

    gnrc_rpl_instance_t *inst1  = (gnrc_rpl_instance_t *)inst;
    return gnrc_rpl_instance_remove(inst1);
}

uint32_t bpf_gnrc_rpl_dodag_init(f12r_t *bpf, uint32_t inst, uint32_t dodag_id, uint32_t iface, uint32_t a4, uint32_t a5){
    (void)bpf;
    (void)a4;
    (void)a5;

    gnrc_rpl_instance_t *instance1 = (gnrc_rpl_instance_t *) inst;
    ipv6_addr_t *dodag_id1 = (ipv6_addr_t *) dodag_id;
    kernel_pid_t iface1 = (kernel_pid_t) iface;
    
    return gnrc_rpl_dodag_init(instance1, dodag_id1, iface1);
}

uint32_t bpf_gnrc_rpl_parent_add_by_addr(f12r_t *bpf, uint32_t dodag, uint32_t addr, uint32_t parent, uint32_t a4, uint32_t a5){
    (void)bpf;
    (void)a4;
    (void)a5;

    gnrc_rpl_dodag_t *dodag1 = (gnrc_rpl_dodag_t *) dodag;
    ipv6_addr_t *addr1 = (ipv6_addr_t *) addr;
    gnrc_rpl_parent_t **parent1 = (gnrc_rpl_parent_t **) parent;
    bool res  = gnrc_rpl_parent_add_by_addr(dodag1, addr1, parent1);

    if (res){
        return (uintptr_t)*parent1;
    }
    else {
        return (uintptr_t)NULL;
    }
    
    return (uintptr_t)NULL;
}

uint32_t bpf_gnrc_rpl_parent_remove(f12r_t *bpf, uint32_t parent, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5){
    (void)bpf;
    (void)a2;
    (void)a3;
    (void)a4;
    (void)a5;

    gnrc_rpl_parent_t *parent1 = (gnrc_rpl_parent_t *) parent;

    return gnrc_rpl_parent_remove(parent1);
}

uint32_t bpf_gnrc_rpl_parent_update(f12r_t *bpf, uint32_t dodag, uint32_t parent, uint32_t a3, uint32_t a4, uint32_t a5){
    (void)bpf;
    (void)a3;
    (void)a4;
    (void)a5;

    gnrc_rpl_dodag_t *dodag1 = (gnrc_rpl_dodag_t *) dodag;
    gnrc_rpl_parent_t *parent1 = (gnrc_rpl_parent_t *) parent;

    gnrc_rpl_parent_update(dodag1, parent1);
    return 0;
}

uint32_t bpf_gnrc_rpl_local_repair(f12r_t *bpf, uint32_t dodag, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5){
    (void)bpf;
    (void)a2;
    (void)a3;
    (void)a4;
    (void)a5;

    gnrc_rpl_dodag_t *dodag1 = (gnrc_rpl_dodag_t *) dodag;

    gnrc_rpl_local_repair(dodag1);
    return 0;
}

uint32_t bpf_gnrc_rpl_delay_dao(f12r_t *bpf, uint32_t dodag, uint32_t long_delay, uint32_t a3, uint32_t a4, uint32_t a5){
    (void)bpf;
    (void)a3;
    (void)a4;
    (void)a5;

    gnrc_rpl_dodag_t *dodag1 = (gnrc_rpl_dodag_t *) dodag;
    bool long_delay1 = (bool) long_delay;

    if(long_delay1){
        gnrc_rpl_long_delay_dao(dodag1);
    }
    else {
        gnrc_rpl_delay_dao(dodag1);
    }

    return 0;
}

uint32_t bpf_gnrc_rpl_get_of_for_ocp(f12r_t *bpf, uint32_t ocp, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5){
    (void)bpf;
    (void)a2;
    (void)a3;
    (void)a4;
    (void)a5;

    uint16_t ocp1 = (uint16_t) ocp;

    return (uintptr_t) gnrc_rpl_get_of_for_ocp(ocp1);
}

uint32_t bpf_gnrc_rpl_send(f12r_t *bpf, uint32_t pkt, uint32_t iface, uint32_t src, uint32_t dst, uint32_t dodag_id)
{
    (void)bpf;
    gnrc_pktsnip_t *pkt1 = (gnrc_pktsnip_t *)pkt;
    kernel_pid_t iface1 = (kernel_pid_t)iface;
    ipv6_addr_t *src1 = (ipv6_addr_t *)src;
    ipv6_addr_t *dst1 = (ipv6_addr_t *)dst;
    ipv6_addr_t *dodag_id1 = (ipv6_addr_t *)dodag_id;

    // printf("bpf_gnrc_rpl_send called, dst: %s\n",  ipv6_addr_to_str(addr_str, dst1, sizeof(addr_str)));

    gnrc_rpl_send(pkt1, iface1, src1, dst1, dodag_id1);
    return 1;
}

uint32_t bpf_gnrc_rpl_init(f12r_t *bpf, uint32_t pid, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5)
{
    (void)bpf;
    (void)a2;
    (void)a3;
    (void)a4;
    (void)a5;

    return gnrc_rpl_init((kernel_pid_t) pid);
}


uint32_t bpf_gnrc_rpl_is_root(f12r_t *bpf, uint32_t set, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5){
    (void)bpf;
    (void)a2;
    (void)a3;
    (void)a4;
    (void)a5;

    if (set){
        set_is_root();
        return 0;
    }

    return get_is_root();
}


uint32_t bpf_gnrc_rpl_mode(f12r_t *bpf, uint32_t set, uint32_t mode, uint32_t a3, uint32_t a4, uint32_t a5){
    (void)bpf;
    (void)a3;
    (void)a4;
    (void)a5;
    int8_t mode1 = (int8_t) mode;

    if (set){
        return gnrc_rpl_set_mode(mode1);
    }

    return gnrc_rpl_get_mode();
}


uint32_t bpf_gnrc_rpl_root_dodag_id(f12r_t *bpf, uint32_t set, uint32_t dodag_id, uint32_t a3, uint32_t a4, uint32_t a5){
    (void)bpf;
    (void)a3;
    (void)a4;
    (void)a5;
    if (set){
        ipv6_addr_t *dodag_id1 = (ipv6_addr_t *) dodag_id;
        gnrc_rpl_set_root_dodag_id(dodag_id1);
        return 0;
    }

    return (uintptr_t) gnrc_rpl_get_root_dodag_id();
    
    
}