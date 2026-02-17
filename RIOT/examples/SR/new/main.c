#include <stdio.h>
#include <stdint.h>
#include "sr.h"
#include "ztimer.h"

#include "shell.h"
#include "msg.h"

#define MAIN_QUEUE_SIZE     (8)
static msg_t _main_msg_queue[MAIN_QUEUE_SIZE];

int main(void) {

    // Define relationships based on packets received
    ipv6_addr_t address_r = {{0xA}};
    ipv6_addr_t address_c = {{0xC}};
    ipv6_addr_t address_b = {{0xB}};
    ipv6_addr_t address_f = {{0xF}};
    ipv6_addr_t address_e = {{0xE}};
    ipv6_addr_t address_g = {{0x1}};
    ipv6_addr_t address_h = {{0x2}};
    ipv6_addr_t address_i = {{0x3}};

    // Initialize the FIB table using the dedicated function
    gnrc_sr_initialize_table((ipv6_addr_t *) &address_r, 0);
    
    uint32_t lifetime = 20000;
    uint32_t sr_flags = FIB_FLAG_RPL_ROUTE;
    kernel_pid_t iface = 0;

    
    // Build source routes dynamically
    
    //gnrc_sr_add_new_dst(address_r, address_r, iface, sr_flags, lifetime); // R -> R
    
    gnrc_sr_add_new_dst((ipv6_addr_t *)&address_i, sizeof(ipv6_addr_t), (ipv6_addr_t *) &address_c, iface, sr_flags, lifetime); // G -> F
    gnrc_sr_add_new_dst((ipv6_addr_t *)&address_c, sizeof(ipv6_addr_t),(ipv6_addr_t *)&address_r, iface, sr_flags, lifetime); // C -> R
    gnrc_sr_add_new_dst((ipv6_addr_t *)&address_b, sizeof(ipv6_addr_t),(ipv6_addr_t *)&address_r, iface, sr_flags, lifetime); // B -> R
    gnrc_sr_add_new_dst((ipv6_addr_t *)&address_f, sizeof(ipv6_addr_t),(ipv6_addr_t *)&address_c, iface, sr_flags, lifetime); // F -> C
    gnrc_sr_add_new_dst((ipv6_addr_t *)&address_e, sizeof(ipv6_addr_t),(ipv6_addr_t *)&address_c, iface, sr_flags, lifetime); // E -> C  
    gnrc_sr_add_new_dst((ipv6_addr_t *)&address_g, sizeof(ipv6_addr_t),(ipv6_addr_t *)&address_f, iface, sr_flags, lifetime); // G -> F
    gnrc_sr_add_new_dst((ipv6_addr_t *)&address_i, sizeof(ipv6_addr_t),(ipv6_addr_t *)&address_c, iface, sr_flags, lifetime); // G -> F
    gnrc_sr_add_new_dst((ipv6_addr_t *)&address_h, sizeof(ipv6_addr_t),(ipv6_addr_t *)&address_f, iface, sr_flags, lifetime); // G -> F
    //gnrc_sr_add_new_dst(address_g, address_f, iface, sr_flags, lifetime); // G -> F

    // Print the FIB table
    gnrc_sr_table_print();

    // Intilaize route retrive
    ipv6_addr_t route_buffer[GNRC_SR_MAX_ROUTE_SIZE];
    size_t route_length = 0;

    // get a route to i even if it's added before the parent
    gnrc_sr_get_full_route(&address_f, route_buffer, &route_length);
    // Print the FIB table
    gnrc_sr_table_print();

    //get a route to g, delete it's entry, check again, re-add a new route, check again
    gnrc_sr_get_full_route(&address_h, route_buffer, &route_length);
    
    gnrc_sr_delete_route(&address_h, UNIVERSAL_ADDRESS_SIZE);
    gnrc_sr_get_full_route(&address_h, route_buffer, &route_length);

    // Print the FIB table
    //gnrc_sr_table_print();

    gnrc_sr_add_new_dst(&address_g, sizeof(ipv6_addr_t),&address_f, iface, sr_flags, lifetime); // G -> F
    gnrc_sr_get_full_route(&address_g, route_buffer, &route_length);


     /* we need a message queue for the thread running the shell in order to
     * receive potentially fast incoming networking packets */
    msg_init_queue(_main_msg_queue, MAIN_QUEUE_SIZE);
    puts("RIOT network stack example application");

    /* start shell */
    puts("All up, running the shell now");
    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(NULL, line_buf, SHELL_DEFAULT_BUFSIZE);
    printf("END\n");

    return 0;
}