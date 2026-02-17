#include <stdio.h>
#include <stdint.h>
#include "sr.h"
#include "ztimer.h"

int main(void) {

    // Initialize the FIB table using the dedicated function
    gnrc_sr_initialize_table();

    // Define relationships based on packets received
    uint8_t address_r[UNIVERSAL_ADDRESS_SIZE] = {0xA};
    uint8_t address_c[UNIVERSAL_ADDRESS_SIZE] = {0xC};
    uint8_t address_b[UNIVERSAL_ADDRESS_SIZE] = {0xB};
    uint8_t address_f[UNIVERSAL_ADDRESS_SIZE] = {0xF};
    uint8_t address_e[UNIVERSAL_ADDRESS_SIZE] = {0xE};
    uint8_t address_g[UNIVERSAL_ADDRESS_SIZE] = {0x1};
    uint8_t address_h[UNIVERSAL_ADDRESS_SIZE] = {0x2};
    uint8_t address_i[UNIVERSAL_ADDRESS_SIZE] = {0x3};

    uint32_t lifetime = 20000;
    uint32_t sr_flags = 0;
    kernel_pid_t iface = 0;


    // Build source routes dynamically
    
    gnrc_sr_add_new_dst(address_r, address_r, iface, sr_flags, lifetime); // R -> R
    //gnrc_sr_add_new_dst(address_g, address_f, iface, sr_flags, lifetime); // G -> F
    
    gnrc_sr_add_new_dst(address_c, address_r, iface, sr_flags, lifetime); // C -> R
    gnrc_sr_add_new_dst(address_b, address_r, iface, sr_flags, lifetime); // B -> R
    gnrc_sr_add_new_dst(address_f, address_c, iface, sr_flags, lifetime); // F -> C
    gnrc_sr_add_new_dst(address_e, address_c, iface, sr_flags, lifetime); // E -> C  
    gnrc_sr_add_new_dst(address_g, address_f, iface, sr_flags, lifetime); // G -> F
    
    
    //gnrc_sr_add_new_dst(address_g, address_f, iface, sr_flags, lifetime); // G -> F

    // Print the FIB table
    gnrc_sr_table_print();
    gnrc_sr_print_route(address_g);

    gnrc_sr_delete_route(address_g, UNIVERSAL_ADDRESS_SIZE);
    gnrc_sr_add_new_dst(address_h, address_f, iface, sr_flags, lifetime); // G -> F
    // Print the FIB table
    gnrc_sr_table_print();
    gnrc_sr_print_route(address_h);
     // Print the FIB table
    //gnrc_sr_table_print();
    //gnrc_sr_print_route(address_g);

    //gnrc_sr_add_new_dst(address_g, address_f, iface, 1, lifetime); // G -> F

    gnrc_sr_add_new_dst(address_i, address_c, iface, sr_flags, lifetime); // G -> F

    // Print the FIB table
    gnrc_sr_table_print();
    gnrc_sr_print_route(address_i);

    return 0;
}
