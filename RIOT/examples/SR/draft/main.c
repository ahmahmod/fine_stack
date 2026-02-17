#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "net/fib.h"

// Define addresses
//#define UNIVERSAL_ADDRESS_SIZE 16

void print_route(uint8_t *addr_list, size_t addr_list_elements, size_t element_size) {
    printf("Route:\n");
    for (size_t i = 0; i < addr_list_elements; ++i) {
        printf("Hop %zu: ", i + 1);
        for (size_t j = 0; j < element_size; ++j) {
            printf("%02X", addr_list[i * element_size + j]);
        }
        printf("\n");
    }
}

int main(void) {
    // Initialize the FIB table
    fib_table_t table;
    fib_sr_meta_t meta;
    fib_sr_t headers[50];
    fib_sr_entry_t entry_pool[50];

    meta.headers = headers;
    meta.entry_pool = entry_pool;
    meta.entry_pool_size = 50;

    // Initialize the table
    table.size = 4;
    table.table_type = FIB_TABLE_TYPE_SR; // FIB_TABLE_TYPE_SR
    table.data.source_routes = &meta;
    table.data.source_routes->headers = headers;
    table.data.source_routes->entry_pool = entry_pool;
    table.data.source_routes->entry_pool_size = 50;
    fib_init(&table);
    printf("OK\n");

    // Addresses (IPv6-style, 16 bytes each)
    uint8_t address_b[UNIVERSAL_ADDRESS_SIZE] = {0xB};
    uint8_t address_c[UNIVERSAL_ADDRESS_SIZE] = {0xC};
    //uint8_t address_e[UNIVERSAL_ADDRESS_SIZE] = {0xE};
    uint8_t address_f[UNIVERSAL_ADDRESS_SIZE] = {0xF};

    printf("OK\n");

/*
    // Create source route entries
    fib_sr_t *sr_b = NULL;
    fib_sr_t *sr_c = NULL;
    fib_sr_t *sr_e = NULL;
    fib_sr_t *sr_f = NULL;

    // Add source route for B -> B
    fib_sr_create(&table, &sr_b, 1, 0, 200000);
    fib_sr_entry_append(&table, sr_b, address_b, UNIVERSAL_ADDRESS_SIZE);

    // Add source route for C -> B
    fib_sr_create(&table, &sr_c, 1, 0, 200000);
    fib_sr_entry_append(&table, sr_c, address_b, UNIVERSAL_ADDRESS_SIZE);
    fib_sr_entry_append(&table, sr_c, address_c, UNIVERSAL_ADDRESS_SIZE);

    // Add source route for E -> C
    fib_sr_create(&table, &sr_e, 1, 0, 200000);
    fib_sr_entry_append(&table, sr_e, address_c, UNIVERSAL_ADDRESS_SIZE);
    fib_sr_entry_append(&table, sr_e, address_e, UNIVERSAL_ADDRESS_SIZE);

    // Add source route for F -> C
    fib_sr_create(&table, &sr_f, 1, 0, 200000);
    fib_sr_entry_append(&table, sr_f, address_c, UNIVERSAL_ADDRESS_SIZE);
    fib_sr_entry_append(&table, sr_f, address_f, UNIVERSAL_ADDRESS_SIZE);
*/

    // Create source route entries
    fib_sr_t *sr = NULL;

    // Add source route for B -> C -> F
    fib_sr_create(&table, &sr, 1, 0, 200000);
    fib_sr_entry_append(&table, sr, address_b, UNIVERSAL_ADDRESS_SIZE); // Hop: B
    fib_sr_entry_append(&table, sr, address_c, UNIVERSAL_ADDRESS_SIZE); // Hop: C
    fib_sr_entry_append(&table, sr, address_f, UNIVERSAL_ADDRESS_SIZE); // Hop: F

    // Prepare parameters for finding the route to F
    uint8_t addr_list[4 * UNIVERSAL_ADDRESS_SIZE];
    size_t addr_list_elements = 4;
    size_t element_size = UNIVERSAL_ADDRESS_SIZE;
    kernel_pid_t sr_iface_id;
    uint32_t sr_flags = 0;
    fib_sr_t *fib_sr = NULL;

    // Find a route to F
    int result = fib_sr_get_route(&table, address_f, UNIVERSAL_ADDRESS_SIZE, &sr_iface_id, &sr_flags,
                                  addr_list, &addr_list_elements, &element_size, false, &fib_sr);

    if (result >= 0) {
        printf("Route to F found!\n");
        print_route(addr_list, addr_list_elements, element_size);
    } else {
        printf("Route to F not found, error code: %d\n", result);
    }

    fib_print_fib_table(&table);
    fib_print_routes(&table);

    // De-initialize the FIB table
    fib_deinit(&table);

    return 0;
}
