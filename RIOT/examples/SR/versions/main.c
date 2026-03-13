#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include "net/fib.h"

// Define constants


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

void build_source_routes(fib_table_t *table, uint8_t *child, uint8_t *parent) {
    uint8_t addr_list[50 * UNIVERSAL_ADDRESS_SIZE]; // Buffer for intermediate routes
    size_t addr_list_elements = 50;
    size_t element_size = UNIVERSAL_ADDRESS_SIZE;
    kernel_pid_t sr_iface_id = 0;
    uint32_t sr_flags = 0;
    fib_sr_t *fib_sr = NULL;
    
    printf("sr address: %p\n", (void *) sr);
    // Attempt to find an existing route to the parent
    int result = fib_sr_get_route(table, parent, UNIVERSAL_ADDRESS_SIZE, &sr_iface_id, &sr_flags,
                                  addr_list, &addr_list_elements, &element_size, false, &fib_sr);
    printf("1- sr address: %p\n", (void *) sr);
    if (result >= 0) {
        printf("Route found!\n");
        print_route(addr_list, addr_list_elements, element_size);
    } else {
        printf("Route not found, error code: %d\n", result);
    }

    fib_sr_t *sr = malloc(sizeof(fib_sr_t));
    uint32_t lifetime = 20000;
    int res = fib_sr_create(table, &sr, sr_iface_id, sr_flags, lifetime);
    printf("res: %d\n", res);
    
    if (result >= 0) {
        //fib_sr_t *sr = NULL;
        printf("DONE0\n");
        // If a route to the parent exists, extend it to include the child
        
        if (res >= 0) {
            printf("DONEX\n");
            // Copy the parent route into the new source route
            for (size_t i = 0; i < addr_list_elements; ++i) {
                printf("Add: %p\n", (void *) &addr_list[i * element_size]);
                fib_sr_entry_append(table, sr, &addr_list[i * element_size], element_size);
            }
            // Append the child
            fib_sr_entry_append(table, sr, child, UNIVERSAL_ADDRESS_SIZE);
        }
    } else {
        //fib_sr_t *sr = NULL;
        printf("DONE1\n");
        // If no route to the parent exists, create a direct route from parent to child
        //if (fib_sr_create(table, &sr, sr_iface_id, sr_flags, lifetime) == 0) {
            fib_sr_entry_append(table, sr, parent, UNIVERSAL_ADDRESS_SIZE);
            fib_sr_entry_append(table, sr, child, UNIVERSAL_ADDRESS_SIZE);
        //}
    }
}


void print_table(fib_table_t *table) {
    printf("FIB Table Content:\n");
    fib_print_routes(table); // Assuming this function prints all routes
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
    table.size = 20;
    table.table_type = FIB_TABLE_TYPE_SR; // FIB_TABLE_TYPE_SR
    table.data.source_routes = &meta;
    table.data.source_routes->headers = headers;
    table.data.source_routes->entry_pool = entry_pool;
    table.data.source_routes->entry_pool_size = 50;
    fib_init(&table);
    printf("OK\n");

    // Define relationships based on packets received
    uint8_t address_r[UNIVERSAL_ADDRESS_SIZE] = {0xA};
    uint8_t address_c[UNIVERSAL_ADDRESS_SIZE] = {0xC};
    uint8_t address_b[UNIVERSAL_ADDRESS_SIZE] = {0xB};
    uint8_t address_f[UNIVERSAL_ADDRESS_SIZE] = {0xF};
    uint8_t address_e[UNIVERSAL_ADDRESS_SIZE] = {0xE};

    // Build source routes dynamically
    build_source_routes(&table, address_c, address_r); // C -> R
    build_source_routes(&table, address_b, address_r); // B -> R
    build_source_routes(&table, address_f, address_c); // F -> C
    build_source_routes(&table, address_e, address_c); // E -> C

    // Print the FIB table
    print_table(&table);

    // Prepare parameters for finding the route to F
    uint8_t addr_list[5 * UNIVERSAL_ADDRESS_SIZE];
    size_t addr_list_elements = 5;
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

    // De-initialize the table
    fib_deinit(&table);

    return 0;
}
