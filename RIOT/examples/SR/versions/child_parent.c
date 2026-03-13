#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include "net/fib.h"




// Define relationships array to store parent-child pairs
typedef struct {
    uint8_t child[UNIVERSAL_ADDRESS_SIZE];
    uint8_t parent[UNIVERSAL_ADDRESS_SIZE];
} relationship_t;

relationship_t relationships[100];
size_t relationship_count = 0;

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

// Add a parent-child relationship
void add_relationship(uint8_t *child, uint8_t *parent) {
    memcpy(relationships[relationship_count].child, child, UNIVERSAL_ADDRESS_SIZE);
    memcpy(relationships[relationship_count].parent, parent, UNIVERSAL_ADDRESS_SIZE);
    relationship_count++;
}

uint8_t *find_parent(uint8_t *child) {
    for (size_t i = 0; i < relationship_count; ++i) {
        if (memcmp(relationships[i].child, child, UNIVERSAL_ADDRESS_SIZE) == 0) {
            return relationships[i].parent;
        }
    }
    return NULL;
}

// Build source routes for each node to the root
void build_source_routes(fib_table_t *table) {
    for (size_t i = 0; i < relationship_count; ++i) {
        uint8_t current_node[UNIVERSAL_ADDRESS_SIZE];
        memcpy(current_node, relationships[i].child, UNIVERSAL_ADDRESS_SIZE);

        fib_sr_t *sr = NULL;
        kernel_pid_t iface_id = 0;
        uint32_t flags = 0;
        uint32_t lifetime = 20000;

        // Create a source route for this relationship
        if (fib_sr_create(table, &sr, iface_id, flags, lifetime) == 0) {
            // Store all nodes in a temporary stack
            uint8_t stack[50][UNIVERSAL_ADDRESS_SIZE]; // Temporary stack for the route
            size_t stack_size = 0;

            // Push child and all parents onto the stack
            uint8_t *parent = find_parent(current_node);
            memcpy(stack[stack_size++], current_node, UNIVERSAL_ADDRESS_SIZE);
            while (parent) {
                memcpy(stack[stack_size++], parent, UNIVERSAL_ADDRESS_SIZE);
                memcpy(current_node, parent, UNIVERSAL_ADDRESS_SIZE);
                parent = find_parent(current_node);
            }

            // Append nodes to the source route in reverse order (root to child)
            for (size_t j = stack_size; j > 0; --j) {
                fib_sr_entry_append(table, sr, stack[j - 1], UNIVERSAL_ADDRESS_SIZE);
            }
        }
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
    table.size = 4;
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

    add_relationship(address_c, address_r); // C -> R
    add_relationship(address_b, address_r); // B -> R
    add_relationship(address_f, address_c); // F -> C
    add_relationship(address_e, address_c); // E -> C

    // Build source routes in the table
    build_source_routes(&table);

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
