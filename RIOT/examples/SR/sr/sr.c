#include <stdio.h>
#include <string.h>
#include "sr.h"
#include "net/ipv6.h"

#define ENABLE_DEBUG        0
#include "debug.h"


static fib_table_t table;
static fib_sr_meta_t meta;
static fib_sr_t headers[GNRC_SR_FIB_TABLE_HEADER_SIZE];
static fib_sr_entry_t entry_pool[GNRC_SR_FIB_TABLE_ENTRY_POOL_SIZE];

static char addr_str[IPV6_ADDR_MAX_STR_LEN];
static char root_node[UNIVERSAL_ADDRESS_SIZE] = {0xA};

void gnrc_sr_initialize_table(void) {

    table.size = GNRC_SR_FIB_TABLE_SIZE;
    table.table_type = FIB_TABLE_TYPE_SR;
    table.data.source_routes = &meta;
    table.data.source_routes->headers = headers;
    table.data.source_routes->entry_pool = entry_pool;
    table.data.source_routes->entry_pool_size = GNRC_SR_FIB_TABLE_ENTRY_POOL_SIZE;

    fib_init(&table);
    DEBUG("FIB Table Initialized\n");
}

void gnrc_sr_table_print(void) {
    DEBUG("FIB Table Content:\n");
    fib_print_routes(&table); // Assuming this function prints all routes
}

void gnrc_sr_print_table_route(uint8_t *node) {
    uint8_t addr_list[GNRC_SR_MAX_ROUTE_SIZE * UNIVERSAL_ADDRESS_SIZE];
    size_t addr_list_elements = GNRC_SR_MAX_ROUTE_SIZE;
    size_t element_size = UNIVERSAL_ADDRESS_SIZE;
    kernel_pid_t sr_iface_id;
    uint32_t sr_flags = 0;
    fib_sr_t *fib_sr = NULL;

    // Attempt to find an existing route to the parent
    int result = fib_sr_get_route(&table, node, UNIVERSAL_ADDRESS_SIZE, &sr_iface_id, &sr_flags,
                                  addr_list, &addr_list_elements, &element_size, false, &fib_sr);
    
    printf("A route to %s/%d route has been found: ",
                ipv6_addr_to_str(addr_str, (ipv6_addr_t *) node, sizeof(addr_str)), UNIVERSAL_ADDRESS_SIZE);
    if (result >= 0){
        for (size_t i = 0; i < addr_list_elements; ++i) {
            printf(" %s - ",
                ipv6_addr_to_str(addr_str, (ipv6_addr_t *) &addr_list[i * element_size], sizeof(addr_str)));
        }
        printf("\n");
    } else {
        printf("No route found");
    }
    
}

int gnrc_sr_add_new_dst(uint8_t *child, uint8_t *parent, kernel_pid_t sr_iface_id, uint32_t sr_flags, uint32_t lifetime) {
    // Initialize a new SR
    fib_sr_t *sr = NULL;
    if (fib_sr_create(&table, &sr, sr_iface_id, sr_flags, lifetime) == 0) {
        // Append only the child-parent pair
        fib_sr_entry_append(&table, sr, parent, UNIVERSAL_ADDRESS_SIZE);
        fib_sr_entry_append(&table, sr, child, UNIVERSAL_ADDRESS_SIZE);
        return 0;
    } else {
        DEBUG("Failed to create source route for child-parent pair.\n");
        return -1;
    }
}

int gnrc_sr_delete_route(uint8_t *dst_node, size_t dst_size) {
    kernel_pid_t sr_iface_id = 0;
    uint32_t sr_flags = 0;
    fib_sr_t *fib_sr = NULL;
    uint8_t addr_list[50 * UNIVERSAL_ADDRESS_SIZE];
    size_t addr_list_elements = 50;
    size_t element_size = UNIVERSAL_ADDRESS_SIZE;

    // Try to find the existing route
    int result = fib_sr_get_route(&table, dst_node, dst_size, &sr_iface_id, &sr_flags,
                                  addr_list, &addr_list_elements, &element_size, false, &fib_sr);
                                  
    if (result >= 0 && fib_sr != NULL) {
        // when to delete a route from the table, first the entry has to be deleted before the sr.
        if (fib_sr_entry_delete(&table, fib_sr, dst_node, dst_size, true) == 0 && fib_sr_delete(&table, fib_sr) == 0) {
            DEBUG("Route to destination deleted successfully.\n");
            return 0;
        } else {
            DEBUG("Failed to delete route to destination.\n");
            return -1;
        }
    } else {
        DEBUG("No existing route found to delete.\n");
        return result; // Return error code if route wasn't found
    }
    return 0;
}

int gnrc_sr_get_full_route(uint8_t *dst_node, uint8_t *route_buffer, size_t *route_length) {
    uint8_t current_node[UNIVERSAL_ADDRESS_SIZE];
    memcpy(current_node, dst_node, UNIVERSAL_ADDRESS_SIZE);

    size_t route_index = 0;

    while (memcmp(current_node, root_node, UNIVERSAL_ADDRESS_SIZE) != 0) {
        uint8_t addr_list[GNRC_SR_MAX_ROUTE_SIZE * UNIVERSAL_ADDRESS_SIZE]; // Parent should be a single entry
        size_t addr_list_elements = GNRC_SR_MAX_ROUTE_SIZE;            // One parent at a time
        size_t element_size = UNIVERSAL_ADDRESS_SIZE;

        kernel_pid_t sr_iface_id = 0;
        uint32_t sr_flags = 0;
        fib_sr_t *fib_sr = NULL;

        // Get the next hop (parent) for the current node
        int result = fib_sr_get_route(&table, current_node, UNIVERSAL_ADDRESS_SIZE, &sr_iface_id, &sr_flags,
                                      addr_list, &addr_list_elements, &element_size, false, &fib_sr);

        if (result < 0 || addr_list_elements == 0) {
            DEBUG("Failed to find route to the root. Stuck at node: %s\n",
                   ipv6_addr_to_str(addr_str, (ipv6_addr_t *)current_node, sizeof(addr_str)));
            return -1; // No route to the root
        }

        // Add the current node to the route buffer
        memcpy(&route_buffer[route_index * UNIVERSAL_ADDRESS_SIZE], current_node, UNIVERSAL_ADDRESS_SIZE);
        route_index++;

        // Move to the parent
        memcpy(current_node, addr_list, UNIVERSAL_ADDRESS_SIZE);
    }

    // Add the root node to the route buffer
    memcpy(&route_buffer[route_index * UNIVERSAL_ADDRESS_SIZE], root_node, UNIVERSAL_ADDRESS_SIZE);
    route_index++;

    *route_length = route_index;

    printf("Route reconstructed: ");
    for (size_t i = 0; i < *route_length-1; ++i) {
        printf("%s -> ",
               ipv6_addr_to_str(addr_str, (ipv6_addr_t *)&route_buffer[i * UNIVERSAL_ADDRESS_SIZE],
                                sizeof(addr_str)));
    }
    printf("root\n");

    return 0;
}