#include "sr.h"
#include "net/ipv6.h"
#include <stdio.h>
#include <string.h>


#define ENABLE_DEBUG        0
#include "debug.h"


static fib_table_t table;
static fib_sr_meta_t meta;
static fib_sr_t headers[GNRC_SR_FIB_TABLE_HEADER_SIZE];
static fib_sr_entry_t entry_pool[GNRC_SR_FIB_TABLE_ENTRY_POOL_SIZE];

static char addr_str[IPV6_ADDR_MAX_STR_LEN];

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

void gnrc_sr_print_route(uint8_t *node) {
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


/*int gnrc_sr_get_route(uint8_t *node, kernel_pid_t *sr_iface_id, uint32_t *sr_flags, 
                        uint8_t *addr_list, size_t *addr_list_elements,  size_t *element_size,
                        uint32_t lifetime){
    //Initials for getting the parent's route
    //uint8_t addr_list[GNRC_SR_MAX_ROUTE_SIZE * UNIVERSAL_ADDRESS_SIZE];
    //size_t addr_list_elements = GNRC_SR_MAX_ROUTE_SIZE;
    //size_t element_size = UNIVERSAL_ADDRESS_SIZE;
    fib_sr_t *fib_sr = NULL;

    //DEBUG("Looking for route to parent: %s/%d\n", ipv6_addr_to_str(addr_str, (ipv6_addr_t *) parent, sizeof(addr_str)), UNIVERSAL_ADDRESS_SIZE);

    // Attempt to find an existing route to the parent
    int result = fib_sr_get_route(&table, node, UNIVERSAL_ADDRESS_SIZE, sr_iface_id, sr_flags,
                                  addr_list, addr_list_elements, element_size, false, &fib_sr);
    
    uint8_t *parent = addr_list;
    
    printf("parent: %s/%d\n",
                ipv6_addr_to_str(addr_str, (ipv6_addr_t *) parent, sizeof(addr_str)), UNIVERSAL_ADDRESS_SIZE);
    
    result = fib_sr_get_route(&table, parent, UNIVERSAL_ADDRESS_SIZE, sr_iface_id, sr_flags,
                                  addr_list, addr_list_elements, element_size, false, &fib_sr);


    //Initialize a new SR
    fib_sr_t *sr = NULL;

    if (fib_sr_create(&table, &sr, *sr_iface_id, *sr_flags, lifetime) == 0) {
        //DEBUG("Creating/Extending route for child: %s/%d\n", ipv6_addr_to_str(addr_str, (ipv6_addr_t *) child, sizeof(addr_str)), UNIVERSAL_ADDRESS_SIZE);
        
        // Append the parent route first
        if (result >= 0) {
            for (size_t i = 0; i < *addr_list_elements; ++i) {
                fib_sr_entry_append(&table, sr, &addr_list[i * *element_size], *element_size);
            }
        } else {
            fib_sr_entry_append(&table, sr, parent, UNIVERSAL_ADDRESS_SIZE);
        }
        // Append the child to the route
        fib_sr_entry_append(&table, sr, node, UNIVERSAL_ADDRESS_SIZE);
        // Attempt to find an existing route to the parent
        fib_sr_get_route(&table, node, UNIVERSAL_ADDRESS_SIZE, sr_iface_id, sr_flags,
                                  addr_list, addr_list_elements, element_size, false, &fib_sr);
        return 0;
        
    } else {
        DEBUG("Failed to create source route for child: %s/%d\n",
                ipv6_addr_to_str(addr_str, (ipv6_addr_t *) node, sizeof(addr_str)), UNIVERSAL_ADDRESS_SIZE);
    }
    return -1;
}*/

/*int gnrc_sr_add_new_node(uint8_t *child, uint8_t *parent, kernel_pid_t sr_iface_id, uint32_t sr_flags, uint32_t lifetime) {
    //Initialize a new SR
    fib_sr_t *sr = NULL;
    if (fib_sr_create(&table, &sr, sr_iface_id, sr_flags, lifetime) == 0) {
    fib_sr_entry_append(&table, sr, parent, UNIVERSAL_ADDRESS_SIZE);
    // Append the child to the route
    fib_sr_entry_append(&table, sr, child, UNIVERSAL_ADDRESS_SIZE);
    return 0;
    } else {
        return -1;
    }
}*/
int gnrc_sr_delete_route(uint8_t *dst, size_t dst_size) {
    kernel_pid_t sr_iface_id = 0;
    uint32_t sr_flags = 0;
    fib_sr_t *fib_sr = NULL;
    uint8_t addr_list[50 * UNIVERSAL_ADDRESS_SIZE];
    size_t addr_list_elements = 50;
    size_t element_size = UNIVERSAL_ADDRESS_SIZE;

    // Try to find the existing route
    int result = fib_sr_get_route(&table, dst, dst_size, &sr_iface_id, &sr_flags,
                                  addr_list, &addr_list_elements, &element_size, false, &fib_sr);
                                  
    if (result >= 0 && fib_sr != NULL) {
        //fib_sr_entry_delete(&table, fib_sr, dst, dst_size, false);
        // Delete the existing route
        //uint32_t lifetime =0 ;
        //if (fib_sr_set(&table, fib_sr, &sr_iface_id, &sr_flags, &lifetime) == 0) {
        if (fib_sr_entry_delete(&table, fib_sr, dst, dst_size, true) == 0 && fib_sr_delete(&table, fib_sr) == 0) {
            printf("Route to destination deleted successfully.\n");
            return 0;
        } else {
            printf("Failed to delete route to destination.\n");
            return -1;
        }
    } else {
        printf("No existing route found to delete.\n");
        return result; // Return error code if route wasn't found
    }
    return 0;
}

int gnrc_sr_add_new_dst(uint8_t *child, uint8_t *parent, kernel_pid_t sr_iface_id, uint32_t sr_flags, uint32_t lifetime) {

    //Initials for getting the parent's route
    uint8_t addr_list[GNRC_SR_MAX_ROUTE_SIZE * UNIVERSAL_ADDRESS_SIZE];
    size_t addr_list_elements = GNRC_SR_MAX_ROUTE_SIZE;
    size_t element_size = UNIVERSAL_ADDRESS_SIZE;
    fib_sr_t *fib_sr = NULL;

    DEBUG("Looking for route to parent: %s/%d\n", 
            ipv6_addr_to_str(addr_str, (ipv6_addr_t *) parent, sizeof(addr_str)), UNIVERSAL_ADDRESS_SIZE);
    
    /*// Delete any previous route to the child before creating a new one
    if (gnrc_sr_delete_route(child, UNIVERSAL_ADDRESS_SIZE) == 0) {
        printf("Previous route deleted. Installing new route...\n");
    } else {
        printf("No previous route to delete or deletion failed.\n");
    }*/

    //addr_list_elements = 0;
    // Attempt to find an existing route to the parent
    int result = fib_sr_get_route(&table, parent, UNIVERSAL_ADDRESS_SIZE, &sr_iface_id, &sr_flags,
                                  addr_list, &addr_list_elements, &element_size, false, &fib_sr);
        //printf("1\n");
    //Initialize a new SR
    fib_sr_t *sr = NULL;

    if (fib_sr_create(&table, &sr, sr_iface_id, sr_flags, lifetime) == 0) {
        sr->sr_dest = NULL;
        sr->sr_path = NULL;
            //printf("2\n");
        DEBUG("Creating/Extending route for child: %s/%d\n",
                ipv6_addr_to_str(addr_str, (ipv6_addr_t *) child, sizeof(addr_str)), UNIVERSAL_ADDRESS_SIZE);
        
        // Append the parent route first
        if (result >= 0 ) {
                printf("3\n");
                //printf("elements: %d\n", addr_list_elements);
            
            for (size_t i = 0; i < addr_list_elements; ++i) {
                printf("i=%d\n", i);
                
                /*int search = fib_sr_search(&table, sr, &addr_list[i * element_size], element_size, &entry);
                printf("search=%d\n", search);*/
                printf("i: %s/%d\n",
                ipv6_addr_to_str(addr_str, (ipv6_addr_t *) &addr_list[i * element_size], sizeof(addr_str)), UNIVERSAL_ADDRESS_SIZE);
                fib_sr_entry_append(&table, sr, &addr_list[i * element_size], element_size);
            }
        } else {
                //printf("4\n");
            fib_sr_entry_append(&table, sr, parent, UNIVERSAL_ADDRESS_SIZE);
        }
        // Append the child to the route
        fib_sr_entry_append(&table, sr, child, UNIVERSAL_ADDRESS_SIZE);
            //printf("5\n");
        return 0;
    } else {
        DEBUG("Failed to create source route for child: %s/%d\n",
                ipv6_addr_to_str(addr_str, (ipv6_addr_t *) child, sizeof(addr_str)), UNIVERSAL_ADDRESS_SIZE);
    }
    return -1;
}

void gnrc_sr_table_print(void) {
    DEBUG("FIB Table Content:\n");
    //fib_print_fib_table(&table); // Assuming this function prints all routesa
    fib_print_routes(&table); // Assuming this function prints all routes
    
}
