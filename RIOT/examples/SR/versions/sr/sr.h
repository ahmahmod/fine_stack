#ifndef SR_H
#define SR_H

#include <stdint.h>
#include <stddef.h>
#include "net/fib.h"

#ifndef GNRC_SR_MAX_ROUTE_SIZE
#define GNRC_SR_MAX_ROUTE_SIZE (20)
#endif

#ifndef GNRC_SR_FIB_TABLE_SIZE
#define GNRC_SR_FIB_TABLE_SIZE (100)
#endif

#ifndef GNRC_SR_FIB_TABLE_HEADER_SIZE
#define GNRC_SR_FIB_TABLE_HEADER_SIZE (100)
#endif

#ifndef GNRC_SR_FIB_TABLE_ENTRY_POOL_SIZE
#define GNRC_SR_FIB_TABLE_ENTRY_POOL_SIZE (100)
#endif


/**
 * @brief Initializes a FIB table for source routing.
 *
 * @param[out] table Pointer to the FIB table to be initialized.
 * @param[in] meta Pointer to the metadata structure for source routes.
 * @param[in] headers Array of FIB source route headers.
 * @param[in] entry_pool Pool of FIB source route entries.
 * @param[in] pool_size Size of the entry pool.
 */
void gnrc_sr_initialize_table(void);


/**
 * @brief Prints the route from an address list.
 *
 * @param[in] addr_list Pointer to the address list containing the route.
 * @param[in] addr_list_elements The number of elements (hops) in the route.
 * @param[in] element_size The size of each address in bytes.
 */
void gnrc_sr_print_route(uint8_t *node);

int gnrc_sr_delete_route(uint8_t *dst, size_t dst_size);
/**
 * @brief Builds source routes for a child node, optionally using the parent's route.
 *
 * @param[in] table Pointer to the FIB table.
 * @param[in] child Pointer to the child's address.
 * @param[in] parent Pointer to the parent's address.
 */
int gnrc_sr_add_new_dst(uint8_t *child, uint8_t *parent, kernel_pid_t sr_iface_id, uint32_t sr_flags, uint32_t lifetime);

/**
 * @brief Prints the current content of the FIB table.
 *
 * @param[in] table Pointer to the FIB table to be printed.
 */
void gnrc_sr_table_print(void);



int gnrc_sr_add_new_node(uint8_t *child, uint8_t *parent, kernel_pid_t sr_iface_id, uint32_t sr_flags, uint32_t lifetime);

int gnrc_sr_get_route(uint8_t *node, kernel_pid_t *sr_iface_id, uint32_t *sr_flags, 
                        uint8_t *addr_list, size_t *addr_list_elements,  size_t *element_size,
                        uint32_t lifetime);
#endif // SR_H
