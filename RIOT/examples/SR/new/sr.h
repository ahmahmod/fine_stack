#ifndef SR_TABLE
#define SR_TABLE

#include <stdint.h>
#include <stddef.h>
#include "net/fib.h"

#ifndef GNRC_SR_MAX_ROUTE_SIZE
#define GNRC_SR_MAX_ROUTE_SIZE (10)
#endif

#ifndef GNRC_SR_FIB_TABLE_HEADER_ELEMENTS
#define GNRC_SR_FIB_TABLE_HEADER_ELEMENTS (2)
#endif

#ifndef GNRC_SR_FIB_TABLE_SIZE
#define GNRC_SR_FIB_TABLE_SIZE (30)
#endif

#ifndef GNRC_SR_FIB_TABLE_HEADER_SIZE
#define GNRC_SR_FIB_TABLE_HEADER_SIZE (30)
#endif

#ifndef GNRC_SR_FIB_TABLE_ENTRY_POOL_SIZE
#define GNRC_SR_FIB_TABLE_ENTRY_POOL_SIZE (30)
#endif




/**
 * @brief Initializes a FIB table for source routing.
 */
void gnrc_sr_initialize_table(ipv6_addr_t *root, kernel_pid_t iface);

/**
 * @brief Prints the current content of the FIB table.
 */
void gnrc_sr_table_print(void);

/**
 * @brief Prints the route for a node.
 *
 * @param[in] node Pointer to the node's address.
 */
void gnrc_sr_print_table_route(ipv6_addr_t *node);


/**
 * @brief Store a child-parent relationship in the table
 *
 * @param[in] child Pointer to the child's address.
 * @param[in] parent Pointer to the parent's address.
 * @param[in] sr_iface_id Pointer to the iface_id.
 * @param[in] sr_flags Pointer to set the flags.
 * @param[in] lifetime Pointer to set the current left lifetime.
 * @return 0 on success
 *         -1 on fail
 */
int gnrc_sr_add_new_dst(ipv6_addr_t *child, size_t prefix, ipv6_addr_t *parent, kernel_pid_t sr_iface_id, uint32_t sr_flags, uint32_t lifetime);

/**
 * @brief Delete a child-parent relationship.
 *
 * @param[in] dst_node Pointer to the destination address.
 * @param[in] dst_size The size of the destination address.
 * @return 0 on success
 *         -1 on fail
 *         -ENOENT on expired lifetime of the source route
 *         -EFAULT on fib_sr is NULL
*/
int gnrc_sr_delete_route(ipv6_addr_t *dst_node, size_t dst_size);

/**
 * @brief Builds source route for a destination node.
 *
 * @param[in] dst_node Pointer to the destination address.
 * @param[in] route_buffer Pointer to buffer to store the route in.
 * @param[in] route_length Pointer to store the length of the retrived route.
 * @return 0 on success
 *         -1 on fail
*/
int gnrc_sr_get_full_route(ipv6_addr_t *dst_node, ipv6_addr_t *route_buffer, size_t *route_length);

#endif // SR_H