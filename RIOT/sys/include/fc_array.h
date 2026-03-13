/*
 * Copyright (C) 2024 Ahmad Mahmod <mahmod@unistra.fr>
 *
 */

/**
 * @defgroup    fc array pool
 * @ingroup     sys
 * @brief       Provides a pool for FCs in the system
 *
 * The target of this API is to provide a pool for FCs installation: add, insert, delete and append.
 * The API porvides function to deal with the FC by IDs reducing the code size for the aforementioned processes.
 *
 * @{
 *
 * @file
 * @brief       Femto Containers (FCs) pooling
 *
 * @author      Ahmad Mahmod <mahmod@unistra.fr>
 */



#ifndef FC_ARRAY_H
#define FC_ARRAY_H

#include <stddef.h>  // For size_t
#include "femtocontainer/femtocontainer.h"

#ifndef CONF_MAX_BPF_VMS
#define MAX_BPF_VMS (16)
#else
#define MAX_BPF_VMS CONF_MAX_BPF_VMS
#endif

#ifndef CONF_MAX_BPF_VMS_LIMIT
#define MAX_BPF_VMS_LIMIT (128)
#else
#define MAX_BPF_VMS_LIMIT CONF_MAX_BPF_VMS_LIMIT
#endif

typedef struct {
    f12r_hook_t *hook;
    f12r_t *fc;
    uint8_t *new_binary;
    size_t new_binary_len;
    f12r_hook_trigger_t trigger;
    int8_t next_index;
    bool init;
    bool dynamic; // check if the memeory allocated for the application is dynamic or static, to free dynamic data before update
    bool new_dynamic; // check if the new binary is dynamic or static, to free dynamic data before update
    bool installed;
    bool reset; // reset the previous hooks on installation
} vm_t;

// Array structure to hold pointers to f12r_hook_t elements
typedef struct {
    vm_t **data;   // Array of pointers to f12r_hook_t elements
    size_t size;          // Current number of elements
    size_t capacity;      // Maximum capacity
} fc_array_t;


// Initialize the array with a specified capacity
// Returns 0 on success and -1 on failure (e.g., memory allocation failure)
int fc_array_init(size_t capacity);

// Return a pointer to the element at index i
// Returns a pointer to the element on success, or NULL on failure (e.g., index out of bounds)
vm_t* fc_array_get(size_t index);

// Install all non-installed vms in the pool
// Return 0 on sucess, -1 on fail
int fc_array_install(void);


// Free the array and all its elements
// Returns 0 on success and -1 on failure (e.g., array already freed or uninitialized)
int fc_array_free(void);


int fc_array_vm_install (size_t index,  f12r_hook_trigger_t trigger, int8_t next_index, 
    uint8_t *new_binary, uint32_t length, bool reset, bool dynamic_mem, bool install);
#endif // FC_ARRAY_H
