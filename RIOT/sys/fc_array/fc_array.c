#include <stdlib.h>  // For malloc, free
#include <stdio.h>   // For DEBUG
#include "irq.h"
#include "fc_array.h"
#include "femtocontainer/femtocontainer.h"

#define ENABLE_DEBUG 0
#include "debug.h"

// Static global variable for the array
static fc_array_t global_array;

// Function to resize the array when it is full
static int _fc_array_resize(void) {
    size_t new_capacity = global_array.capacity * 2;
    
    if (new_capacity > MAX_BPF_VMS_LIMIT){
        DEBUG("VMs Limit has been accessed");
        return -1;
    }

    DEBUG("Resizing array from %u to %u...\n", global_array.capacity, new_capacity);

    // Allocate a new larger array
    vm_t **new_data = (vm_t **)malloc(new_capacity * sizeof(vm_t *));
    if (!new_data) {
        DEBUG("Error: Memory allocation failed during resize.\n");
        return -1;  // Return -1 on memory allocation failure
    }

    // Copy elements from old array to new array
    for (size_t i = 0; i < global_array.capacity; ++i) {
        new_data[i] = global_array.data[i];
    }

    // Initialize new elements
    for (size_t i = global_array.capacity; i < new_capacity; ++i) {
        new_data[i] = (vm_t *)malloc(sizeof(vm_t));
        new_data[i]->hook = NULL;
        new_data[i]->init = 0;
    }

    printf("Free old arary.\n");
    // Free the old array
    free(global_array.data);
    printf("Free old arary.\n");

    // Update the global array with the new one
    global_array.data = new_data;
    global_array.capacity = new_capacity;

    return 0;  // Success
}

// Initialize the array with a specified capacity
int fc_array_init(size_t capacity) {
    global_array.data = (vm_t **)malloc(capacity * sizeof(vm_t *));
    if (!global_array.data) {
        DEBUG("Error: Memory allocation failed during initialization.\n");
        return -1;  // Return -1 on memory allocation failure
    }

    for (size_t i=0;  i<capacity; i++){
        global_array.data[i] = (vm_t *)malloc(sizeof(vm_t));
        global_array.data[i]->hook = NULL;
        global_array.data[i]->init = 0;
    }

    global_array.size = 0;
    global_array.capacity = capacity;

    DEBUG("Array initialized with capacity: %u\n", capacity);

    return 0;  // Success
}

// Install all non-installed VMS
int fc_array_install(void) {
    
    for (size_t index=0;  index<global_array.capacity; index++){
        if (global_array.data[index] == NULL || 
            global_array.data[index]->fc == NULL || 
            global_array.data[index]->hook == NULL) {
            DEBUG("Error: NULL pointer at index %u\n", index);
            continue;
        }
        DEBUG("Installing VM at index: %u, hook: %u\n", index, global_array.data[index]->trigger);
        
        if (!(global_array.data[index]->installed)){
            // Free up the previous application memory
            if (((global_array.data[index]->fc->application) != NULL) && (global_array.data[index]->dynamic)){
                free(global_array.data[index]->fc->application);
                global_array.data[index]->hook->application = NULL;
            }
            global_array.data[index]->fc->application = global_array.data[index]->new_binary;
            global_array.data[index]->fc->application_len = global_array.data[index]->new_binary_len;
            global_array.data[index]->dynamic = global_array.data[index]->new_dynamic;

            f12r_setup(global_array.data[index]->fc);
            global_array.data[index]->hook->application = global_array.data[index]->fc;

            int8_t ni = global_array.data[index]->next_index;
            if (ni < 0 || (size_t)ni >= global_array.capacity) {
                global_array.data[index]->hook->next = NULL;
            }
            else {
                global_array.data[index]->hook->next = global_array.data[ni]->hook;
            }

            unsigned state = irq_disable();
            f12r_hook_install(global_array.data[index]->hook, global_array.data[index]->trigger, global_array.data[index]->reset);
            irq_restore(state);
        }
    }
    DEBUG("Array Installed\n");

    return 0;  // Success
}


// Return a pointer to the element at index i
vm_t* fc_array_get(size_t index) {
    if (index >= global_array.capacity) {
        DEBUG("Error: Index out of bounds, cannot retrieve element.\n");
        return NULL;
    }

    return global_array.data[index];
}


// Free the entire array and its elements
int fc_array_free(void) {
    if (!global_array.data) {
        DEBUG("Error: No array to free.\n");
        return -1;  // Return -1 if the array is already freed or uninitialized
    }

    for (size_t i = 0; i < global_array.capacity; ++i) {
        free(global_array.data[i]);  // Free each allocated f12r_hook_t
    }
    free(global_array.data);         // Free the array of pointers
    DEBUG("Array and its elements have been freed.\n");

    return 0;  // Success
}

static int _init_fc(f12r_t *fc, uint8_t *new_binary, uint32_t length){
    static uint8_t _stack[512];
    // static uint8_t _stack[512];
    *fc = (f12r_t) {
        .application = new_binary,               
        .application_len = length,   
        .stack = _stack,                         
        .stack_size = sizeof(_stack),            
    };
    return 0;
}

static int _vm_update(size_t index, f12r_hook_trigger_t trigger, int8_t next_index, 
        uint8_t *new_binary, uint32_t length, bool reset, bool dynamic_mem, bool install)
{
    printf("index: %d, trigger: %d, next vm: %d, reset: %d, dynamic: %d, install: %d\n",
           index, trigger, next_index, reset, dynamic_mem, install);


    if (global_array.data[index]->hook == NULL || global_array.data[index]->hook->application == NULL) {
        DEBUG("Error: Hook or application is NULL.\n");
        return -1;
    }
    if (new_binary == NULL){
        DEBUG("Error: New binary is NULL.\n");
        return -1;
    }

    if(new_binary != NULL){
        global_array.data[index]->new_binary = new_binary;
        global_array.data[index]->new_binary_len = length;
    }

    /* Hook installation */
    if (install){
        // Free up the previous application memory
        if (((global_array.data[index]->fc->application) != NULL) && (global_array.data[index]->dynamic)){
            free(global_array.data[index]->fc->application);
            // global_array.data[index]->hook->application->application = NULL;
        }
        global_array.data[index]->fc->application = new_binary;
        global_array.data[index]->fc->application_len = length;
        global_array.data[index]->dynamic = dynamic_mem;

        f12r_setup(global_array.data[index]->fc);

        if ((size_t)next_index >= global_array.capacity || next_index < 0){
            global_array.data[index]->hook->next = NULL;
        }
        else {
            global_array.data[index]->hook->next = global_array.data[next_index]->hook;
        }

        unsigned state = irq_disable();
        f12r_hook_install(global_array.data[index]->hook, trigger, reset);
        irq_restore(state);
    }
    global_array.data[index]->new_dynamic = dynamic_mem;
    global_array.data[index]->trigger = trigger;
    global_array.data[index]->installed = install; 
    global_array.data[index]->reset = reset;
    global_array.data[index]->next_index = next_index;
    
    return 0;
}

static int _vm_init(size_t index, f12r_hook_trigger_t trigger, int8_t next_index, 
        uint8_t *new_binary, uint32_t length,  bool reset, bool dynamic_mem, bool install)
{
    if (global_array.data[index] == NULL) {
        DEBUG("Error: global_array.data[%u] is NULL\n", index);
        return -1;
    }

    (void) dynamic_mem;   
    /*Initialize the new FC*/
    f12r_t *fc = (f12r_t *) malloc(sizeof(f12r_t));
    if (!fc){
        DEBUG("Error: FC Memory allocation failed during malloc.\n");
        return -1;  // Return -1 on memory allocation failure
    }
    if (_init_fc(fc, new_binary, length) < 0){
        DEBUG("Error: FC initialization failed.\n");
        return -1;  // Return -1 on memory allocation failure
    }


    /*Initiliaze the new hook*/
    f12r_hook_t *hook = (f12r_hook_t *) malloc(sizeof(f12r_hook_t));
    if (!hook) {
        free(fc);
        DEBUG("Error: Hook Memory allocation failed during malloc.\n");
        return -1;  // Return -1 on memory allocation failure
    }
    hook->application = fc;

    if ((next_index < 0) || ((size_t)next_index >= global_array.capacity) || !global_array.data[next_index]) {
        hook->next = NULL;
    }
    else {
        hook->next = global_array.data[next_index]->hook;
    }

    /* Configure the vm */
    global_array.data[index]->hook = hook;
    global_array.data[index]->fc = fc;
    global_array.data[index]->trigger = trigger;
    global_array.data[index]->init = true;
    global_array.data[index]->dynamic = dynamic_mem;
    global_array.data[index]->new_dynamic = false;
    global_array.data[index]->installed = install; 
    global_array.data[index]->reset = reset; 

    f12r_setup(global_array.data[index]->hook->application);

    /*Hook installation*/
    if (install){
        unsigned state = irq_disable();
        f12r_hook_install(global_array.data[index]->hook, global_array.data[index]->trigger, global_array.data[index]->reset);
        irq_restore(state);
    }

    return 0;
}

int fc_array_vm_install(size_t index,  f12r_hook_trigger_t trigger, int8_t next_index, 
                    uint8_t *new_binary, uint32_t length, bool reset, bool dynamic_mem, bool install)
{
    if(index >= 2*global_array.capacity){
        return -1; // Return -1 if index out of double capacity (capacity after resizing)
    }

    // Check if the address is in the bounds
    if (index >= global_array.capacity) {
        DEBUG("Resizing FCs array..\n");
        if (_fc_array_resize() < 0){
            return -1;  // Return -1 if resizing failed
        }
    }
    
    /* Update if already initialized */
    if(global_array.data[index]->init){
        DEBUG("Updating a FC..\n");
        return _vm_update(index, trigger, next_index, new_binary, length, reset, dynamic_mem, install);
    }
    else { /*Initiliaze if it's not*/
        DEBUG("Installing a new FC..\n");
        return _vm_init(index, trigger, next_index, new_binary, length, reset, dynamic_mem, install);
    }
}