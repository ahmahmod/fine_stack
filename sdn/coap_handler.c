/*
 * Copyright (C) 2024 Ahmad Mahmod <https://ahmahmod.github.io/>
 *
 */

//#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "net/gcoap.h"
#include "net/nanocoap.h"
#include "suit/transport/coap.h"
#include "suit/storage.h"
#include "suit/storage/ram.h"

#define ENABLE_DEBUG 0
#include "debug.h"
#if USE_FC
#include "femtocontainer/femtocontainer.h"
#include "femtocontainer/shared.h"
#include "fc_array.h"


#define BUFFER_SIZE 256

static uint8_t *_get_slot_content(char *slot, size_t *length){
    /*Get the payload in the Slot*/
    suit_storage_t *storage = suit_storage_find_by_id(slot);
    if (!storage) {
        DEBUG("No storage with id \"%s\" present\n", slot);
        return NULL;
    }
    suit_storage_set_active_location(storage, slot);
    if (suit_storage_has_readptr(storage)) {
        const uint8_t *mem_region;
        suit_storage_read_ptr(storage, &mem_region, length);
        return (void *) mem_region;
    }
    else {
        DEBUG("Empty Slot");
        return NULL;
    }
}

/**
 * @brief Parses comma-separated data string into provided integer variables.
 * 
 * @param data          Input string containing comma-separated values
 * @param vm_id         Parsed virtual machine identifier
 * @param hook_trigger  Parsed hook trigger identifier
 * @param next_vm_id    Parsed next VM identifier
 * @param reset         Parsed reset flag
 * 
 * @return 0 on success, -1 on error
 */

static int _parse_data(const char *data, size_t data_len, int8_t *vm_id, int8_t *hook_trigger, 
    int8_t *next_vm_id, int8_t *reset, int8_t *install) {
    if (data_len >= BUFFER_SIZE) {
    DEBUG("Error: Payload too large for buffer.\n");
    return -1;
    }

    char buffer[BUFFER_SIZE];
    strcpy(buffer, data);
    buffer[data_len] = '\0'; // Null-terminate the string

    char *token = strtok(buffer, ",");
    if (token) *vm_id = strtol(token, NULL, 10);

    token = strtok(NULL, ",");
    if (token) *hook_trigger = strtol(token, NULL, 10);

    token = strtok(NULL, ",");
    if (token) *next_vm_id = strtol(token, NULL, 10);

    token = strtok(NULL, ",");
    if (token) *reset = strtol(token, NULL, 10);

    token = strtok(NULL, ",");
    if (token) *install = strtol(token, NULL, 10);
    else *install = 0;  // Optional: default to 0 if not present

    return 0;
}


/**
 * @brief Handles the update of a function call via CoAP.
 *
 * @param pdu    CoAP packet containing the payload
 * @param buf    Buffer for the reply
 * @param len    Length of the buffer
 * @param ctx    Context pointer (unused)
 *
 * @return ssize_t Size of the response, or -1 on error
 */

static ssize_t _update_fc(coap_pkt_t *pdu, uint8_t *buf, size_t len, void *ctx)
{
    (void) ctx;
    // (void) buf;

    if (pdu->payload == NULL || pdu->payload_len == 0) {
        DEBUG("Error: No payload provided.\n");
        return -1;
    }

    /* Extract data from the POST payload */
    int8_t vm_id=0, hook_trigger=0, next_vm_id=-1, reset=0, install=0;
    if (_parse_data((const char *)pdu->payload, pdu->payload_len, &vm_id, &hook_trigger, &next_vm_id, &reset, &install) < 0) {
        DEBUG("Error: Parsing data failed.\n");
        const char *reply = "Failed";
        return coap_reply_simple(pdu, COAP_CODE_404, buf, len, 0, (uint8_t*)reply, strlen(reply));
    }

    // new vms are always installed in slot 0
    char slot[] = ".ram.0";

    /* Read slot content */
    size_t length = 0;
    uint8_t *mem_region = _get_slot_content(slot, &length);
    if (!mem_region || length == 0) {
        DEBUG("Error: Slot content retrieval failed.\n");
        const char *reply = "Failed";
        return coap_reply_simple(pdu, COAP_CODE_404, buf, len, 0, (uint8_t*)reply, strlen(reply));
    }

    /* Copy the data from the slot to a memory location */
    uint8_t *new_binary = (uint8_t *)malloc(length);
    if (!new_binary) {
        DEBUG("Memory allocation failed!\n");
        const char *reply = "Failed";
        return coap_reply_simple(pdu, COAP_CODE_404, buf, len, 0, (uint8_t*)reply, strlen(reply));
    }
    memcpy(new_binary, mem_region, length);
    
    // install the vm properly
    int code = fc_array_vm_install(vm_id, hook_trigger, next_vm_id, new_binary, length, reset, true, install);

    if (code < 0){
        DEBUG("Error: Updating failed.\n");
        const char *reply = "Failed";
        return coap_reply_simple(pdu, COAP_CODE_404, buf, len, 0, (uint8_t*)reply, strlen(reply));
    }
    else{
        DEBUG("Successful Update\n");
        const char *reply = "Success";
        return coap_reply_simple(pdu, COAP_CODE_204, buf, len, 0, (uint8_t*)reply, strlen(reply));
    }
}

static ssize_t _trigger_hook(coap_pkt_t *pdu, uint8_t *buf, size_t len, void *ctx)
{
    (void) ctx;
    // (void) buf;

    if (pdu->payload == NULL) {
        DEBUG("Error: No payload provided.\n");
        return -1;
    }

    // Ensure payload is null-terminated
    char payload_str[16] = {0};  // large enough for an int
    size_t copy_len = (pdu->payload_len < sizeof(payload_str) - 1) ? pdu->payload_len : sizeof(payload_str) - 1;
    memcpy(payload_str, pdu->payload, copy_len);
    payload_str[copy_len] = '\0';

    /* Extract data from the POST payload */
    int8_t hook_number = atoi(payload_str);
    DEBUG("Hook number: %d\n", hook_number);
    if (hook_number < 0 || hook_number >= FC_HOOK_NUM) {
        DEBUG("Error: Invalid hook number.\n");
        return -1;
    }
    int64_t script_res = 0;
    int hook_ctx = 0;
    uint32_t start = ztimer_now(ZTIMER_MSEC);
    f12r_hook_execute(hook_number, &hook_ctx, sizeof(hook_ctx), &script_res);
    uint32_t end = ztimer_now(ZTIMER_MSEC);
    DEBUG("Hook %d executed in: %" PRIu32 " ms\n", hook_number, end-start);

    if (script_res < 0){
        DEBUG("Error: Hook execution failed.\n");
        const char *reply = "Failed";
        return coap_reply_simple(pdu, COAP_CODE_404, buf, len, 0, (uint8_t*)reply, strlen(reply));
    }
    else{
        DEBUG("Successful Hook execution\n");
        const char *reply = "Success";
        return coap_reply_simple(pdu, COAP_CODE_204, buf, len, 0, (uint8_t*)reply, strlen(reply));
    }
}


static ssize_t _instal_array(coap_pkt_t *pdu, uint8_t *buf, size_t len, void *ctx)
{
    (void) ctx;
    //(void) buf;

    // install the vm properly
    int code = fc_array_install();

    if (code < 0){
        DEBUG("Error: Installation failed.\n");
        const char *reply = "Failed";
        return coap_reply_simple(pdu, COAP_CODE_404, buf, len, 0, (uint8_t*)reply, strlen(reply));
    }
    else{
        DEBUG("Successful Install\n");
        const char *reply = "Success";
        //DEBUG("VM %d successfuly attached to Hook %d\n", vm_id, hook_trigger);
        return coap_reply_simple(pdu, COAP_CODE_204, buf, len, 0, (uint8_t*)reply, strlen(reply));
    }
}
#endif

/* must be sorted by path (ASCII order) */
const coap_resource_t coap_resources[] = {
    COAP_WELL_KNOWN_CORE_DEFAULT_HANDLER,

#if USE_FC
    { "/fc/install", COAP_METHOD_PUT | COAP_METHOD_POST, _instal_array, NULL },
    { "/fc/trigger_hook", COAP_METHOD_PUT | COAP_METHOD_POST, _trigger_hook, NULL },
    { "/fc/update", COAP_METHOD_PUT | COAP_METHOD_POST, _update_fc, NULL },
#endif

    /* this line adds the whole "/suit"-subtree */
    SUIT_COAP_SUBTREE,  
};


const unsigned coap_resources_numof = ARRAY_SIZE(coap_resources);
