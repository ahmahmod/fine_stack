#include <stdio.h>
#include "shell.h"
#include "msg.h"
#include "bpf.h"
#include "blob/fc/increment.bin.h"
#include "blob/fc1/new1.bin.h"

#define MAX_BPF_VMS 10

/* Pre-allocated stack for the virtual machines */
static uint8_t _stack[MAX_BPF_VMS][512] = { { 0 } };

/* Array to store multiple BPF VMs 
    It should be global to be accessed from the cmd functions*/
static bpf_t bpf_vms[MAX_BPF_VMS];

int update_cmd(int argc, char **argv)
{
    if (argc < 2) {
        printf("usage: %s <VM_ID> <application_len>\n", argv[0]);
        return 1;
    }

    /* Parse the VM ID and the application length */
    int vm_id = atoi(argv[1]);
    if (vm_id < 0 || vm_id >= MAX_BPF_VMS) {
        printf("Invalid VM ID. Must be between 0 and %d.\n", MAX_BPF_VMS - 1);
        return 1;
    }

    /* Update the specific VM's application_len */
    //int new_len = atoi(argv[2]);
    bpf_vms[vm_id].application = new1_bin;
    bpf_vms[vm_id].application_len = sizeof(new1_bin);

    printf("Updated VM %d application_len to %d\n", vm_id, sizeof(new1_bin));
    return 0;
}

int execute_cmd(int argc, char **argv)
{
    if (argc < 2) {
        printf("usage: %s <VM_ID>\n", argv[0]);
        return 1;
    }

    int vm_id = atoi(argv[1]);
    if (vm_id < 0 || vm_id >= MAX_BPF_VMS) {
        printf("Invalid VM ID. Must be between 0 and %d.\n", MAX_BPF_VMS - 1);
        return 1;
    }

    uint64_t ctx = 5;
    int64_t result = 0;

    int res = bpf_execute_ctx(&bpf_vms[vm_id], &ctx, sizeof(ctx), &result);
    printf("Executed VM %d, result: %ld, return code: %d\n", vm_id, (unsigned long)result, res);

    return 0;
}

static const shell_command_t shell_commands[] = {
    { "update", "Update a VM with a new application length", update_cmd },
    { "execute", "Execute a specific VM", execute_cmd },
    { NULL, NULL, NULL }
};

int main(void)
{
    /* Initialize the BPF subsystem */
    bpf_init();

    puts("Initializing BPF VMs...");
    
    /* Initialize multiple BPF VMs */
    for (int i = 0; i < MAX_BPF_VMS; i++) {
        bpf_vms[i] = (bpf_t) {
            .application = increment_bin,               /* The increment.bin content */
            .application_len = sizeof(increment_bin),   /* Length of the application */
            .stack = _stack[i],                         /* Preallocated stack */
            .stack_size = sizeof(_stack[i]),            /* And the length */
        };

        bpf_setup(&bpf_vms[i]);
        printf("Initialized VM %d at address: %p\n", i, (void*) &bpf_vms[i]);
    }
    printf("SIZE increment: %d\n", sizeof(increment_bin));
    printf("SIZE new1: %d\n", sizeof(new1_bin));

    /* start shell */
    puts("All up, running the shell now");
    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);

    return 0;
}
