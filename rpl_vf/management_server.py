#!/usr/bin/env python3

import os
import subprocess
import sys
from pathlib import Path
import time


# --- Configuration ---
SUIT_GEN = "/RIOT/dist/tools/suit/gen_manifest.py"
SUIT_TOOL = "/RIOT/dist/tools/suit/suit-manifest-generator/bin/suit-tool"
KEY_FILE = "/RIOT/keys/default.pem"
NODE_CLASS = "iotlab-m3"  # change if needed
SEQ_NUMBER = 1
SERVER_ADDR = "SERVER_IP"  # Replace with actual server address
INSTALL_FLAG = 0
ROOT_ID = 250  # Root node ID, change if needed

#--- Node Dictionary ---
NODES = {
    ''' NODE ID : {"link_local":local_link_addr, "global":global_addr, "parent": parent_local_link_addr} '''
    # Add more entries as needed

}


# --- VM Configuration per Binary File ---
VM_CONFIG = {
    ''' "file_name": {"vm_id": <id>, "hook_trigger": <trigger>, "next_vm": <next_vm>, "reset_flag": <reset_flag>, "install_flag": <install_flag>} '''
    # Add more entries as needed
}

# --- Helper Functions ---

def run(cmd):
    print(f"[RUN] {cmd}")
    subprocess.run(cmd, shell=True, check=False)

def create_and_sign_manifest(bin_path, output_dir):
    file_stem = bin_path.stem
    tmp_file = output_dir / f"{file_stem}.tmp"
    manifest_file = output_dir / f"{file_stem}_manifest"
    signed_file = output_dir / f"{file_stem}.signed"

    # Step 1: Create tmp manifest
    run(f"{SUIT_GEN} --urlroot coap://[{SERVER_ADDR}] --uuid-class {NODE_CLASS} "
        f"--seqnr {SEQ_NUMBER} -o {tmp_file} {bin_path}:0:ram:0")

    # Step 2: Create manifest
    run(f"{SUIT_TOOL} create -f suit -i {tmp_file} -o {manifest_file}")

    # Step 3: Sign manifest
    run(f"{SUIT_TOOL} sign -k {KEY_FILE} -m {manifest_file} -o {signed_file}")

    return signed_file.name


def poll_download_status(client_addr, timeout=500, interval=2):
    """Polls the /suit/status endpoint until status is 'downloaded' or timeout is reached."""

    start = time.time()
    print(f"[WAIT] Waiting for {client_addr} to finish download...")

    while time.time() - start < timeout:
        result = subprocess.run(
            f"aiocoap-client -m GET coap://[{client_addr}]/suit/status",
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL
        )
        status = result.stdout.decode().strip()
        if "downloaded" in status:
            print(f"[OK] Download complete on {client_addr}")
            return True
        elif "failed" in status:
            print(f"[ERROR] Download failed on {client_addr}")
            return False

        print(f"[WAIT] Still downloading... ({status})")
        time.sleep(interval)

    print(f"[TIMEOUT] Node {client_addr} did not finish downloading in time.")
    return False


def send_manifest(client_addr, file_name):
    print(f"Starting update to {client_addr} with {file_name}")
    start_time = time.time()

    # Trigger update
    run(f"aiocoap-client -m POST coap://[{client_addr}]/suit/trigger "
        f"--payload coap://[{SERVER_ADDR}]/{file_name}")
    
     # Wait for node to download manifest
    success = poll_download_status(client_addr)

    end_time = time.time()
    elapsed = end_time - start_time
    status = "OK" if success else "FAIL"
    print(f"Update to {client_addr} {status} in {elapsed:.2f} seconds\n")

    with open("update_times.csv", "a") as f:
        f.write(f"{file_name},{client_addr},{elapsed:.2f}\n")

    return success

def send_update(client_addr, vm_id, hook_trigger, next_vm, reset_flag, install_flag):
    # # Update VM
    payload = f"{vm_id},{hook_trigger},{next_vm},{reset_flag},{install_flag}"
    run(f"aiocoap-client -m POST coap://[{client_addr}]/fc/update --payload {payload}")


# --- Main Execution ---

def update_root(folder_path):
    INTERVAL = 5
    ordered_files = ['dao_recv', 'dao_send2', 'dao_send', 'root']

    for file_stem in ordered_files:
        bin_file = folder_path / f"{file_stem}.bin"
        
        print(f"\nProcessing {bin_file.name}")
        signed_file_name = create_and_sign_manifest(bin_file, folder_path)

        file_stem = bin_file.stem
        if file_stem not in VM_CONFIG:
            print(f"Warning: No VM config found for {file_stem}, skipping...")
            continue

        config = VM_CONFIG[file_stem]

        node_info = NODES[ROOT_ID]
        client_addr = node_info["global"]
        success = send_manifest(client_addr, signed_file_name)
        if not success:
            print(f"[SKIP] Skipping update/install for {client_addr} due to failed download")

        # Give the needed time to finish downloading and update
        time.sleep(INTERVAL)
        
        # Update VM
        client_addr = node_info["global"]
        send_update(
            client_addr,
            vm_id=config["vm_id"],
            hook_trigger=config["hook_trigger"],
            next_vm=config["next_vm"],
            reset_flag=config["reset_flag"],
            install_flag=config["install_flag"],
        )
    
    time.sleep(INTERVAL)

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 deploy_updates.py <bin_folder>")
        sys.exit(1)

    folder_path = Path(sys.argv[1])

    # Delete old update_times.csv if it exists
    csv_path = Path("update_times.csv")
    if csv_path.exists():
        print("[INFO] Removing old update_times.csv...")
        csv_path.unlink()

    print(f"Starting updating process.. ")
    start_time = time.time()

    ordered_files = ['dao_recv', 'dao_send2', 'dao_send', 'root']

    for file_stem in ordered_files:
        bin_file = folder_path / f"{file_stem}.bin"

        if not bin_file.exists():
            print(f"[WARNING] File {bin_file.name} not found, skipping...")
            continue

        # Skip root for normal nodes
        if file_stem == 'root':
            continue

        print(f"\nProcessing {bin_file.name}")
        signed_file_name = create_and_sign_manifest(bin_file, folder_path)

        if file_stem not in VM_CONFIG:
            print(f"Warning: No VM config found for {file_stem}, skipping...")
            continue

        config = VM_CONFIG[file_stem]

        for node_id, node_info in NODES.items():
            if node_id == ROOT_ID:
                continue

            client_addr = node_info["global"]
            success = send_manifest(client_addr, signed_file_name)
            if not success:
                print(f"[SKIP] Skipping update/install for {client_addr} due to failed download")
                continue


        for node_id, node_info in NODES.items():
            if (node_id == ROOT_ID):
                continue
            # Update VM
            client_addr = node_info["global"]
            send_update(
                client_addr,
                vm_id=config["vm_id"],
                hook_trigger=config["hook_trigger"],
                next_vm=config["next_vm"],
                reset_flag=config["reset_flag"],
                install_flag=config["install_flag"],
            )

    # After all nodes, finally update the root
    update_root(folder_path)


    end_time = time.time()
    elapsed = end_time - start_time
    print(f"The whole Update process completed in {elapsed:.2f} seconds\n")

    with open("update_times.csv", "a") as f:
        f.write(f"Update process,all clients,{elapsed:.2f}\n")

if __name__ == "__main__":
    main()
