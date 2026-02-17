#!/usr/bin/env python3
"""
Send (TRIO + STATE) exactly ONCE per node, node-by-node (sequential).

For each node (in sorted order):
  1) send trio: dao_recv -> dao_send2 -> dao_send
  2) send one state FC (depends on MODE + STATEFUL mapping)
Optional: you can include/exclude the root (ROOT_ID) in NODE_IDS.

Usage:
  python3 hybrid_update.py <bin_folder>
"""

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
INSTALL_FLAG = 0 #install afer update

MODE = 0 # Mode to change to: 0 - storing, 1 - non-storing
STATEFUL = 1 # Send state info or not
HOOK_NUMBER = 5  # Hook number to install new rules

# Send order
TRIO = ["dao_recv", "dao_send2", "dao_send"]

#--- Node Dictionary ---
NODES = {
    ''' NODE ID : {"link_local":local_link_addr, "global":global_addr, "parent": parent_local_link_addr} '''
    '''Example: "103": {"link_local": "fe80::acca:861e:a27:f66b", "global": "2001:660:4403:480:acca:861e:a27:f66b"}, "parent": "fe80::5820:f6f8:6ab6:dce4"}'''
    # Add more entries as needed

}

# --- VM Configuration per Binary File ---
VM_CONFIG = {
    ''' "file_name": {"vm_id": <id>, "hook_trigger": <trigger>, "next_vm": <next_vm>, "reset_flag": <reset_flag>, "install_flag": <install_flag>} '''
    '''
    Example: "dis_send":  {"vm_id": 0, "hook_trigger": 6, "next_vm": -1, "reset_flag": 1, "install_flag": INSTALL_FLAG}, \
             "state_a":   {"vm_id": 11, "hook_trigger": 5, "next_vm": -1, "reset_flag": 1, "install_flag": INSTALL_FLAG}, 
    '''
    # Add more entries as needed
}

# Example state mapping from your original (edit as needed)
# NOTE: only nodes in NODES will be updated.
STATE_MAP_STORING_STATEFUL = {
    ROOT_ID: "root_state_storing",  # root_state_storing.bin
    "103": "103_state_storing",         # 103_state_storing.bin
}
STATE_DEFAULT_STORING = "switch_storing_normal"

STATE_MAP_NONSTORING = {
    ROOT_ID: "root_state_non_storing",  # root_state_non_storing.bin
}
STATE_DEFAULT_NONSTORING = "switch_non_normal"

# ----------------------------
# Helpers
# ----------------------------
def coap_host(addr: str) -> str:
    """Bracket IPv6 addresses for CoAP URIs; leave IPv4/hostnames as-is."""
    return f"[{addr}]" if ":" in addr else addr


def run(cmd: str) -> None:
    print(f"[RUN] {cmd}")
    subprocess.run(cmd, shell=True, check=True)


def get_node_id_by_addr(addr: str):
    for node_id, node_info in NODES.items():
        if addr == node_info.get("global") or addr == node_info.get("link_local"):
            return node_id
    return None


def create_and_sign_manifest(bin_path: Path, output_dir: Path) -> str:
    """Creates and signs SUIT manifest for bin_path. Returns signed filename (basename)."""
    suit_gen = str(Path(SUIT_GEN).expanduser())
    suit_tool = str(Path(SUIT_TOOL).expanduser())
    key_file = str(Path(KEY_FILE).expanduser())

    file_stem = bin_path.stem
    tmp_file = output_dir / f"{file_stem}.tmp"
    manifest_file = output_dir / f"{file_stem}_manifest"
    signed_file = output_dir / f"{file_stem}.signed"

    run(
        f"{suit_gen} --urlroot coap://{coap_host(SERVER_ADDR)} --uuid-class {NODE_CLASS} "
        f"--seqnr {SEQ_NUMBER} -o {tmp_file} {bin_path}:0:ram:0"
    )
    run(f"{suit_tool} create -f suit -i {tmp_file} -o {manifest_file}")
    run(f"{suit_tool} sign -k {key_file} -m {manifest_file} -o {signed_file}")

    return signed_file.name


def poll_download_status(client_addr: str, timeout: int = 500, interval: int = 2) -> bool:
    """Polls /suit/status until 'downloaded' or 'failed' or timeout."""
    node_id = get_node_id_by_addr(client_addr) or client_addr
    start = time.time()
    print(f"[WAIT] Waiting for {node_id} to finish download...")

    while time.time() - start < timeout:
        result = subprocess.run(
            f"aiocoap-client -m GET coap://{coap_host(client_addr)}/suit/status",
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        status = result.stdout.decode(errors="ignore").strip()

        if "downloaded" in status:
            print(f"[OK] Download complete on {node_id}")
            return True
        if "failed" in status:
            print(f"[ERROR] Download failed on {node_id}: {status}")
            return False

        print(f"[WAIT] Still downloading... ({status})")
        time.sleep(interval)

    print(f"[TIMEOUT] Node {node_id} did not finish downloading in time.")
    return False


def send_manifest(client_addr: str, signed_filename: str) -> bool:
    """Triggers /suit/trigger with payload pointing to server file; waits download completion."""
    node_id = get_node_id_by_addr(client_addr) or client_addr
    print(f"[SEND] Update to {node_id} with {signed_filename}")
    start_time = time.time()

    run(
        f"aiocoap-client -m POST coap://{coap_host(client_addr)}/suit/trigger "
        f"--payload coap://{coap_host(SERVER_ADDR)}/{signed_filename}"
    )

    success = poll_download_status(client_addr)

    elapsed = time.time() - start_time
    print(f"[SEND] {node_id} {'OK' if success else 'FAIL'} in {elapsed:.2f}s\n")

    with open("update_times.csv", "a") as f:
        f.write(f"{signed_filename},{client_addr},{elapsed:.2f}\n")

    return success


def state_file_for_node(node_id: str, mode: int, stateful: int) -> str:
    """Return the FC stem (without .bin) to use as state info for this node."""
    if mode == 0:  # storing
        if stateful:
            return STATE_MAP_STORING_STATEFUL.get(node_id, STATE_DEFAULT_STORING)
        return STATE_DEFAULT_STORING
    # non-storing
    return STATE_MAP_NONSTORING.get(node_id, STATE_DEFAULT_NONSTORING)


# ----------------------------
# Main
# ----------------------------
def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python3 deploy_once_per_node.py <bin_folder>")
        sys.exit(1)

    folder_path = Path(sys.argv[1])

    # fresh timing file
    csv_path = Path("update_times.csv")
    if csv_path.exists():
        print("[INFO] Removing old update_times.csv...")
        csv_path.unlink()

    print("[INFO] Starting node-by-node update (TRIO + STATE once per node).")
    start_time = time.time()

    # 1) Pre-sign trio binaries once
    trio_signed = {}
    for stem in TRIO:
        bin_file = folder_path / f"{stem}.bin"
        if not bin_file.exists():
            print(f"[ERROR] Missing trio file: {bin_file}")
            sys.exit(1)
        trio_signed[stem] = create_and_sign_manifest(bin_file, folder_path)

    # 2) Pre-sign all possible state binaries once (only those that exist)
    # Build the set of state stems we might need for nodes in NODES.
    needed_state_stems = {state_file_for_node(nid, MODE, STATEFUL) for nid in NODES.keys()}
    state_signed = {}
    for stem in sorted(needed_state_stems):
        bin_file = folder_path / f"{stem}.bin"
        if not bin_file.exists():
            print(f"[ERROR] Missing state file: {bin_file} (needed by some node).")
            sys.exit(1)
        state_signed[stem] = create_and_sign_manifest(bin_file, folder_path)

    # Choose node order (numeric if possible)
    node_ids = sorted(NODES.keys(), key=lambda x: int(x) if str(x).isdigit() else str(x))

    # If you want to skip root (ROOT_ID) because it's not in NODES anyway, nothing to do.
    # If you include root in NODES later and want to skip it, uncomment:
    # node_ids = [nid for nid in node_ids if nid != ROOT_ID]

    for node_id in node_ids:
        node = NODES.get(node_id)
        if not node or "global" not in node:
            print(f"[WARNING] Skipping node {node_id}: missing info/global.")
            continue

        addr = node["global"]
        print(f"\n====================")
        print(f"[NODE] {node_id} ({addr})")
        print(f"====================")

        # A) Send trio once
        for stem in TRIO:
            signed_name = trio_signed[stem]
            print(f"[TRIO] Sending {stem}.bin -> {signed_name}")
            ok = send_manifest(addr, signed_name)
            if not ok:
                print(f"[STOP] Node {node_id}: trio file {stem} failed. Skipping STATE for this node.")
                break
            time.sleep(3)
        else:
            # B) Send state info once (only if trio fully succeeded)
            state_stem = state_file_for_node(node_id, MODE, STATEFUL)
            signed_state = state_signed[state_stem]
            print(f"[STATE] Sending {state_stem}.bin -> {signed_state}")
            ok = send_manifest(addr, signed_state)
            if not ok:
                print(f"[WARN] Node {node_id}: STATE download failed.")
            time.sleep(3)

        # Gap between nodes
        time.sleep(5)

    elapsed = time.time() - start_time
    print(f"\n[INFO] Whole update process completed in {elapsed:.2f} seconds")

    with open("update_times.csv", "a") as f:
        f.write(f"Update process,all clients,{elapsed:.2f}\n")


if __name__ == "__main__":
    main()