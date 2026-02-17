#!/usr/bin/env python3
import os
import sys
import time
import asyncio
import subprocess
from pathlib import Path
import threading  # add this
import shlex
import hashlib


from aiocoap import resource, Context, Message, Code

FILES_PORT = 5685  # separate port for file server

# CoAP content-format numbers (from IANA registry)
TEXT_PLAIN = 0
APPLICATION_OCTET_STREAM = 42


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

# For mapping node_id -> FC filename (without .bin)
NODE_TO_FILE = {
    "NODE_ID": "FILE_NAME",
}
DEFAULT_FILE = "a"

# ----------------- Helpers -----------------
def run(cmd):
    print(f"[RUN] {cmd}")
    subprocess.run(cmd, shell=True, check=False)

def get_node_id_by_addr(addr: str):
    for node_id, node_info in NODES.items():
        if addr == node_info["global"] or addr == node_info["link_local"]:
            return node_id
    return None

def create_and_sign_manifest(bin_path: Path, output_dir: Path):
    file_stem = bin_path.stem
    tmp_file = output_dir / f"{file_stem}.tmp"
    manifest_file = output_dir / f"{file_stem}_manifest"
    signed_file = output_dir / f"{file_stem}.signed"

    suit_gen = os.path.expanduser(SUIT_GEN)
    suit_tool = os.path.expanduser(SUIT_TOOL)
    key_file = os.path.expanduser(KEY_FILE)

    uri = f"coap://[{SERVER_ADDR}]/{file_stem}.bin"
    print(f"[DEBUG] Generating manifest with URI: {uri}")
    run(f"{suit_gen} --urlroot coap://[{SERVER_ADDR}] --uuid-class {NODE_CLASS} "
        f"--seqnr {SEQ_NUMBER} -o {tmp_file} {bin_path}:0:ram:0")
    run(f"{suit_tool} create -f suit -i {tmp_file} -o {manifest_file}")
    run(f"{suit_tool} sign -k {key_file} -m {manifest_file} -o {signed_file}")

    if not signed_file.exists():
        raise RuntimeError(f"Failed to create {signed_file}")
    return signed_file.name


def strip_port(addr: str) -> str:
    """Remove :port from [IPv6]:port or IPv4:port strings."""
    if addr.startswith("["):  # IPv6 literal like [2001:db8::1]:5683
        if "]" in addr:
            return addr.split("]")[0].strip("[]")
    if ":" in addr and addr.count(":") == 1:  # IPv4:port
        return addr.split(":")[0]
    return addr

def poll_download_status(client_addr, timeout=500, interval=2):
    node_id = get_node_id_by_addr(client_addr) or client_addr
    start = time.time()
    print(f"[WAIT] Waiting for {node_id} to finish download...")
    while time.time() - start < timeout:
        result = subprocess.run(
            f"aiocoap-client -m GET coap://[{client_addr}]/suit/status",
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL
        )
        status = result.stdout.decode().strip()
        if "downloaded" in status:
            print(f"[OK] Download complete on {node_id}")
            return True
        if "failed" in status:
            print(f"[ERROR] Download failed on {node_id}")
            return False
        print(f"[WAIT] Still downloading... ({status})")
        time.sleep(interval)
    print(f"[TIMEOUT] Node {node_id} did not finish downloading in time.")
    return False

def send_manifest(client_addr, file_name, background=True):
    node_id = get_node_id_by_addr(client_addr) or client_addr
    print(f"Starting update to {node_id} with {file_name}")
    start_time = time.time()

    # Trigger download (node will GET coap://[SERVER_ADDR]/{file_name})
    run(f"aiocoap-client -m POST coap://[{client_addr}]/suit/trigger "
    f"--payload coap://[{SERVER_ADDR}]/{file_name}")
    success = True
    elapsed = time.time() - start_time
    status = "OK" if success else "FAIL"
    print(f"Update to {node_id} {status} in {elapsed:.2f} seconds\n")
    with open("update_times.csv", "a") as f:
        f.write(f"{file_name},{client_addr},{elapsed:.2f}\n")
    return success

def send_update(client_addr, vm_id, hook_trigger, next_vm, reset_flag, install_flag):
    payload = f"{vm_id},{hook_trigger},{next_vm},{reset_flag},{install_flag}"
    run(f"aiocoap-client -m POST coap://[{client_addr}]/fc/update --payload {payload}")

def prefer_ipv6_literal(ip: str) -> str:
    """Strip any scope IDs from link-local (e.g., '%lowpan0')."""
    return ip.split('%', 1)[0]

def ip_from_request(req) -> str:
    """
    Return the exact host part (with %scope if link-local), suitable for aiocoap-client URLs.
    """
    # Usually best source:
    if getattr(req, "remote", None) and getattr(req.remote, "hostinfo", None):
        return req.remote.hostinfo  # already like "fe80::...%lowpan0" or "[2001:...]"
    # Fallback: sockaddr may include scopeid
    try:
        host = req.remote.sockaddr[0]
        scopeid = req.remote.sockaddr[3] if len(req.remote.sockaddr) >= 4 else None
        return f"{strip_port(host)}%{scopeid}" if scopeid else strip_port(host)
    except Exception:
        return ""

def _get_signed_bytes(bin_folder: Path, file_key: str) -> bytes:
    bin_file = bin_folder / f"{file_key}.bin"
    signed_path = bin_folder / f"{file_key}.signed"

    if not bin_file.exists():
        raise FileNotFoundError(f"Missing {file_key}.bin in {bin_folder}")

    # (Re)generate manifest if missing or outdated
    if (not signed_path.exists()) or (bin_file.stat().st_mtime > signed_path.stat().st_mtime):
        print(f"[INFO] Creating signed manifest for {file_key}.bin")
        created = create_and_sign_manifest(bin_file, bin_folder)
        # If generator returned a different name, honor it
        alt = bin_folder / created
        if alt.exists():
            signed_path = alt

    data = signed_path.read_bytes()
    return data

# ----------------- CoAP Resources -----------------
from aiocoap.numbers.codes import Code

class FileServerRoot(resource.Resource):
    def __init__(self, bin_folder: Path):
        super().__init__()
        self.bin_folder = bin_folder

    async def render_get(self, request):
        segs = request.opt.uri_path
        if not segs:
            return Message(code=Code.NOT_FOUND, payload=b"No file specified")
        filename = "/".join(segs)
        fpath = self.bin_folder / filename

        if not fpath.exists() or not fpath.is_file():
            return Message(code=Code.NOT_FOUND, payload=b"File not found")

        try:
            data = fpath.read_bytes()
            m = Message(code=Code.CONTENT, payload=data)
            m.opt.content_format = APPLICATION_OCTET_STREAM
            return m
        except Exception as e:
            m = Message(code=Code.INTERNAL_SERVER_ERROR, payload=str(e).encode())
            m.opt.content_format = TEXT_PLAIN
            return m

class FCSubmitResource(resource.Resource):
    def __init__(self, bin_folder: Path):
        super().__init__()
        self.bin_folder = bin_folder

    async def render_get(self, request):
        client_ip = ip_from_request(request)
        if not client_ip:
            return Message(code=Code.BAD_REQUEST, payload=b"Cannot determine client IP")

        # Resolve node and file mapping
        node_id = get_node_id_by_addr(client_ip.replace('[','').replace(']','')) or client_ip
        file_key = NODE_TO_FILE.get(node_id, DEFAULT_FILE)
        bin_file = self.bin_folder / f"{file_key}.bin"

        if not bin_file.exists():
            msg = f"Missing {file_key}.bin in {self.bin_folder}"
            print(f"[ERROR] {msg}")
            return Message(code=Code.INTERNAL_SERVER_ERROR, payload=msg.encode())

        # Ensure .signed manifest is up-to-date
        signed_name = f"{file_key}.signed"
        signed_path = self.bin_folder / signed_name
        try:
            if (not signed_path.exists()) or (bin_file.stat().st_mtime > signed_path.stat().st_mtime):
                print(f"[INFO] Creating signed manifest for {file_key}.bin")
                created = create_and_sign_manifest(bin_file, self.bin_folder)
                if created != signed_name:
                    signed_name = created
                    signed_path = self.bin_folder / signed_name

            # Read and return the manifest
            with open(signed_path, 'rb') as f:
                data = f.read()
            m = Message(code=Code.CONTENT, payload=data)
            m.opt.content_format = APPLICATION_OCTET_STREAM
            print(f"[DONE] Sent manifest {signed_name} to {node_id}")
            return m
        except FileNotFoundError:
            msg = f"Manifest {signed_name} not found for {node_id}"
            print(f"[ERROR] {msg}")
            return Message(code=Code.NOT_FOUND, payload=msg.encode())
        except Exception as e:
            msg = f"Failed to serve manifest for {node_id}: {e}"
            print(f"[ERROR] {msg}")
            return Message(code=Code.INTERNAL_SERVER_ERROR, payload=msg.encode())

    async def render_post(self, request):
        client_ip = ip_from_request(request)
        if not client_ip:
            return Message(code=Code.BAD_REQUEST, payload=b"Cannot determine client IP")

        # Resolve node and file mapping
        node_id = get_node_id_by_addr(client_ip.replace('[','').replace(']','')) or client_ip
        file_key = NODE_TO_FILE.get(node_id, DEFAULT_FILE)
        bin_file = self.bin_folder / f"{file_key}.bin"

        if not bin_file.exists():
            msg = f"Missing {file_key}.bin in {self.bin_folder}"
            print(f"[ERROR] {msg}")
            return Message(code=Code.INTERNAL_SERVER_ERROR, payload=msg.encode())

        # Ensure .signed manifest is up-to-date
        signed_name = f"{file_key}.signed"
        signed_path = self.bin_folder / signed_name
        try:
            if (not signed_path.exists()) or (bin_file.stat().st_mtime > signed_path.stat().st_mtime):
                print(f"[INFO] Creating signed manifest for {file_key}.bin")
                created = create_and_sign_manifest(bin_file, self.bin_folder)
                if created != signed_name:
                    signed_name = created
                    signed_path = self.bin_folder / signed_name

            # Read and return the manifest
            with open(signed_path, 'rb') as f:
                data = f.read()
            m = Message(code=Code.CONTENT, payload=data)
            m.opt.content_format = APPLICATION_OCTET_STREAM
            print(f"[DONE] Sent manifest {signed_name} to {node_id}")
            return m
        except FileNotFoundError:
            msg = f"Manifest {signed_name} not found for {node_id}"
            print(f"[ERROR] {msg}")
            return Message(code=Code.NOT_FOUND, payload=msg.encode())
        except Exception as e:
            msg = f"Failed to serve manifest for {node_id}: {e}"
            print(f"[ERROR] {msg}")
            return Message(code=Code.INTERNAL_SERVER_ERROR, payload=msg.encode())
        
        
class FileResource(resource.Resource):
    def __init__(self, file_path):
        super().__init__()
        self.file_path = file_path

    async def render_get(self, request):
        try:
            with open(self.file_path, 'rb') as f:
                content = f.read()
            m = Message(code=Code.CONTENT, payload=content)
            m.opt.content_format = APPLICATION_OCTET_STREAM
            return m
        except FileNotFoundError:
            print(f"[ERROR] File not found: {self.file_path}")
            return Message(code=Code.NOT_FOUND, payload=b"File not found")
        except Exception as e:
            print(f"[ERROR] Failed to serve file {self.file_path}: {e}")
            return Message(code=Code.INTERNAL_SERVER_ERROR, payload=str(e).encode())
        
# ----------------- Main (server) -----------------
async def start_server(bin_folder: Path):
    site = resource.Site()

    # Ensure the folder exists
    Path(bin_folder).mkdir(exist_ok=True)

    # Add a resource for each file in the folder
    for file_name in os.listdir(bin_folder):
        file_path = os.path.join(bin_folder, file_name)
        if os.path.isfile(file_path):
            # Create a resource for the file under /<filename>
            site.add_resource([file_name], FileResource(file_path))
            print(f"[INFO] Registered resource: /{file_name}")

    # Discovery
    site.add_resource(['.well-known', 'core'], resource.WKCResource(site.get_resources_as_linkheader))
    # FC submit endpoint
    site.add_resource(['fc', 'submit'], FCSubmitResource(bin_folder))

    # Bind to all IPv6 (default CoAP port 5683)
    await Context.create_server_context(site)
    print(f"[READY] CoAP server up. Serving files from: {bin_folder}")
    await asyncio.get_running_loop().create_future()

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 server.py <bin_folder>")
        sys.exit(1)

    bin_folder = Path(sys.argv[1]).resolve()
    if not bin_folder.exists() or not bin_folder.is_dir():
        print(f"[ERROR] Invalid bin_folder: {bin_folder}")
        sys.exit(1)

    # Prepare update_times.csv fresh
    csv_path = Path("update_times.csv")
    if csv_path.exists():
        print("[INFO] Removing old update_times.csv...")
        csv_path.unlink()

    # Optional: pre-sign all known files if present (speeds up first hit)
    for base in set(NODE_TO_FILE.values()):
        bin_file = bin_folder / f"{base}.bin"
        if bin_file.exists():
            signed = bin_folder / f"{base}.signed"
            if (not signed.exists()) or (bin_file.stat().st_mtime > signed.stat().st_mtime):
                try:
                    print(f"[INFO] Pre-signing {bin_file.name}")
                    create_and_sign_manifest(bin_file, bin_folder)
                except Exception as e:
                    print(f"[WARN] Pre-sign failed for {bin_file.name}: {e}")


    asyncio.run(start_server(bin_folder))

if __name__ == "__main__":
    main()
