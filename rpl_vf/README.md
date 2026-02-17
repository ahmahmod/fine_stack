# OTA Update over FIT IoT-LAB

Transmit the whole needed VFs through the network using the FIT IoT-LAB testbed.

---

## Normal Nodes


1. **Build the initial image**:
   ```sh
   BOARD=iotlab-m3 USE_ETHOS=0 DEFAULT_CHANNEL=15 make
   ```

2. **Flash the firmware**:
   ```sh
   iotlab-node --flash bin/iotlab-m3/rpl_vf.bin -l SITENAME,m3,NODE_ID
   ```

## Border Router / RPL Root

This guide explains how to set up a Border Router (BR) on an IoT-LAB M3 node.

---

### 1. Compile the Firmware

```sh
make ETHOS_BAUDRATE=500000 DEFAULT_CHANNEL=15 BOARD=iotlab-m3
```

---

### 2. Flash the M3 Node

```sh
iotlab-node --flash bin/iotlab-m3/gnrc_border_router.elf -l SITE_NAME,m3,NODE_ID
```

---

### 3. Run the Border Router using ETHOS

```sh
sudo ethos_uhcpd.py m3-250 tap0 NET_PREFIX::1/64
```

---
 **Note**: Wait a few seconds after running the BR to allow prefix configuration and RPL root initialization.



## Orchestrator

This section details how to automate the deployment of VFs to IoT-LAB M3 nodes using Management Server and `management_server.py`.

---

### 0. Prepare Binary Files

- Place the binary files you want to send into the `bin_files/` directory.

---

### 1. Run the CoAP Server

```sh
aiocoap-fileserver -vvvv
```

Ensure it serves from the `bin_files/` directory.

---

### 2. Configure `management_server.py`

- Set server parameters:
  ```python
  SERVER_IP = "YOUR_IPV6_ADDR_OF_COAP_SERVER"
  NODE_CLASS = "iotlab-m3"
  ```

---

### 3. Configure Node Parameters

- Under the `NODES` section of `management_server.py`, set:
  - Link-local addresses
  - Global IPv6 addresses

---

### 4. Configure VM Pool Parameters

- Under the `VM_CONFIG` section:
  ```python
  vm_id: <ID>, "hook_trigger", "next_vm", "reset_flag"
  ```

---

### 5. Run the Deployment Server

```sh
./management_server.py bin_files/
```

This will automatically trigger CoAP-based updates to the specified M3 nodes using the configured manifest and VM parameters.

> Replace `[SERVER_IP]` and `[CLIENT_IP]` with the appropriate IP addresses.

---

