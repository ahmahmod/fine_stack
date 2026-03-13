# OTA RIOT Firmware Update over FIT IoT-LAB

Transmit the whole firmware through the network using the FIT IoT-LAB testbed.

---

## Normal Nodes


1. **Build the initial image**:
   ```sh
   BOARD=iotlab-m3 USE_ETHOS=0 FEATURES_REQUIRED+=riotboot DEFAULT_CHANNEL=15 make
   ```

2. **Flash the firmware**:
   ```sh
   iotlab-node --flash bin/iotlab-m3/riotboot_files/slot0-extended.bin -l SITENAME,m3,NODE_ID
   ```

---


## Border Router / RPL Root

### CLIENT

1. **Compile**:
   ```sh
   FEATURES_REQUIRED+=riotboot DEFAULT_CHANNEL=15 USE_ETHOS=0 make ETHOS_BAUDRATE=500000
   ```

2. **Flash**:
   ```sh
   iotlab-node --flash bin/iotlab-m3/riotboot_files/slot0-extended.bin -l SITENAME,m3,NODE_ID
   ```

3. **Run ETHOS**:
   ```sh
   sudo ethos_uhcpd.py m3-250 tap0 NET_PREFIX::1/64
   ```

---


## Update SERVER

1. **Publish the new update to the CoAP server directory**:
   ```sh
   BOARD=iotlab-m3 USE_ETHOS=0 SUIT_COAP_SERVER=[SERVER_IP] make -C ota suit/publish
   ```

2. **Run the CoAP server in the folder /RIOT**:
   ```sh
   aiocoap-fileserver /coaproot -vvvv
   ```

3. **Notify the client node of the new update**:
   ```sh
   SUIT_COAP_SERVER=[SERVER_IP] SUIT_CLIENT=[CLIENT_IP] BOARD=iotlab-m3 make -C examples/suit_update suit/notify
   ```

> Replace `[SERVER_IP]` and `[CLIENT_IP]` with the appropriate IP addresses.

---
