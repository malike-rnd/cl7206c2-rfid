# CL7206C2 RFID Reader — Complete Protocol Specification
## Reverse Engineered from protocol_cmd_hdl() decompilation

---

## 1. PACKET FRAME FORMAT

```
┌────────┬──────┬──────┬────────┬────────┬──────────────┬──────────┬──────────┐
│ Header │ CMD  │ SUB  │ LEN_Hi │ LEN_Lo │  Data [0..N] │ CRC16_Hi │ CRC16_Lo │
│  0xAA  │ 1 B  │ 1 B  │  1 B   │  1 B   │  N bytes     │   1 B    │   1 B    │
└────────┴──────┴──────┴────────┴────────┴──────────────┴──────────┴──────────┘
  Byte 0   Byte 1 Byte 2  Byte 3   Byte 4   Byte 5...    Last-1     Last

Header:   Always 0xAA
CMD:      Main command category (param_1[1])
SUB:      Sub-command (param_1[2])
LEN:      Data length = total_packet_len - 5 (header+cmd+sub+len excluded)
          LEN_Hi = (data_len >> 9), LEN_Lo = (data_len & 0xFF)
Data:     Payload (variable length, starts at byte 5)
CRC16:    CRC16 over bytes [0..last_data_byte] (packet_len - 1 bytes)
          Calculated by CRC16_CalculateBuf()
```

### CRC16 Calculation (CONFIRMED from decompilation)

**Algorithm:** CRC-16/BUYPASS (IBM)
- **Polynomial:** 0x8005
- **Initial value:** 0x0000
- **Formula:** `crc = (crc << 8) ^ table[(crc >> 8) ^ byte]`
- **Coverage:** Bytes [1] through end of data — CMD + SUB + LEN + DATA
- **Excludes:** 0xAA sync byte and CRC bytes themselves
- **Appended:** Big-endian (high byte first)
- **Note:** If device uses init=0xFFFF, it's CRC-16/IBM variant variant

```
Packet:  [0xAA] [CMD] [SUB] [LEN_Hi] [LEN_Lo] [Data...] [CRC_Hi] [CRC_Lo]
CRC:             |<========= CRC covers this range ========>|
```

**Source:** `CRC16_CalateByte()` → `(crc << 8) ^ CRCtable[(crc >> 8) ^ byte]`
           `CRC16_CalculateBuf()` → init=0, iterates over all bytes
           `protocol_cmd_hdl()` → `CRC16_CalculateBuf(re_buff+1, packet_len-1)`


---

## 2. COMMAND TABLE

### Overview

The protocol has two main flows:

**PC → Reader (local_25 = 0):** Commands from PC/network to the reader
**RF Module → Reader (local_25 = 1):** Tag data from internal RF module, forwarded to PC

### 2.1 Main Command Categories (CMD byte)

| CMD  | Direction | Purpose                                    |
|------|-----------|-------------------------------------------|
| 0x01 | PC→Reader | **Management commands** (big switch below) |
| 0x02 | PC→RF     | **RF passthrough** (inventory, read/write) |
| 0x04 | PC→RF/Upg | Sub 0x01: RF passthrough; Sub 0x00: **Firmware upgrade** |
| 0x05 | PC→RF     | **RF passthrough** (additional RF commands) |
| 0x12 | RF→PC     | **Tag notification** (EPC/TID data from RF)|
| 0x10 | RF→PC     | RF module response                         |

### 2.2 RF Passthrough Commands (CMD = 0x02, 0x05)

These are forwarded directly to the RF module via `transfer_to_rf()`.
The RF module uses its own sub-protocol (likely CLOU/Hopeland proprietary).

**Reading flag tracking:**
- SUB = 0x10 or SUB = 0x40 → `reading_flag = 1` (inventory running)
- SUB = 0xFF → `reading_flag = 0` (inventory stopped)

### 2.3 Tag Notification (CMD = 0x12, from RF module)

When RF module reads a tag, it sends CMD=0x12 to the main app:

| SUB  | Meaning                      |
|------|------------------------------|
| 0x00 | EPC tag data                 |
| 0x20 | EPC + additional data        |
| 0x30 | EPC + TID data               |

**Processing flow:**
1. If Wiegand enabled → `WieGand_Data_Save()` (output to Wiegand)
2. If tag cache enabled → `data_base_store_record()` (save to SQLite)
3. If whitelist enabled → `data_base_white_list_check()`:
   - Match found → Activate relay (`gpio_relay_on_ctl()`)
4. Always → `transfer_to_pc()` (forward tag data to PC)

---

### 2.4 Management Commands (CMD = 0x01, SUB = xx)

This is the main command switch. All responses use the same frame format.

#### DEVICE INFORMATION

| SUB  | Name                | Data In              | Data Out                    | Notes |
|------|---------------------|----------------------|-----------------------------|-------|
| 0x00 | Get Reader Info     | (none)               | reader_info(4B) + 0x00 + 0x10 + reader_name(16B) + uptime(4B) | Returns model, name, uptime |
| 0x01 | RF Passthrough      | RF command data      | (forwarded to RF module)    | Direct RF module access |

#### SERIAL PORT / COM CONFIGURATION

| SUB  | Name                | Data In              | Data Out                    | Notes |
|------|---------------------|----------------------|-----------------------------|-------|
| 0x02 | Set PC COM Config   | COM parameters       | ACK (build_set_pack)        | Reinitializes PC serial port |
| 0x15 | Set RS485 Config    | [addr][mode][baud?]  | ACK (build_set_pack)        | Sets RS485 address + baud |
| 0x16 | Get RS485 Config    | (none)               | [addr(1B)] [com_mode(1B)]   | Returns RS485 address + mode |

#### NETWORK CONFIGURATION

| SUB  | Name                | Data In              | Data Out                    | Notes |
|------|---------------------|----------------------|-----------------------------|-------|
| 0x04 | Set IP Config       | IP/Mask/GW data      | ACK (build_set_pack)        | Validates IP first, then applies |
| 0x05 | Get Network Params  | (none)               | 12 bytes (IP+Mask+GW)      | Returns IP(4B)+Mask(4B)+GW(4B) |
| 0x06 | Get MAC Address     | (none)               | 6 bytes MAC                 | Device MAC address |
| 0x07 | Set Server/Client   | 9 bytes config       | ACK (build_set_pack)        | TCP mode: SERVER or CLIENT |
| 0x13 | Set MAC Address     | 6 bytes MAC          | ACK (build_set_pack)        | Must be exactly 6 bytes |
| 0x2D | Set Ping/GW Address | IP address data      | ACK (build_set_pack)        | Gateway for ping monitoring |
| 0x2E | Get Ping Config     | (none)               | [sw(1B)] [type(1B)] [ip(4B)] | Ping switch + target IP |
| 0x2F | Set DHCP Mode       | DHCP config          | ACK (build_set_pack)        | 0=static (kills udhcpc), 1=DHCP |

#### GPIO / RELAY / TRIGGER

| SUB  | Name                | Data In              | Data Out                    | Notes |
|------|---------------------|----------------------|-----------------------------|-------|
| 0x09 | Set GPO Output      | GPO control data     | [status(1B)]                | 0=success, 1=error |
| 0x0A | Get GPI Inputs      | (none)               | [1][lvl1][2][lvl2][3][lvl3][4][lvl4] | 4 input pins with levels |
| 0x0B | Set Trigger Config  | trigger parameters   | ACK (build_set_pack)        | Validates trigger mode first |
| 0x0C | Get Trigger Config  | [trigger_id(1B)]     | trigger config data         | Returns trigger parameters |
| 0x23 | Set Relay Config    | relay parameters     | ACK (build_set_pack)        | Relay number + on-time |
| 0x24 | Get Relay Config    | (none)               | [relay_num(1B)] [time_hi(1B)] [time_lo(1B)] | Which relay + duration |

#### TIME

| SUB  | Name                | Data In              | Data Out                    | Notes |
|------|---------------------|----------------------|-----------------------------|-------|
| 0x10 | Set System Time     | [unix_ts(4B BE)]     | [status(1B)]                | Sets RTC via settimeofday + hwclock |
| 0x11 | Get System Time     | (none)               | [seconds(4B)] [useconds(4B)] | 8 bytes, big-endian |

#### TAG DATABASE

| SUB  | Name                | Data In              | Data Out                    | Notes |
|------|---------------------|----------------------|-----------------------------|-------|
| 0x17 | Set Tag Cache Cfg   | cache config data    | ACK (build_set_pack)        | Enable/configure tag caching |
| 0x18 | Get Tag Cache SW    | (none)               | [switch(1B)]                | 0=off, 1=on |
| 0x19 | Set Tag Cache Time  | time config data     | ACK (build_set_pack)        | Cache duration setting |
| 0x1A | Get Tag Cache Time  | (none)               | [time_hi(1B)] [time_lo(1B)] | Cache time value |
| 0x1B | Get Tag Records     | (none)               | (sends via data_base_answer_machine) | Bulk tag data transfer |
| 0x1C | Clear All Tags      | (none)               | [status(1B)]                | 0=success, 1=error |
| 0x1D | Delete Tag by Index | [index(4B BE)]       | (sends updated records)     | Also triggers answer_machine |
| 0x55 | Delete Tag by Index | [index(4B BE)]       | (same as 0x1D)              | Alias for 0x1D |

#### CONFIG READ/WRITE (GENERIC)

| SUB  | Name                | Data In              | Data Out                    | Notes |
|------|---------------------|----------------------|-----------------------------|-------|
| 0x03 | Get Config Param    | (implicit from SUB)  | config data (variable)      | Generic config read |
| 0x08 | Get Config Param    | (implicit from SUB)  | config data (variable)      | Same handler as 0x03 |
| 0x0D | Save Config         | config data          | ACK (build_set_pack)        | Generic config write |
| 0x0E | Get Config Param    | (implicit from SUB)  | config data (variable)      | Same handler as 0x03 |
| 0x30 | Get Config Param    | (implicit from SUB)  | config data (variable)      | Same handler as 0x03 |

#### SYSTEM

| SUB  | Name                | Data In              | Data Out                    | Notes |
|------|---------------------|----------------------|-----------------------------|-------|
| 0x0F | Reboot Reader       | (none)               | (forwards to RF, then reboots) | Executes `reboot -f` |
| 0x12 | Connection ACK      | [seq_num(4B BE)]     | (none — no response)        | Keepalive acknowledgment |
| 0x14 | Factory Reset       | (none)               | [status(1B)]                | Resets config + RF baud to default |
| 0x54 | RS485 Passthrough   | raw data             | (forwarded to RS485 port)   | Direct RS485 write |

#### FIRMWARE UPGRADE

| CMD  | SUB  | Name                | Data In              | Notes |
|------|------|---------------------|----------------------|-------|
| 0x04 | 0x00 | Upload FW Data      | firmware chunk       | Returns [addr(4B)] [status(1B)] |
| 0x01 | 0x20 | Get White List      | [offset(4B BE)]      | Returns whitelist DB data |
| 0x01 | 0x21 | Upload White List   | whitelist chunk      | Returns [addr(4B)] [status(1B)] |


---

## 3. RESPONSE PACKET FORMAT

All responses follow the same frame:

```
[0xAA] [CMD_echo] [SUB_echo] [LEN_Hi] [LEN_Lo] [Response Data] [CRC16_Hi] [CRC16_Lo]
```

- CMD and SUB are echoed back from the request
- Some commands use `build_set_pack()` for ACK/NACK responses
- Some commands use `transfer_to_pc()` directly

### build_set_pack Response (ACK/NACK)

Used by: 0x02, 0x04, 0x07, 0x0B, 0x0D, 0x13, 0x15, 0x17, 0x19, 0x23, 0x2D, 0x2F

Parameters: `build_set_pack(CMD, SUB, status)`
- status = 0 → Success
- status = 1 → Error/Failure


---

## 4. PROTOCOL FLOW EXAMPLES

### 4.1 Get Reader Information
```
TX: AA 01 00 00 00 [CRC16]
RX: AA 01 00 [LEN] [reader_info(4B)] 00 10 [reader_name(16B)] [uptime(4B)] [CRC16]
```

### 4.2 Get Network Parameters (IP/Mask/GW)
```
TX: AA 01 05 00 00 [CRC16]
RX: AA 01 05 00 0C [IP(4B)] [Mask(4B)] [GW(4B)] [CRC16]
```

### 4.3 Get MAC Address
```
TX: AA 01 06 00 00 [CRC16]
RX: AA 01 06 00 06 [MAC(6B)] [CRC16]
```

### 4.4 Set IP Address
```
TX: AA 01 04 [LEN] [IP(4B)] [Mask(4B)] [GW(4B)] [CRC16]
RX: AA 01 04 [LEN] [status] [CRC16]    (via build_set_pack)
```

### 4.5 Start Inventory (RF passthrough)
```
TX: AA 02 10 [LEN] [RF params...] [CRC16]
    (reading_flag = 1, forwarded to RF module)
```

### 4.6 Stop Inventory
```
TX: AA 02 FF [LEN] [data] [CRC16]
    (reading_flag = 0, forwarded to RF module)
```

### 4.7 Tag Notification (async, from reader)
```
RX: AA 12 00 [LEN] [EPC data...] [CRC16]     (EPC only)
RX: AA 12 20 [LEN] [EPC + extra...] [CRC16]   (EPC + additional)
RX: AA 12 30 [LEN] [EPC + TID...] [CRC16]     (EPC + TID)
```

### 4.8 Get System Time
```
TX: AA 01 11 00 00 [CRC16]
RX: AA 01 11 00 08 [seconds(4B BE)] [useconds(4B BE)] [CRC16]
```

### 4.9 Set System Time
```
TX: AA 01 10 00 04 [unix_timestamp(4B BE)] [CRC16]
RX: AA 01 10 00 01 [00] [CRC16]
```

### 4.10 Reboot
```
TX: AA 01 0F 00 00 [CRC16]
(reader reboots, no response expected)
```

### 4.11 Factory Reset
```
TX: AA 01 14 00 00 [CRC16]
RX: AA 01 14 00 01 [status] [CRC16]
```

### 4.12 Get GPI Input Levels
```
TX: AA 01 0A 00 00 [CRC16]
RX: AA 01 0A [LEN] [01] [gpi1_level] [02] [gpi2_level] [03] [gpi3_level] [04] [gpi4_level] [CRC16]
```

### 4.13 Clear Tag Database
```
TX: AA 01 1C 00 00 [CRC16]
RX: AA 01 1C 00 01 [status(0=ok)] [CRC16]
```

### 4.14 Get RS485 Config
```
TX: AA 01 16 00 00 [CRC16]
RX: AA 01 16 00 02 [rs485_addr] [com_mode] [CRC16]
```

### 4.15 Set DHCP Mode
```
TX: AA 01 2F [LEN] [dhcp_mode] [CRC16]
RX: (ACK via build_set_pack)
    dhcp_mode=0: kills udhcpc (static IP)
    dhcp_mode=1: enables DHCP
```

### 4.16 Get Tag Cache Config
```
TX: AA 01 18 00 00 [CRC16]
RX: AA 01 18 00 01 [cache_switch(0/1)] [CRC16]
```

### 4.17 Get Relay Config
```
TX: AA 01 24 00 00 [CRC16]
RX: AA 01 24 00 03 [relay_num] [time_hi] [time_lo] [CRC16]
```


---

## 5. CONNECTION MANAGEMENT

### Initial Connection
- When a new client connects on a non-active FD:
  `connect_state_init(fd, packet, length)` is called
- Uses `connect_get_active_fd()` to check if this is the active connection

### Keepalive
- TCP keepalive via SO_KEEPALIVE/KEEPIDLE/KEEPINTVL
- Application-level: SUB 0x12 (Connection ACK with sequence number)
- `update_alive_timer()` / `update_reconnect_timer()` on each valid packet

### Server/Client Mode
- Server: Reader listens, PC connects
- Client: Reader connects to HOST_SERVER_IP:HOST_SERVER_PORT
- Configured via SUB 0x07 (9-byte config block)


---

## 6. FIRMWARE UPGRADE PROTOCOL

### Network Upgrade (CMD=0x04, SUB=0x00)
```
TX: AA 04 00 [LEN] [firmware_chunk] [CRC16]
RX: AA 04 00 00 05 [write_addr(4B BE)] [status] [CRC16]
    status: 0=success, 1=error
```

### White List Upgrade (CMD=0x01, SUB=0x21)
```
TX: AA 01 21 [LEN] [whitelist_chunk] [CRC16]
RX: AA 01 21 00 05 [write_addr(4B BE)] [status] [CRC16]
```

### White List Read (CMD=0x01, SUB=0x20)
```
TX: AA 01 20 00 04 [offset(4B BE)] [CRC16]
RX: AA 01 20 [LEN] [offset(4B BE)] [whitelist_data...] [CRC16]
    (if offset = 0xFFFFFFFF → end of data, LEN=4)
```


---

## 7. QUICK REFERENCE — ALL SUB-COMMANDS (CMD=0x01)

| SUB  | Hex  | R/W   | Function                      |
|------|------|-------|-------------------------------|
| 0x00 | 00   | Read  | Get Reader Info               |
| 0x01 | 01   | →RF   | RF Module Passthrough         |
| 0x02 | 02   | Write | Set PC COM Config             |
| 0x03 | 03   | Read  | Get Config Parameter          |
| 0x04 | 04   | Write | Set IP Configuration          |
| 0x05 | 05   | Read  | Get Network Params (IP/M/GW)  |
| 0x06 | 06   | Read  | Get MAC Address               |
| 0x07 | 07   | Write | Set Server/Client Mode        |
| 0x08 | 08   | Read  | Get Config Parameter          |
| 0x09 | 09   | Write | Set GPO Output                |
| 0x0A | 0A   | Read  | Get GPI Input Levels          |
| 0x0B | 0B   | Write | Set Trigger Config            |
| 0x0C | 0C   | Read  | Get Trigger Config            |
| 0x0D | 0D   | Write | Save Config (generic)         |
| 0x0E | 0E   | Read  | Get Config Parameter          |
| 0x0F | 0F   | Exec  | **Reboot Reader**             |
| 0x10 | 10   | Write | Set System Time               |
| 0x11 | 11   | Read  | Get System Time               |
| 0x12 | 12   | Write | Connection ACK (keepalive)    |
| 0x13 | 13   | Write | Set MAC Address               |
| 0x14 | 14   | Exec  | **Factory Reset**             |
| 0x15 | 15   | Write | Set RS485 Config              |
| 0x16 | 16   | Read  | Get RS485 Config              |
| 0x17 | 17   | Write | Set Tag Cache Config          |
| 0x18 | 18   | Read  | Get Tag Cache Switch          |
| 0x19 | 19   | Write | Set Tag Cache Time Config     |
| 0x1A | 1A   | Read  | Get Tag Cache Time            |
| 0x1B | 1B   | Read  | Get Tag Records (bulk)        |
| 0x1C | 1C   | Exec  | **Clear All Tags**            |
| 0x1D | 1D   | Exec  | Delete Tag by Index           |
| 0x20 | 20   | Read  | Get White List Data           |
| 0x21 | 21   | Write | Upload White List             |
| 0x23 | 23   | Write | Set Relay Config              |
| 0x24 | 24   | Read  | Get Relay Config              |
| 0x2D | 2D   | Write | Set Ping/Gateway Address      |
| 0x2E | 2E   | Read  | Get Ping Config               |
| 0x2F | 2F   | Write | Set DHCP Mode                 |
| 0x30 | 30   | Read  | Get Config Parameter          |
| 0x54 | 54   | →485  | RS485 Passthrough             |
| 0x55 | 55   | Exec  | Delete Tag by Index (alias)   |


---

## 8. NOTES

- All multi-byte integers are **big-endian** in the protocol
- LEN field counts only data bytes (excludes header, cmd, sub, len itself)
- CRC16 covers bytes [0] through end of data (everything except CRC itself)
- RF commands (CMD 0x02, 0x05) are opaque passthrough to the Hopeland RF module
- Tag notifications (CMD 0x12) are async and can arrive at any time during inventory
- The reader echoes CMD and SUB in responses
- Factory reset (0x14) also resets RF module baud rate to default (mode 2)
- DHCP mode 0 explicitly kills the udhcpc daemon
- Reboot (0x0F) forwards packet to RF first, waits 100ms, then executes `reboot -f`
