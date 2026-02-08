# CLOU CL7206C2 UHF RFID Reader — Reverse Engineering & Tools

> 🇬🇧 **English** | [🇷🇺 Русский](README.ru.md)

> **Complete protocol reverse engineering** of the CLOU (Hopeland) CL7206C2 8-port UHF RFID fixed reader.
> Proprietary binary protocol fully decoded from firmware. No vendor SDK or demo software required.

## 🎯 Project Goal

Building a **cycling race timing system** (хронометраж) using this reader + 2× 9dBi UHF antennas.
This repo contains everything needed to control the reader programmatically without vendor software.

---

## 📦 Hardware

| Parameter | Value |
|-----------|-------|
| **Model** | CLOU CL7206C2 (Hopeland Technologies / Shenzhen Clou IoT) |
| **FCC ID** | 2AKAGCLOUIOTCL7206C |
| **Firmware** | CL7206C_20170602 (HW v0.1, FW v0.19) |
| **CPU** | ARM (Linux 2.6.39+, BusyBox v1.6.0) |
| **Toolchain** | GCC 4.0.0 (DENX ELDK 4.1) |
| **RF Ports** | 4 RF × 2 MUX = **8 antenna ports** |
| **Max Power** | 33 dBm (+1 dB) per port |
| **Frequency** | ETSI 865–868 MHz / FCC 902–928 MHz / CN 840–845 + 920–925 MHz |
| **Protocol** | ISO 18000-6C (EPC Gen2) / ISO 18000-6B |
| **Read Distance** | 0–8 m (depends on tag/antenna/environment) |
| **I/O** | 4× GPI (optocoupler), 4× GPO (relay), Wiegand output |
| **Interfaces** | Ethernet (TCP/UDP), RS-232, RS-485, USB |
| **Power** | 24V DC (30V–10V range), PSU: 24V/2.5A |
| **Protection** | IP53 |
| **Dimensions** | 256 × 147.6 × 43.47 mm |
| **Antennas** | 2× 9dBi circular polarization UHF (ordered, pending delivery) |

---

## 🔌 Network Configuration (default)

| Parameter | Value |
|-----------|-------|
| IP Address | 192.168.1.116 |
| Subnet | 255.255.255.0 |
| Gateway | 192.168.1.1 |
| MAC | 6C:EC:A1:FE:75:3A |
| Management Port | **9090** (TCP + UDP) |
| Telnet | Port 23, login: `root` / no password |

---

## 🛠 Tools

### `tools/cl7206c2_client.py` — Main Protocol Client

Full-featured client for reader control via the reverse-engineered binary protocol.

```bash
# Basic queries (all tested & working ✓)
python3 cl7206c2_client.py 192.168.1.116 info        # Reader model, firmware, uptime
python3 cl7206c2_client.py 192.168.1.116 network     # IP / Mask / Gateway
python3 cl7206c2_client.py 192.168.1.116 mac         # MAC address
python3 cl7206c2_client.py 192.168.1.116 time        # System clock
python3 cl7206c2_client.py 192.168.1.116 settime now # Sync clock to PC time
python3 cl7206c2_client.py 192.168.1.116 gpi         # Read 4 digital inputs
python3 cl7206c2_client.py 192.168.1.116 relay       # Relay config
python3 cl7206c2_client.py 192.168.1.116 rs485       # RS485 address & mode
python3 cl7206c2_client.py 192.168.1.116 tagcache    # Tag cache on/off
python3 cl7206c2_client.py 192.168.1.116 tagtime     # Tag cache duration
python3 cl7206c2_client.py 192.168.1.116 ping        # Ping watchdog config
python3 cl7206c2_client.py 192.168.1.116 tags        # Retrieve stored tags
python3 cl7206c2_client.py 192.168.1.116 cleartags   # Clear tag database

# Tag reading (requires antennas + tags)
python3 cl7206c2_client.py 192.168.1.116 inventory   # Live tag stream (Ctrl+C to stop)
python3 cl7206c2_client.py 192.168.1.116 monitor     # Passive packet listener

# Dangerous commands
python3 cl7206c2_client.py 192.168.1.116 reboot      # Reboot reader
python3 cl7206c2_client.py 192.168.1.116 reset       # Factory reset (asks confirmation)
```

Requirements: Python 3.6+, no external dependencies.

### `tools/cl7206c2_tool.py` — Config File Parser

Parse and edit the binary `/config_pram` configuration file offline.

```bash
python3 cl7206c2_tool.py dump-config config_pram     # Decode config file
python3 cl7206c2_tool.py discover                     # UDP broadcast discovery
python3 cl7206c2_tool.py info 192.168.1.116           # Query reader info via UDP
```

### `tools/crc16_verified.py` — CRC16 Reference Implementation

Verified CRC16 with test packets. Use to validate your own packet construction.

---

## 📡 Protocol Specification

### Packet Frame Format

```
 Byte:   0      1     2     3       4       5..N      N+1     N+2
       ┌──────┬─────┬─────┬───────┬───────┬─────────┬───────┬───────┐
       │ 0xAA │ CMD │ SUB │ LEN_H │ LEN_L │ DATA... │ CRC_H │ CRC_L │
       └──────┴─────┴─────┴───────┴───────┴─────────┴───────┴───────┘
                |<============= CRC covers this ============>|
```

| Field | Size | Description |
|-------|------|-------------|
| Header | 1 | Always `0xAA` |
| CMD | 1 | Command category |
| SUB | 1 | Sub-command |
| LEN | 2 | Data length (big-endian), excludes header/cmd/sub/len |
| DATA | N | Payload (variable) |
| CRC16 | 2 | CRC-16 checksum (big-endian) |

### CRC16 Algorithm (verified from firmware)

| Parameter | Value |
|-----------|-------|
| **Algorithm** | CRC-16/BUYPASS (CRC-16/IBM/UMTS) |
| **Polynomial** | **0x8005** |
| **Initial value** | 0x0000 |
| **Reflect in/out** | No (MSB-first) |
| **Coverage** | CMD + SUB + LEN + DATA (0xAA header **excluded**) |
| **Byte order** | Big-endian |
| **Verification** | CRCtable @ 0x00020fe4: `[0]=0x0000 [1]=0x8005 [2]=0x800F [3]=0x000A` ✓ |

```python
# Python implementation
TABLE = []
for i in range(256):
    crc = i << 8
    for _ in range(8):
        crc = ((crc << 1) ^ 0x8005) if crc & 0x8000 else crc << 1
        crc &= 0xFFFF
    TABLE.append(crc)

def crc16(data, init=0x0000):
    crc = init
    for b in data:
        crc = ((crc << 8) & 0xFFFF) ^ TABLE[((crc >> 8) ^ b) & 0xFF]
    return crc
```

### Command Reference (CMD=0x01, Management)

| SUB | Hex | R/W | Function | Tested |
|-----|-----|-----|----------|--------|
| 0x00 | `AA 01 00 00 00 94 03` | R | Get Reader Info | ✅ |
| 0x01 | — | →RF | RF Module Passthrough | — |
| 0x02 | — | W | Set PC COM Config | — |
| 0x03 | — | R | Get Config Parameter | — |
| 0x04 | — | W | Set IP Configuration | — |
| 0x05 | `AA 01 05 00 00 94 47` | R | Get Network (IP/Mask/GW) | ✅ |
| 0x06 | `AA 01 06 00 00 94 7B` | R | Get MAC Address | ✅ |
| 0x07 | — | W | Set Server/Client Mode | — |
| 0x08 | — | R | Get Config Parameter | — |
| 0x09 | — | W | Set GPO Output | — |
| 0x0A | `AA 01 0A 00 00 94 8B` | R | Get GPI Input Levels | ✅ |
| 0x0B | — | W | Set Trigger Config | — |
| 0x0C | — | R | Get Trigger Config | — |
| 0x0D | — | W | Save Config (generic) | — |
| 0x0E | — | R | Get Config Parameter | — |
| 0x0F | `AA 01 0F 00 00 94 CF` | X | **Reboot** | ⚠️ |
| 0x10 | — | W | Set System Time | ✅ |
| 0x11 | `AA 01 11 00 00 95 57` | R | Get System Time | ✅ |
| 0x12 | — | W | Connection ACK (keepalive) | — |
| 0x13 | — | W | Set MAC Address | — |
| 0x14 | `AA 01 14 00 00 95 13` | X | **Factory Reset** | ⚠️ |
| 0x15 | — | W | Set RS485 Config | — |
| 0x16 | `AA 01 16 00 00 15 38` | R | Get RS485 Config | ✅ |
| 0x17 | — | W | Set Tag Cache Config | — |
| 0x18 | `AA 01 18 00 00 95 E3` | R | Get Tag Cache Switch | ✅ |
| 0x19 | — | W | Set Tag Cache Time | — |
| 0x1A | `AA 01 1A 00 00 15 C8` | R | Get Tag Cache Time | ✅ |
| 0x1B | `AA 01 1B 00 00 95 DF` | R | Get Stored Tag Records | ✅ |
| 0x1C | `AA 01 1C 00 00 15 B0` | X | Clear All Tags | ✅ |
| 0x1D | — | X | Delete Tag by Index | — |
| 0x20 | — | R | Get White List Data | — |
| 0x21 | — | W | Upload White List | — |
| 0x23 | — | W | Set Relay Config | — |
| 0x24 | `AA 01 24 00 00 96 D3` | R | Get Relay Config | ✅ |
| 0x2D | — | W | Set Ping/Gateway Address | — |
| 0x2E | `AA 01 2E 00 00 96 5B` | R | Get Ping Config | ✅ |
| 0x2F | — | W | Set DHCP Mode | — |
| 0x30 | — | R | Get Config Parameter | — |
| 0x54 | — | →485 | RS485 Passthrough | — |
| 0x55 | — | X | Delete Tag by Index (alias) | — |

### RF Commands (passthrough to RF module)

| CMD | SUB | Function |
|-----|-----|----------|
| 0x02 | 0x10 | **Start Inventory** (`AA 02 10 00 00 29 40`) |
| 0x02 | 0x40 | Start Inventory (variant) |
| 0x02 | 0xFF | **Stop Inventory** (`AA 02 FF 00 00 A4 0F`) |
| 0x04 | 0x01 | RF passthrough |
| 0x05 | * | RF passthrough |

### Tag Notification (async, CMD=0x12)

When the RF module reads a tag, the reader sends:

```
AA 12 [SUB] [LEN] [tag_data...] [CRC16]
```

| SUB | Contents |
|-----|----------|
| 0x00 | EPC only |
| 0x20 | EPC + additional data |
| 0x30 | EPC + TID |

Tag data uses **TLV (Type-Length-Value)** encoding from the RF module:

| Type | Data | Description |
|------|------|-------------|
| 0xAA | Header + EPC | Packet header with EPC data |
| 0x01 | `[ant_num] [sub_ant_num]` | Antenna identification (2 bytes) |
| 0x02 | `[byte1] [byte2]` | RSSI / signal parameters |
| 0x03 | `[type] [len_hi\|len_lo] [TID...]` | TID data block |
| 0x04 | `[type] [len_hi\|len_lo] [data...]` | Extra data block |
| 0x05 | `[type] [len_hi\|len_lo] [data...]` | Additional data |
| 0x06 | `[sub_type] [byte]` | Extra parameter |

### Firmware Upgrade (CMD=0x04, SUB=0x00)

```
TX: AA 04 00 [LEN] [firmware_chunk] [CRC16]
RX: AA 04 00 00 05 [write_addr(4B BE)] [status] [CRC16]
```

---

## 📻 8-Antenna Architecture

The reader has **4 RF ports** with **GPIO relay multiplexers** for 8 physical antennas:

```
RF Port 0 ──┬── Relay Pin 1 = 0 ──→ Antenna 1 (ANT1)
             └── Relay Pin 1 = 1 ──→ Antenna 2 (ANT2)

RF Port 1 ──┬── Relay Pin 2 = 0 ──→ Antenna 3 (ANT3)
             └── Relay Pin 2 = 1 ──→ Antenna 4 (ANT4)

RF Port 2 ──┬── Relay Pin 3 = 0 ──→ Antenna 5 (ANT5)
             └── Relay Pin 3 = 1 ──→ Antenna 6 (ANT6)

RF Port 3 ──┬── Relay Pin 4 = 0 ──→ Antenna 7 (ANT7)
             └── Relay Pin 4 = 1 ──→ Antenna 8 (ANT8)
```

Tag data contains both `ant_num` (RF port 0–3) and `sub_ant_num` (0–1) for exact antenna identification.

GPO command (SUB=0x09) switches antennas: `[pin_id] [state]` pairs, max 8 bytes.

---

## 💾 Config File Format (`/config_pram`, 1072 bytes)

```
┌─────────────────────────────────────────────────────────┐
│ 0x000–0x01B: Network Configuration (28 bytes)           │
│ 0x01C–0x11B: RF Port 0 Config (256 bytes) → ANT1/ANT2  │
│ 0x11C–0x21B: RF Port 1 Config (256 bytes) → ANT3/ANT4  │
│ 0x21C–0x31B: RF Port 2 Config (256 bytes) → ANT5/ANT6  │
│ 0x31C–0x41B: RF Port 3 Config (256 bytes) → ANT7/ANT8  │
│ 0x41C–0x42F: Global Settings (20 bytes)                 │
└─────────────────────────────────────────────────────────┘
```

### Network Block (0x00–0x1B)

| Offset | Size | Description | Current Value |
|--------|------|-------------|---------------|
| 0x00 | 1 | DHCP mode (0=static, 1=DHCP) | 0x02 |
| 0x01 | 4 | Device IP | 192.168.1.116 |
| 0x05 | 4 | Subnet mask | 255.255.255.0 |
| 0x09 | 4 | Gateway | 192.168.1.1 |
| 0x0D | 6 | MAC address | 6C:EC:A1:FE:75:3A |
| 0x14 | 2 | Local port (BE) | 9090 |
| 0x16 | 4 | Server IP | 192.168.1.1 |
| 0x1A | 2 | Server port (BE) | 9090 |

### Antenna Block (each 256 bytes, ×4)

| Offset | Size | Description | Value |
|--------|------|-------------|-------|
| +0x00 | 1 | Antenna index | 0–3 |
| +0x03 | 1 | Power level | 6 |
| +0x04 | 1 | Protocol (2=Gen2 dual-target) | 2 |
| +0x05 | 1 | Frequency region (0x10=CN dual-band) | 0x10 |
| +0x07 | 1 | Session (S0–S3) | 2 (S2) |
| +0x08 | 1 | Target (A/B) | 1 (B) |
| +0x09 | 1 | Q value | 1 |

### Global Settings (0x41C–0x42F)

| Offset | Description | Value |
|--------|-------------|-------|
| 0x41F | Wiegand enable | 1 (on) |
| 0x420 | Wiegand format | 2 |
| 0x421 | Wiegand bits | 2 |
| 0x424 | Buzzer | 1 (on) |
| 0x425 | Tag filter/dedupe | 1 (on) |
| 0x427 | Auto-read mode | 1 (on) |
| 0x429 | Remote server IP | 192.168.1.1 |

---

## 🗄 Tag Database (`/tag_table`, SQLite3)

```sql
CREATE TABLE tag_data (
    tag_index    INTEGER PRIMARY KEY,
    package_len  INT,
    package_data BLOB,        -- Raw RF packet
    epc_len      INT,
    epc_code     BLOB,        -- EPC tag ID
    pc           INT,         -- Protocol Control word
    ant_num      INT,         -- RF port (0–3)
    sub_ant_num  INT,         -- Sub-antenna (0–1)
    tid_flag     INT,
    tid_len      INT,
    tid_code     BLOB,        -- TID data
    time_seconds INT,         -- Unix timestamp
    time_usec    INT          -- Microseconds
);
-- Also: back_tag_data (same schema), white_list
```

---

## 🐧 Device Filesystem

| Path | Description |
|------|-------------|
| `/bin/CL7206C2` | Main application (150KB, ARM ELF, **not stripped**) |
| `/bin/fifo_read` | FIFO IPC reader |
| `/bin/feed_dog` | Hardware watchdog |
| `/config_pram` | Binary config (1072 bytes) |
| `/tag_table` | SQLite tag database |
| `/gateway` | Gateway IP text file |
| `/driver/wiegand.ko` | Wiegand kernel module |
| `/driver/g_serial.ko` | USB serial gadget |

### Boot Sequence
```
1. Set IP address (netapp)
2. Load wiegand.ko, g_serial.ko
3. Start ping_gateway.sh, feeddog_auto.sh, auto_start_fifo.sh
4. Launch auto_start.sh → CL7206C2 main loop
```

### Key Processes
```
CL7206C2 (×5 instances), fifo_read, feed_dog, telnetd, syslogd
```

---

## 🔬 Firmware Analysis

The binary is **not stripped** — all 310 function names are preserved.

### Key Decompiled Functions

| Function | Purpose | Status |
|----------|---------|--------|
| `protocol_cmd_hdl()` | **Main command router** — all 37+ opcodes | ✅ Fully decoded |
| `CRC16_CalateByte()` | CRC per-byte calculation | ✅ Decoded, poly verified |
| `CRC16_CalculateBuf()` | CRC buffer wrapper | ✅ Decoded |
| `GetHead()` | Packet queue dequeue | ✅ Decoded |
| `tag_data_analise()` | RF tag TLV parser | ✅ Decoded |
| `Gpo_Data_Process()` | GPIO relay switching | ✅ Decoded |

### Source Files (from debug symbols)

```
main.c          — Main loop, socket handling
protocol.c      — Command parsing (protocol_cmd_hdl)
configration.c  — Config read/write
netapp.c        — Network IP/MAC/gateway management
connect_man.c   — TCP/UDP connection management
recive.c        — Data receiving
transfer.c      — Data forwarding/relay
data_base.c     — SQLite tag database
uart.c          — Serial port init
gpio.c          — GPIO, LED, buzzer, relay, RS485
wiegand.c       — Wiegand output protocol
triger.c        — Trigger/event management
timer.c         — Timer subsystem
upgrade.c       — Firmware upgrade (USB + network)
crc32.c         — CRC32 calculation
usb_mornitor.c  — USB hotplug monitoring
net_link.c      — Netlink for cable detect
```

### Functions Still Worth Decompiling

| Function | Why | Priority |
|----------|-----|----------|
| `transfer_to_rf()` | Exact RF module command format | High (for timing) |
| `config_get_pra()` / `config_set_pra()` | Generic config read/write | Medium |
| `data_base_store_record()` | How tags are inserted into SQLite | Medium |
| `Triger_State_Machine()` | GPI trigger → inventory automation | Medium (for timing) |
| `WieGand_Data_Save()` | Wiegand output format | Low |
| `Server_Client_Pra_Process()` | TCP mode configuration | Low |
| `check_crc()` / `add_crc()` | CRC validation on receive | Low (already known) |
| `connect_state_init()` | TCP handshake sequence | Low |

---

## 📂 Repository Structure

```
cl7206c2-rfid/
├── README.md                          ← This file
├── tools/
│   ├── cl7206c2_client.py             ← Main protocol client
│   ├── cl7206c2_tool.py               ← Config file parser + UDP discovery
│   └── crc16_verified.py              ← CRC16 reference implementation
├── docs/
│   ├── CL7206C2_Protocol_Spec.md      ← Full protocol specification
│   ├── CL7206C2_RE_Report.md          ← Reverse engineering report
│   └── config_pram_analysis.md        ← Config binary format analysis
└── firmware_analysis/
    └── CL7206C2_strings.txt           ← All 1206 extracted strings
```

---

## ⏱ Future: Cycling Race Timing System

**Goal:** Measure lap/finish times for cyclists using UHF RFID tags.

**Hardware setup:**
- CL7206C2 reader (this device)
- 2× 9dBi circular polarization UHF antennas (ordered)
- UHF RFID tags on cyclists (ordered from AliExpress)

**Timing architecture (planned):**
```
                    ┌─────────────────┐
  [START LINE]      │   CL7206C2      │      [FINISH LINE]
  9dBi Antenna ────►│   RFID Reader   │◄──── 9dBi Antenna
  (ANT1/Port 0)     │   192.168.1.116 │      (ANT2/Port 1)
                    └────────┬────────┘
                             │ TCP/9090
                             ▼
                    ┌─────────────────┐
                    │  Timing Server  │
                    │  (Python app)   │
                    │                 │
                    │  - Tag registry │
                    │  - Split times  │
                    │  - Results      │
                    └─────────────────┘
```

**Key features needed:**
- ant_num in tag data identifies START vs FINISH antenna
- Microsecond timestamps from reader for precision
- Tag deduplication (configurable filter time)
- Real-time display of results
- GPI triggers for manual start signal (optional)
- GPO relay for start gate / traffic light (optional)

**Status:** Waiting for antennas and tags delivery. Protocol is ready.

---

## 🔗 References

- [FCC Filing (CL7206C)](https://fccid.io/2AKAGCLOUIOTCL7206C)
- [CL7206B User Manual (similar model)](https://fccid.io/2AKAGCLOUIOTCL7206B/User-Manual/User-Manual-3232262)
- Manufacturer: Shenzhen Clou IoT Technologies Co., Ltd (Hopeland Technologies)
- Website: clouglobal.com / szclou.com

---

## 📜 Reverse Engineering Log

| Date | Milestone |
|------|-----------|
| 2026-02-07 | Initial access via telnet (root, no password) |
| 2026-02-07 | Filesystem enumeration, config_pram binary analysis |
| 2026-02-07 | Binary extraction via TFTP |
| 2026-02-08 | Discovered binary is NOT stripped — 310 function symbols |
| 2026-02-08 | Ghidra analysis: protocol_cmd_hdl() fully decompiled |
| 2026-02-08 | CRC16 algorithm verified: poly 0x8005, init 0x0000 |
| 2026-02-08 | Python client created, all read commands tested OK |
| 2026-02-08 | tag_data_analise() decoded — TLV format, 8-antenna mapping |
| 2026-02-08 | Gpo_Data_Process() decoded — GPIO relay antenna switching |

---

## ⚠️ Disclaimer

This project is for **educational and personal use**. The reverse engineering was performed on hardware owned by the author. No proprietary SDK or documentation was used — all protocol information was derived from firmware analysis using Ghidra.
