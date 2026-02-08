# CLOU CL7206C2 UHF RFID Reader — Complete Reverse Engineering & Tools

> 🇬🇧 **English** | [🇷🇺 Русский](README.ru.md)

> **100% firmware reverse engineering** of the CLOU (Hopeland) CL7206C2 8-port UHF RFID fixed reader.
> Proprietary binary protocol fully decoded. 80 functions decompiled. No vendor SDK required.

## 🎯 Project Goal

Building a **cycling race timing system** using this reader + UHF antennas + RFID tags on cyclists.
This repo contains everything needed to control the reader programmatically without vendor software.

---

## 📦 Hardware

| Parameter | Value |
|-----------|-------|
| **Model** | CLOU CL7206C2 / CL7206C4 (Hopeland Technologies, Shenzhen) |
| **Family** | CL7206C series — C2 (8-port via 4RF×2MUX) / C4 (4-port). Same firmware & protocol. |
| **FCC ID** | 2AKAGCLOUIOTCL7206C |
| **Firmware** | CL7206C_20170602 (HW v0.1, FW v0.19) |
| **CPU** | ARM (Linux 2.6.39+, BusyBox v1.6.0) |
| **Toolchain** | GCC 4.0.0 (DENX ELDK 4.1) |
| **RF Ports** | 4 RF × 2 MUX = **8 antenna ports** (C2) / 4 ports (C4) |
| **Max Power** | 33 dBm (±1 dB) per port, 1 dB step adjustment |
| **Frequency** | CN 840–845 + 920–925 MHz / FCC 902–928 MHz / ETSI 865–868 MHz |
| **Protocol** | ISO 18000-6C (EPC Gen2) / ISO 18000-6B |
| **Read Distance** | 0–8 m (depends on tag/antenna/environment) |
| **Channel BW** | <200 kHz |
| **I/O** | 4× GPI (optocoupler, DC 0–12V, >9V=HIGH / <8V=LOW) |
| **Relays** | 4× GPO (DC max 30V/2A, AC max 125V/0.3A, default: open circuit) |
| **Wiegand** | WG0 + WG1 output (26/34/66 bit formats), default: high level |
| **Interfaces** | Ethernet 10/100M, RS-232, RS-485, USB Device, USB Host |
| **RS-232 Baud** | 115200 (default), 19200, 9600 bps |
| **RS-485 Baud** | 115200 (default), 19200, 9600 bps |
| **Power** | DC 10–30V (60W min), adapter: AC 100–240V 50/60Hz → DC 24V/2.5A |
| **Protection** | IP54, operating −20°C to +70°C, storage −40°C to +85°C |
| **Dimensions** | 256 × 147.6 × 43.47 mm, 1.41 kg |
| **Connectors** | 4× TNC (reverse polarity, internal thread, inner pin) |
| **RF Cable** | Max 5m, 50Ω, insertion loss <2dB, TNC↔SMA adapters |
| **Network Cable** | Max 80m (direct or via switch/router) |
| **Serial Cable** | Max 10m (RS-232 DB9) |
| **Boot time** | ~20 seconds |

### I/O Terminal Block Pinout

```
R1 L1 R2 L2 R3 L3 R4 L4 GND GND │ IN1 IN2 IN3 IN4 IN_GND │ WG0 WG1 GND │ 485-A 485-B
└──────── 4× Relay outputs ───────┘ └── 4× Optocoupler in ──┘ └─ Wiegand ──┘ └── RS485 ──┘
```

> R1/L1 are both sides of relay 1 contact (normally open). Same for R2/L2, R3/L3, R4/L4.
> IN_GND is separate from relay/signal GND — it's the optocoupler input reference ground.

---

## 🔌 Network Configuration

| Parameter | Default |
|-----------|---------|
| IP Address | **192.168.1.116** |
| Subnet | 255.255.255.0 |
| Gateway | 192.168.1.1 |
| TCP Port | **9090** (management + data) |
| UDP Port | **9090** (broadcast discovery) |
| Telnet | Port 23, login: `root` / no password |
| DHCP | Off (static IP by default) |
| Max TCP Clients | 2 (simultaneous) |

> If you forget the IP, reset via RS-232 serial port or use `cl7206c2_tool.py discover`.

---

## 🛠 Tools

### `tools/cl7206c2_client.py` — Complete Protocol Client (1118 lines)

Full-featured client for reader control. All commands implemented from firmware reverse engineering.

```bash
# === GET commands (read configuration) ===
python3 cl7206c2_client.py 192.168.1.116 info          # Reader model, firmware, uptime
python3 cl7206c2_client.py 192.168.1.116 network       # IP / Mask / Gateway
python3 cl7206c2_client.py 192.168.1.116 mac           # MAC address
python3 cl7206c2_client.py 192.168.1.116 time          # System clock (sec + usec)
python3 cl7206c2_client.py 192.168.1.116 gpi           # Read 4 GPI input levels
python3 cl7206c2_client.py 192.168.1.116 relay         # Relay number + on-time
python3 cl7206c2_client.py 192.168.1.116 rs485         # RS485 address & mode
python3 cl7206c2_client.py 192.168.1.116 tagcache      # Tag cache switch
python3 cl7206c2_client.py 192.168.1.116 tagtime       # Tag cache duration
python3 cl7206c2_client.py 192.168.1.116 ping          # Ping watchdog config
python3 cl7206c2_client.py 192.168.1.116 wiegand       # Wiegand output config
python3 cl7206c2_client.py 192.168.1.116 server        # Server/client mode
python3 cl7206c2_client.py 192.168.1.116 com           # COM/baud config
python3 cl7206c2_client.py 192.168.1.116 antenna 0     # Antenna port 0 config
python3 cl7206c2_client.py 192.168.1.116 antennaall    # All 4 antenna configs
python3 cl7206c2_client.py 192.168.1.116 trigger 0     # GPI trigger 0 config
python3 cl7206c2_client.py 192.168.1.116 triggerall    # All 4 trigger configs

# === SET commands (write configuration) ===
python3 cl7206c2_client.py 192.168.1.116 settime now            # Sync clock to PC time
python3 cl7206c2_client.py 192.168.1.116 setpower 0 30          # RF port 0 = 30 dBm
python3 cl7206c2_client.py 192.168.1.116 setantenna 0 30 2 0 4  # Full antenna config
python3 cl7206c2_client.py 192.168.1.116 setip 192.168.1.200 255.255.255.0 192.168.1.1
python3 cl7206c2_client.py 192.168.1.116 setmac AA:BB:CC:DD:EE:FF
python3 cl7206c2_client.py 192.168.1.116 setrelay 1 500         # Relay 1, 500ms on-time
python3 cl7206c2_client.py 192.168.1.116 settrigger 0 1 6 3000  # GPI-0: rising start, 30s auto-stop

# === Tag operations ===
python3 cl7206c2_client.py 192.168.1.116 inventory     # Live tag stream (Ctrl+C to stop)
python3 cl7206c2_client.py 192.168.1.116 monitor       # Passive packet listener
python3 cl7206c2_client.py 192.168.1.116 tags          # Retrieve stored tag records
python3 cl7206c2_client.py 192.168.1.116 cleartags     # Clear tag database

# === System commands ===
python3 cl7206c2_client.py 192.168.1.116 reboot        # Reboot reader (⚠️)
python3 cl7206c2_client.py 192.168.1.116 reset         # Factory reset (⚠️ asks confirmation)
```

Requirements: Python 3.6+, no external dependencies.

### `tools/cl7206c2_tool.py` — UDP Discovery & Config Parser

```bash
python3 cl7206c2_tool.py discover                       # Find readers on network
python3 cl7206c2_tool.py info 192.168.1.116              # Query reader via UDP
python3 cl7206c2_tool.py dump-config config_pram         # Decode config file offline
```

---

## 📡 Protocol Specification

### Packet Frame

```
 Byte:   0      1     2     3       4       5..N      N+1     N+2
       ┌──────┬─────┬─────┬───────┬───────┬─────────┬───────┬───────┐
       │ 0xAA │ CMD │ SUB │ LEN_H │ LEN_L │ DATA... │ CRC_H │ CRC_L │
       └──────┴─────┴─────┴───────┴───────┴─────────┴───────┴───────┘
                |<============= CRC covers this ============>|
```

### CRC16 (verified from firmware @ 0x00020fe4)

| Parameter | Value |
|-----------|-------|
| **Polynomial** | **0x8005** (CRC-16/BUYPASS) |
| **Init** | 0x0000, no reflection, MSB-first |
| **Coverage** | CMD + SUB + LEN + DATA (header 0xAA excluded) |

### Complete Command Map (CMD=0x01)

| SUB | R/W | Function | Client Command |
|-----|-----|----------|----------------|
| 0x00 | R | Reader Info (model, name, uptime) | `info` |
| 0x02 | W | Set COM/Baud | — |
| 0x03 | R | Get COM/Baud | `com` |
| 0x04 | W | Set IP/Mask/Gateway | `setip` |
| 0x05 | R | Get Network | `network` |
| 0x06 | R | Get MAC | `mac` |
| 0x07 | W | Set Server/Client Mode | — |
| 0x08 | R | Get Server/Client | `server` |
| 0x09 | W | Set GPO Output | — |
| 0x0A | R | Get GPI Levels (all 4) | `gpi` |
| 0x0B | W | Set Antenna/Trigger | `setantenna`, `settrigger` |
| 0x0C | R | Get Antenna/Trigger | `antenna`, `trigger` |
| 0x0D | W | Set Wiegand | `setwiegand` |
| 0x0E | R | Get Wiegand | `wiegand` |
| 0x0F | X | **Reboot** (+ RF reset) | `reboot` |
| 0x10 | W | Set System Time | `settime` |
| 0x11 | R | Get System Time | `time` |
| 0x12 | — | Connection ACK (keepalive) | — |
| 0x13 | W | Set MAC | `setmac` |
| 0x14 | X | **Factory Reset** (+ RF baud reset) | `reset` |
| 0x15 | W | Set RS485 | `setrs485` |
| 0x16 | R | Get RS485 (addr + mode) | `rs485` |
| 0x17 | W | Set Tag Cache | `settagcache` |
| 0x18 | R | Get Tag Cache Switch | `tagcache` |
| 0x19 | W | Set Tag Cache Time | `settagtime` |
| 0x1A | R | Get Tag Cache Time | `tagtime` |
| 0x1B | R | Get Stored Tags (paginated) | `tags` |
| 0x1C | X | Clear All Tags | `cleartags` |
| 0x1D | X | Delete Tag by Index | — |
| 0x20 | R | Get White List Entries | — |
| 0x21 | W | Upload White List | — |
| 0x23 | W | Set Relay Config | `setrelay` |
| 0x24 | R | Get Relay (num + on_time) | `relay` |
| 0x2D | W | Set Ping Config | `setping` |
| 0x2E | R | Get Ping Config | `ping` |
| 0x2F | W | Set DHCP Mode | — |
| 0x30 | R | Get DHCP Mode | — |
| 0x54 | — | RS485 Passthrough | — |
| 0x55 | X | Delete Tag by Index (alias) | — |

### RF Commands

| CMD | SUB | Function |
|-----|-----|----------|
| 0x02 | 0x10 | **Start Inventory** |
| 0x02 | 0x40 | **Start Inventory** (alternate) |
| 0x02 | 0xFF | **Stop Inventory** |
| 0x04 | 0x00 | Firmware Upgrade (network) |
| 0x04 | 0x01 | RF Module Firmware Upgrade |
| 0x12 | 0x00 | **Tag Notification** (EPC only) |
| 0x12 | 0x20 | **Tag Notification** (EPC + extra data) |
| 0x12 | 0x30 | **Tag Notification** (EPC + TID) |

### UDP Discovery Response (multicast 230.1.1.116)

```
^RFID_READER_INFORMATION:7206C2,DHCP_SW:{ON|OFF},IP:{ip},MASK:{mask},
GATEWAY:{gw},MAC:{mac},PORT:{port},HOST_SERVER_IP:{srv_ip},
HOST_SERVER_PORT:{srv_port},MODE:{SERVER|CLIENT},NET_STATE:{ACTIVE|INACTIVE}$
```

---

## 📻 8-Antenna Architecture

```
RF Port 0 ──┬── MUX=0 → ANT1     RF Port 2 ──┬── MUX=0 → ANT5
             └── MUX=1 → ANT2                  └── MUX=1 → ANT6
RF Port 1 ──┬── MUX=0 → ANT3     RF Port 3 ──┬── MUX=0 → ANT7
             └── MUX=1 → ANT4                  └── MUX=1 → ANT8
```

Physical antenna = `ant_num × 2 + sub_ant_num + 1` (1–8)

> CL7206C4 has 4 TNC connectors = 4 antennas directly (no MUX switching).

---

## 🏷 Tag Data Pipeline

```
RF Module → TLV packet → tag_data_analise() → 500-byte struct
  ├─► sql_insert() → back_tag_data (RAM, 5s buffer) → tag_data (disk)
  ├─► transfer_to_pc() → TCP client (real-time stream)
  └─► WieGand_Data_Save() → Wiegand output (if enabled)
```

Timestamps: `gettimeofday()` = **microsecond precision**.

### SQLite Schema (`/tag_table`)

```sql
CREATE TABLE tag_data (
    tag_index    INTEGER PRIMARY KEY,  -- auto-increment
    package_len  INT,                  -- raw packet length
    package_data BLOB,                 -- raw RF + appended timestamp TLV
    epc_len      INT,                  -- EPC data length (bytes)
    epc_code     BLOB,                 -- EPC tag identifier
    pc           INT,                  -- Protocol Control word
    ant_num      INT,                  -- RF port (0–3)
    sub_ant_num  INT,                  -- MUX position (0–1)
    tid_flag     INT,                  -- TID present (0/1)
    tid_len      INT,                  -- TID data length
    tid_code     BLOB,                 -- TID data bytes
    time_seconds INT,                  -- Unix timestamp (seconds)
    time_usec    INT                   -- Microseconds
);
-- back_tag_data: same schema, in :memory: database, 5-second buffer
```

---

## ⚡ GPI Trigger System

4 optocoupler inputs can auto-start/stop inventory. 5-state FSM per GPI.

| Mode | Value | Description |
|------|-------|-------------|
| Disabled | 0 | No trigger |
| Rising Edge | 1 | LOW→HIGH (button press) |
| Falling Edge | 2 | HIGH→LOW (button release) |
| Level HIGH | 3 | While >9V (photocell gate) |
| Level LOW | 4 | While <8V |
| Any Edge | 5 | Both transitions |
| Delay Timer | 6 | Auto-stop after N×10ms |

```bash
# Race start button (rising edge, 30s auto-stop)
python3 cl7206c2_client.py 192.168.1.116 settrigger 0 1 6 3000

# Photocell gate: start on HIGH, stop on LOW
python3 cl7206c2_client.py 192.168.1.116 settrigger 1 3 4
```

---

## 🔬 Firmware Analysis — 100% Complete

80 functions decompiled from unstripped ARM ELF binary (310 symbols). ~4000 lines of Python analysis. All application logic decoded — only trivial getters/setters remain.

| Subsystem | Key Functions |
|-----------|--------------|
| Main loop | `main()` — select() on 10 FDs, dual TCP clients |
| Command router | `GetHead()` — 37+ sub-commands |
| Tag pipeline | `tag_data_analise`, `sql_insert`, `transfer_to_pc` |
| Database | `data_base_init/machine/answer_machine`, 6 SQL functions |
| Config | `config_set_pra`, `config_get_pra`, `pram_p_array` (16 params) |
| Triggers | `Triger_State_Machine`, `Triger_Manage` + 4 helpers |
| Network | `tcp_recive`, `connect_manage`, `link_status_mornitor` |
| GPIO | `gpio_init`, `gpio_relay_on_ctl`, `relay_timer_start`, 6 ioctl helpers |
| Wiegand | `WieGand_Data_Save` (EPC/TID, 300-entry circular buffer) |
| Firmware OTA | `Upgrade_Process` (CRC32 + app signature verify) |
| UDP discovery | `UDP_cmd_process` (frame: `^[mac][commands]$`) |
| Watchdog | `fifo_write` → "reader process alive" / 2s → `feed_dog` |
| Ethernet | `link_status_mornitor` — 3 failures → PHY reset cycle |
| White list | `data_base_white_list_check` — **STUB** (returns 1, not implemented) |
| Timers | `cpu_get_lltimer`, `cpu_diff_tick` (100ms ticks), `cpu_diff_us` (μs) |
| Config file | `config_pram_init` (0x430 bytes), `config_reset` (preserves MAC!) |
| Protocol parser | `protocol_data_process` — 7-state FSM, CRC verify, circular buffer |
| Transfer | `transfer_to_pc` — TCP/serial/RS485 auto-detect, 3-fail socket reset |
| Receive | `com_recive` — circular buffer read, EINTR/EAGAIN handling |
| Reconnect | `client_mode_reconnect` — auto TCP reconnect every ~9s |
| Wiegand TX | `WieGand_Send` — bit-level Wiegand-26/34/66 with 100μs pulses, 500ms min interval |
| RS485 framing | `Rs485_data_process` + `Add_Rs485_Addr` — address byte insert/strip, CMD bit 5 flag |
| TCP setup | `tcp_socket_setup` — **keepalive: 5s idle + 3×1s = 8s dead peer detection** |
| Heartbeat | `heart_beat_manage` + `if_com_alive` — serial number gap ≥4 = dead |
| Network init | `net_pram_init` — static IP or DHCP, MAC with fallback |
| Firmware replace | `upgrade_instead_file` — backup to `/back_app`, white list upload mode |

### Internal Architecture

```
                    ┌──────────────────────────────────────┐
                    │          MAIN SELECT() LOOP           │
                    │                                      │
  RF Module ──────► rf_com_fd ──► protocol_data_process()  │
  PC Serial ──────► pc_com_fd ──► GetHead() ─┬► transfer_to_rf()
  RS-485 ─────────► rs485_com_fd              ├► transfer_to_pc()
  USB Serial ─────► usb_com_fd                ├► config_set/get_pra()
  USB Hotplug ────► usb_disk_fd               ├► data_base_store_record()
  UDP Broadcast ──► multicast_rec_fd          ├► WieGand_Data_Save()
  TCP Client 1 ──► tcp_connect_fd             ├► Upgrade_Process()
  TCP Client 2 ──► tcp_connect_back_fd        └► gpio/relay/trigger
  TCP Socket ────► socket_fd                   │
                    │  Per-loop: data_base_machine(), connect_manage(),
                    │  link_status_mornitor(), fifo_write(), DHCP check
                    └──────────────────────────────────────┘
```

---

## 📂 Repository Structure

```
cl7206c2-rfid/
├── README.md                                    ← This file (English)
├── README.ru.md                                 ← Russian version
├── .gitignore
├── tools/
│   ├── cl7206c2_client.py                       ← Complete protocol client (1118 lines)
│   ├── cl7206c2_tool.py                         ← UDP discovery + config parser
│   └── crc16_verified.py                        ← Reference CRC16 implementation
├── docs/
│   ├── CL7206C2_Protocol_Spec.md                ← Protocol specification
│   ├── CL7206C2_RE_Report.md                    ← Reverse engineering report
│   ├── config_pram_analysis.md                  ← Config format analysis
│   └── CL7206C4_User_Manual.pdf                 ← Official manufacturer manual
└── firmware_analysis/
    ├── architecture.py                          ← Complete firmware architecture map
    ├── tag_data_struct.py                       ← Tag data struct + SQLite + parsers
    ├── trigger_system.py                        ← Trigger FSM + config builder
    ├── pram_p_array_decode.py                   ← Config parameter table decoder
    ├── remaining_subsystems.py                  ← Network, GPIO, DB, UDP subsystems
    ├── utility_functions.py                     ← GPIO ioctl map, timers, config, protocol parser
    ├── final_functions.py                       ← Wiegand TX, RS485 framing, TCP keepalive, OTA
    └── CL7206C2_strings.txt                     ← All 1206 extracted strings
```

---

## ⏱ Future: Cycling Race Timing

```
  [START]  9dBi ──►  CL7206C2  ◄── 9dBi  [FINISH]
  (Port 0)           │ TCP/9090          (Port 1)
                     ▼
               Timing Server
               • ant_num → START / FINISH
               • μs timestamps (gettimeofday)
               • Tag dedup (5s buffer built-in)
               • Live results display
               • GPI trigger → auto start/stop inventory
               • GPO relay → gate / buzzer / light control
               • White list → relay auto-fire on known tag
```

**Status:** Protocol & firmware 100% decoded. Waiting for antennas and tags. ✅

**Key findings for timing system:**
- **No firmware dedup** — RF module cache handles sub-second repeats; client must dedup by EPC+antenna
- **TCP keepalive 8s** — dead peer detected in 5s idle + 3×1s probes (aggressive, good for timing)
- **Auto-reconnect ~17s** — 8s detection + 9s reconnect cycle = fast recovery
- **Firmware backup** — OTA creates `/back_app`, recoverable via telnet if upgrade fails

---

## 🔗 References

- [FCC Filing](https://fccid.io/2AKAGCLOUIOTCL7206C) — Internal photos, test reports
- [Hopeland](http://www.hopelandrfid.com) — Manufacturer (Shenzhen Hopeland Technologies Co., Ltd)
- Contact: support@hopelandrfid.com | +86-755-36901035

## ⚠️ Disclaimer

Educational and personal use. Reverse engineering performed on owned hardware using Ghidra. No proprietary SDK used.
