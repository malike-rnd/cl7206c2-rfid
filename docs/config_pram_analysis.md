
# CL7206C2 RFID Reader - config_pram Binary Format Analysis
# File size: 1072 bytes (0x0430)

## STRUCTURE OVERVIEW
┌─────────────────────────────────────────────────────────┐
│ Offset 0x000-0x01B: Network Configuration (28 bytes)    │
│ Offset 0x01C-0x11B: Antenna 0 Config Block (256 bytes)  │
│ Offset 0x11C-0x21B: Antenna 1 Config Block (256 bytes)  │
│ Offset 0x21C-0x31B: Antenna 2 Config Block (256 bytes)  │
│ Offset 0x31C-0x41B: Antenna 3 Config Block (256 bytes)  │
│ Offset 0x41C-0x42F: Global Settings (20 bytes)          │
└─────────────────────────────────────────────────────────┘

## 1. NETWORK BLOCK (0x00-0x1B) — 28 bytes
───────────────────────────────────────────
Offset  Size  Value           Description
------  ----  --------------  -------------------------
0x00    1     0x02            DHCP mode (0=static, 1=DHCP, 2=static?)
0x01    4     192.168.1.116   Device IP address
0x05    4     255.255.255.0   Subnet mask
0x09    4     192.168.1.1     Default gateway
0x0D    5     6C:EC:A1:FE:75  Device ID or partial MAC
0x12    2     0x003A (58)     Unknown (heartbeat interval?)
0x14    2     0x2382 (9090)   Management port (BE) ≈ UDP 9092
0x16    4     192.168.1.1     Destination/Server IP
0x1A    2     0x2382 (9090)   Data port (BE)

## 2. ANTENNA BLOCKS (0x1C-0x41B) — 4 × 256 bytes
───────────────────────────────────────────────────
Each antenna block is identical except for the index.
Active params occupy only first 12 bytes, rest = 0x00.

Offset  Size  Ant0  Ant1  Ant2  Ant3  Description
------  ----  ----  ----  ----  ----  -------------------------
+0x00   1     00    01    02    03    Antenna index (0-3)
+0x01   2     0000  0000  0000  0000  Reserved
+0x03   1     06    06    06    06    Power level (6 = ~6 dBm?)
+0x04   1     02    02    02    02    Protocol (2 = EPC Gen2?)
+0x05   1     10    10    10    10    Frequency region (0x10=16)
+0x06   1     00    00    00    00    Reserved
+0x07   1     02    02    02    02    Session (Gen2: S0-S3)
+0x08   1     01    01    01    01    Target (A/B)
+0x09   1     01    01    01    01    Q value
+0x0A   1     03    03    03    03    Unknown param
+0x0B   1     01    01    01    01    Unknown param
+0x0C   244   0...  0...  0...  0...  Reserved (all zeros)

### Power Level Notes:
  Value 6 is likely an index, not dBm directly.
  Typical CLOU mapping: 0-30 or 0-33 (representing dBm)
  Need demo software or firmware RE to confirm scale.

### Frequency Region (0x10 = 16):
  Common CLOU mappings:
    0x01 = FCC (US 902-928 MHz)
    0x02 = ETSI (EU 865-868 MHz)  
    0x04 = China 920-925 MHz
    0x10 = China 840-845 / 920-925 MHz (dual band?)
  Value 16 likely = Chinese frequency plan

## 3. GLOBAL SETTINGS (0x41C-0x42F) — 20 bytes
────────────────────────────────────────────────
Raw: 00 00 00 01 02 02 00 00 01 01 00 01 00 C0 A8 01 01 00 00 00

Offset  Size  Value         Description
------  ----  -----------   -------------------------
0x41C   3     00 00 00      Reserved
0x41F   1     0x01          Wiegand enable (1=on)
0x420   1     0x02          Wiegand format
0x421   1     0x02          Wiegand bit count config
0x422   2     00 00         Reserved
0x424   1     0x01          Buzzer enable (1=on)
0x425   1     0x01          Tag filter/dedupe (1=on)
0x426   1     0x00          Reserved
0x427   1     0x01          Auto-read mode (1=on)
0x428   1     0x00          Reserved
0x429   4     192.168.1.1   Remote server IP
0x42D   3     00 00 00      Reserved/padding

## 4. TAG DATABASE (tag_table)
──────────────────────────────
SQLite3 database, currently empty (0 rows).

CREATE TABLE tag_data(
  tag_index     INTEGER PRIMARY KEY,
  package_len   INT,
  package_data  BLOB,      -- raw packet
  epc_len       INT,
  epc_code      BLOB,      -- EPC tag ID
  pc            INT,       -- Protocol Control word  
  ant_num       INT,       -- antenna port (0-3)
  sub_ant_num   INT,       -- sub-antenna
  tid_flag      INT,       -- TID read flag
  tid_len       INT,
  tid_code      BLOB,      -- TID data
  time_seconds  INT,       -- Unix timestamp
  time_usec     INT        -- microseconds
);

## 5. UDP PROTOCOL (port 9092)
──────────────────────────────
The PC Demo software connects via UDP to port 9092.
Based on CLOU/Hopeland protocol documentation:
  - Commands are binary framed packets
  - Typical frame: [Header][Len][Cmd][Data][CRC]
  - Common commands: read EPC, set power, set frequency,
    get/set config, start/stop inventory, firmware upgrade

## 6. KEY FILES ON DEVICE
─────────────────────────
/config_pram        - This config (1072 bytes, binary)
/tag_table          - SQLite tag database  
/gateway            - Gateway IP text file
/bin/CL7206C2       - Main RFID application (150KB, ARM ELF)
/bin/fifo_read      - FIFO reader for inter-process communication
/bin/feed_dog       - Hardware watchdog feeder
/driver/wiegand.ko  - Wiegand kernel module
/driver/g_serial.ko - USB serial gadget module
