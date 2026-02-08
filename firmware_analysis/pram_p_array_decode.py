#!/usr/bin/env python3
"""
CL7206C2 pram_p_array decoder
Decodes the configuration parameter mapping table from firmware.

Source: 16 structures × 12 bytes at 0x0002bb80
Pointer array at 0x0002bc40 (16 × 4-byte LE pointers to structures)

Structure format (12 bytes each):
  +0x00: uint16 LE  - offset in config_pram file
  +0x02: uint16 LE  - max data size (bytes)
  +0x04: uint16 LE  - last written size
  +0x06: uint8      - SET sub-command (CMD=0x01)
  +0x07: uint8      - GET sub-command (CMD=0x01)
  +0x08: uint8      - sub-parameter (antenna index for per-port configs)
  +0x09: uint8[3]   - reserved (zeros)
"""

import struct

raw = bytes.fromhex(
    "00 00 01 00 01 00 02 03 00 00 00 00"
    "01 00 0c 00 0c 00 04 05 00 00 00 00"
    "0d 00 06 00 06 00 13 06 00 00 00 00"
    "13 00 09 00 09 00 07 08 00 00 00 00"
    "1c 00 00 01 0e 00 0b 0c 00 00 00 00"
    "1c 01 00 01 0e 00 0b 0c 01 00 00 00"
    "1c 02 00 01 0e 00 0b 0c 02 00 00 00"
    "1c 03 00 01 0e 00 0b 0c 03 00 00 00"
    "1c 04 03 00 03 00 0d 0e 00 00 00 00"
    "1f 04 02 00 02 00 15 16 00 00 00 00"
    "22 04 01 00 01 00 17 18 00 00 00 00"
    "23 04 02 00 02 00 19 1a 00 00 00 00"
    "25 04 03 00 03 00 23 24 00 00 00 00"
    "28 04 05 00 05 00 2d 2e 00 00 00 00"
    "2d 04 01 00 01 00 2f 30 00 00 00 00"
    "21 04 01 00 01 00 ff ff 00 00 00 00"
    .replace(" ", "")
)

# Known command names
CMD_NAMES = {
    (0x02, 0x03): "COM/Baud Config",
    (0x04, 0x05): "IP Configuration (IP + Mask + Gateway)",
    (0x13, 0x06): "MAC Address",
    (0x07, 0x08): "Server/Client Mode (port + server IP + server port)",
    (0x0B, 0x0C): "Antenna/Trigger Config",
    (0x0D, 0x0E): "Wiegand Config",
    (0x15, 0x16): "RS485 Config (address + mode)",
    (0x17, 0x18): "Tag Cache Switch",
    (0x19, 0x1A): "Tag Cache Time",
    (0x23, 0x24): "Relay Config",
    (0x2D, 0x2E): "Ping/Gateway Config",
    (0x2F, 0x30): "DHCP Mode",
    (0xFF, 0xFF): "(internal/sentinel)",
}

print("=" * 100)
print("CL7206C2 CONFIG PARAMETER MAP (pram_p_array) — from firmware @ 0x0002bb80")
print("=" * 100)
print()
print(f"{'#':>2}  {'Offset':>8}  {'MaxSz':>5}  {'ActSz':>5}  {'SET':>5}  {'GET':>5}  {'Sub':>3}  Description")
print("-" * 100)

for i in range(16):
    entry = raw[i*12 : (i+1)*12]
    offset = struct.unpack_from('<H', entry, 0)[0]
    max_sz = struct.unpack_from('<H', entry, 2)[0]
    act_sz = struct.unpack_from('<H', entry, 4)[0]
    set_cmd = entry[6]
    get_cmd = entry[7]
    sub_param = entry[8]

    name = CMD_NAMES.get((set_cmd, get_cmd), "???")
    if (set_cmd, get_cmd) == (0x0B, 0x0C):
        name = f"Antenna/Trigger Config — RF Port {sub_param} (ANT{sub_param*2+1}/ANT{sub_param*2+2})"

    print(f"{i:>2}  0x{offset:04X}    {max_sz:>5}  {act_sz:>5}  0x{set_cmd:02X}   0x{get_cmd:02X}   {sub_param:>3}  {name}")

print()
print("=" * 100)
print("COMPLETE config_pram LAYOUT (1072 bytes = 0x0430)")
print("=" * 100)
print()

layout = [
    (0x0000, 1,    "COM/Baud Config",                     "SET 0x02 / GET 0x03"),
    (0x0001, 12,   "IP Config: IP(4) + Mask(4) + GW(4)",  "SET 0x04 / GET 0x05"),
    (0x000D, 6,    "MAC Address (6 bytes)",                "SET 0x13 / GET 0x06"),
    (0x0013, 9,    "Server/Client: port(2)+IP(4)+port(2)+mode(1)", "SET 0x07 / GET 0x08"),
    (0x001C, 256,  "RF Port 0 Config → ANT1/ANT2",        "SET 0x0B / GET 0x0C sub=0"),
    (0x011C, 256,  "RF Port 1 Config → ANT3/ANT4",        "SET 0x0B / GET 0x0C sub=1"),
    (0x021C, 256,  "RF Port 2 Config → ANT5/ANT6",        "SET 0x0B / GET 0x0C sub=2"),
    (0x031C, 256,  "RF Port 3 Config → ANT7/ANT8",        "SET 0x0B / GET 0x0C sub=3"),
    (0x041C, 3,    "Wiegand: enable(1)+format(1)+bits(1)", "SET 0x0D / GET 0x0E"),
    (0x041F, 2,    "RS485: address(1)+mode(1)",            "SET 0x15 / GET 0x16"),
    (0x0421, 1,    "(internal sentinel, 0xFF/0xFF)",       "—"),
    (0x0422, 1,    "Tag Cache Switch",                     "SET 0x17 / GET 0x18"),
    (0x0423, 2,    "Tag Cache Time",                       "SET 0x19 / GET 0x1A"),
    (0x0425, 3,    "Relay Config",                         "SET 0x23 / GET 0x24"),
    (0x0428, 5,    "Ping/Gateway Config",                  "SET 0x2D / GET 0x2E"),
    (0x042D, 1,    "DHCP Mode",                            "SET 0x2F / GET 0x30"),
]

total = 0
for offset, size, desc, cmds in layout:
    end = offset + size - 1
    print(f"  0x{offset:04X}–0x{end:04X}  ({size:>4} bytes)  {desc:<50s} {cmds}")
    total += size

print(f"\n  Total mapped: {total} bytes out of 1072 (0x0430)")
print(f"  Unmapped: {1072 - total} bytes (0x042E–0x042F = 2 bytes padding)")

print()
print("=" * 100)
print("SET COMMAND PACKET EXAMPLES (CMD=0x01)")
print("=" * 100)
print("""
To SET a config parameter, send:
  AA 01 [SET_SUB] [LEN_H] [LEN_L] [data...] [CRC_H] [CRC_L]

For antenna configs (SET=0x0B), the sub-parameter (antenna index) is byte[0] of data:
  AA 01 0B [LEN_H] [LEN_L] [ant_index] [config_data...] [CRC_H] [CRC_L]

Antenna config data format (14 bytes active, 256 max):
  Byte 0:   Antenna index (0-3)
  Byte 1-2: Reserved (0x00 0x00)
  Byte 3:   Power level (0-33 = dBm)
  Byte 4:   Protocol (2 = EPC Gen2 dual-target)
  Byte 5:   Frequency region (0x10 = CN dual-band)
  Byte 6:   Reserved (0x00)
  Byte 7:   Session (0-3 = S0-S3)
  Byte 8:   Target (0=A, 1=B)
  Byte 9:   Q value
  Byte 10:  Unknown param
  Byte 11:  Unknown param
  Byte 12+: Reserved

Example — Set RF Port 0 power to 30 dBm:
  Data: 00 00 00 1E 02 10 00 02 01 01 03 01 00 00
        ^ant=0   ^pwr=30
  Packet: AA 01 0B 00 0E [data 14 bytes] [CRC16]
""")
