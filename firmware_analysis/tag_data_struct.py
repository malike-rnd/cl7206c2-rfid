#!/usr/bin/env python3
"""
CL7206C2 Tag Data Structure — Complete Analysis
================================================

Decoded from: tag_data_analise() + sql_insert()
Total structure size: 500 bytes (0x1F4), zeroed before use.

## tag_data_struct Layout (500 bytes)

Offset  Size   SQLite Column    Description
------  -----  ---------------  ------------------------------------------
0x000   1      —                PC high byte (Protocol Control)
0x002   2      epc_len (col 4)  EPC length in bytes
0x004   var    epc_code (col 5) EPC data (variable, up to 64 bytes)
0x044   2      pc (col 6)       Protocol Control word (big-endian)
0x046   1      ant_num (col 7)  RF port number (0–3)
0x047   1      sub_ant_num(col8) Sub-antenna number (0–1) [from TLV type 6]
0x048   1      —                Antenna byte from TLV type 1
0x049   1      —                Sub-antenna byte from TLV type 1
0x04A   1      —                RSSI/signal byte 1 (TLV type 2)
0x04B   1      —                RSSI/signal byte 2 (TLV type 2)
0x04C   1      tid_flag (col 9) TID present flag (TLV type 3 marker)
0x04E   2      tid_len (col 10) TID data length
0x050   var    tid_code (col 11) TID data (variable length)
0x090   1      —                TLV type 4 marker
0x092   2      —                TLV type 4 data length
0x094   var    —                TLV type 4 data
0x0D4   1      —                TLV type 5 marker
0x0D6   2      —                TLV type 5 data length
0x0D8   var    —                TLV type 5 data
0x0E8   4      time_sec (col 12) Unix timestamp (tv_sec from gettimeofday)
0x0EC   4      time_usec(col 13) Microseconds (tv_usec from gettimeofday)
0x0F0   var    package_data(col3) Raw RF packet (copy of original input)
0x0F3   2      —                Packet length field (in rebuilt packet)
0x1EF   1      package_len(col2) Total package length for SQL
0x1F0   4      tag_index (col 1) Auto-increment tag index

## SQLite Column Mapping (from sql_insert)

Col#  Struct Offset  Type   SQLite Column    Description
----  -------------  -----  ---------------  --------------------------------
1     0x1F0          INT    tag_index        Auto-increment index
2     0x1EF          INT    package_len      Raw packet length
3     0x0F0          BLOB   package_data     Raw RF packet (+ appended TLV)
4     0x002          INT    epc_len          EPC data length
5     0x004          BLOB   epc_code         EPC tag identifier
6     0x044          INT    pc               Protocol Control word
7     0x046          INT    ant_num          RF antenna port (0–3)
8     0x047          INT    sub_ant_num      Sub-antenna (0–1)
9     0x04C          INT    tid_flag         TID present (0/1)
10    0x04E          INT    tid_len          TID data length
11    0x050          BLOB   tid_code         TID data bytes
12    0x0E8          INT    time_seconds     Unix timestamp
13    0x0EC          INT    time_usec        Microseconds

## TLV Parser (tag_data_analise)

The RF module sends tag data in TLV format. The parser walks the input:

Type  Format                          Struct Offsets   Description
----  ------------------------------  ---------------  ---------------------------
0xAA  [AA][?][PC_hi][len_hi][len_lo]  0x000, 0x044     Header: PC word, EPC length
      [epc_len_hi][epc_len_lo][EPC..] 0x002, 0x004     EPC data
      [PC_hi][PC_lo][extra_byte]      0x044, 0x046     Protocol Control + antenna

0x01  [01][ant_num][sub_ant_num]      0x048, 0x049     Antenna identification
                                                        ant_num = RF port 0–3
                                                        sub_ant = mux switch 0–1

0x02  [02][rssi1][rssi2]              0x04A, 0x04B     Signal strength / RSSI

0x03  [03][type][len_hi|len_lo]       0x04C, 0x04E     TID data block
      [TID_data...]                   0x050             (type = tid_flag)

0x04  [04][type][len_hi|len_lo]       0x090, 0x092     Extra data block 1
      [data...]                       0x094

0x05  [05][type][len_hi|len_lo]       0x0D4, 0x0D6     Extra data block 2
      [data...]                       0x0D8

0x06  [06][sub_ant_byte]              0x047             Sub-antenna number
                                                        (alternative to type 1)

## Rebuilt Packet (appended to package_data at 0x0F0)

After copying the original RF data, tag_data_analise appends:

  [original_rf_packet]
  [0x07] [timestamp_sec(4B BE)] [timestamp_usec(4B BE)]
  [0x08] [tag_index(4B BE)]
  [CRC16 of rebuilt packet]

So package_data in SQLite contains the original RF TLV data PLUS
timestamp and index TLVs appended by the reader firmware.

## Data Flow

  RF Module → raw TLV packet
       ↓
  tag_data_analise()
       ├── Parse TLV types 0xAA, 0x01–0x06
       ├── Fill 500-byte struct
       ├── gettimeofday() → timestamp
       ├── Append TLV 0x07 (timestamp) and 0x08 (index)
       ├── Recalculate CRC16
       └── Set package_len
       ↓
  sql_insert()
       ├── Bind 13 columns from struct offsets
       └── INSERT INTO back_tag_data (or tag_data)
       ↓
  transfer_to_pc() (if enabled)
       └── Send rebuilt packet to TCP/UDP client
"""

import struct


def parse_tag_struct(data):
    """Parse a 500-byte tag_data_struct into fields.
    
    Args:
        data: bytes, at least 500 bytes (the tag_data_struct)
    
    Returns:
        dict with parsed fields
    """
    if len(data) < 500:
        return {'error': f'Too short: {len(data)} < 500'}
    
    result = {}
    
    # EPC
    result['pc_byte']     = data[0x000]
    result['epc_len']     = struct.unpack_from('>H', data, 0x002)[0]
    if result['epc_len'] > 0 and result['epc_len'] <= 64:
        result['epc_code'] = data[0x004:0x004 + result['epc_len']].hex().upper()
    else:
        result['epc_code'] = ''
    
    # Protocol Control & Antenna
    result['pc']          = struct.unpack_from('>H', data, 0x044)[0]
    result['ant_num']     = data[0x046]
    result['sub_ant_num'] = data[0x047]
    result['ant_byte1']   = data[0x048]
    result['ant_byte2']   = data[0x049]
    
    # RSSI
    result['rssi1']       = data[0x04A]
    result['rssi2']       = data[0x04B]
    
    # TID
    result['tid_flag']    = data[0x04C]
    result['tid_len']     = struct.unpack_from('>H', data, 0x04E)[0]
    if result['tid_len'] > 0 and result['tid_len'] <= 128:
        result['tid_code'] = data[0x050:0x050 + result['tid_len']].hex().upper()
    else:
        result['tid_code'] = ''
    
    # Timestamps
    result['time_sec']    = struct.unpack_from('>I', data, 0x0E8)[0]
    result['time_usec']   = struct.unpack_from('>I', data, 0x0EC)[0]
    
    # Index and package
    result['tag_index']   = struct.unpack_from('>I', data, 0x1F0)[0]
    result['package_len'] = data[0x1EF]
    
    # Physical antenna
    port = result['ant_num']
    sub  = result['sub_ant_num']
    result['physical_antenna'] = port * 2 + sub + 1  # 1-8
    
    return result


def parse_tag_notification(payload):
    """Parse a tag notification packet payload (from CMD=0x12).
    
    This is the raw TLV data before it goes into tag_data_analise().
    Useful for real-time inventory parsing.
    
    Args:
        payload: bytes from a CMD=0x12 packet
    
    Returns:
        dict with parsed tag data
    """
    result = {
        'epc': '', 'epc_len': 0, 'pc': 0,
        'ant_num': -1, 'sub_ant_num': -1,
        'rssi1': 0, 'rssi2': 0,
        'tid': '', 'tid_len': 0,
    }
    
    pos = 0
    while pos < len(payload):
        tlv_type = payload[pos]
        
        if tlv_type == 0xAA:
            # Header: [AA][?][PC_hi][len_hi][len_lo][epc_len_hi][epc_len_lo][EPC...]
            if pos + 7 > len(payload):
                break
            result['pc'] = (payload[pos + 3] << 8) | payload[pos + 4]
            epc_len = (payload[pos + 5] << 8) | payload[pos + 6]
            result['epc_len'] = epc_len
            pos += 7
            if pos + epc_len <= len(payload):
                result['epc'] = payload[pos:pos+epc_len].hex().upper()
                pos += epc_len
            # After EPC: [PC_hi][PC_lo][extra]
            if pos + 3 <= len(payload):
                result['pc'] = (payload[pos] << 8) | payload[pos + 1]
                result['ant_num'] = payload[pos + 2]
                pos += 3
        
        elif tlv_type == 0x01:
            if pos + 2 < len(payload):
                result['ant_num'] = payload[pos + 1]   # not pos, the type byte IS pos
                # Wait — TLV type 1 uses: [01][ant][sub_ant]
                # But from decompile: param_3[0x48] = input[pos], param_3[0x49] = input[pos+1]
                # and local_1e += 2. So format is [01] already consumed, next 2 bytes are data
                pass
            # Actually from code: bVar1 is already read, then:
            # param_3[0x48] = input[local_1e]       ← this is the byte AFTER type
            # param_3[0x49] = input[local_1e + 1]
            # local_1e += 2
            # But the while loop reads bVar1 = input[local_1e] first, so type byte IS at local_1e
            # Then for type 1: param_3[0x48] = input[local_1e] = type byte itself? No...
            #
            # Looking more carefully at the decompile:
            # The switch reads bVar1 = *(byte*)(local_1e + param_1)
            # Then case 1: param_3[0x48] = *(input + local_1e), param_3[0x49] = *(input + local_1e+1)
            # local_1e += 2
            # 
            # This means the type byte IS consumed by the switch but NOT incremented yet!
            # Actually no — bVar1 is read but local_1e is NOT advanced past the type byte.
            # So param_3[0x48] = input[local_1e] = the type byte (0x01) itself??
            #
            # That seems wrong. Let me re-check... Actually in the decompile the reads use
            # local_1e as-is (the position of the type byte), then advance by 2.
            # So 0x48 = type byte (0x01), 0x49 = first data byte.
            # But sql_insert maps 0x046 = ant_num and 0x047 = sub_ant_num (from TLV 0xAA/0x06).
            # TLV type 1 goes to 0x048/0x049 which are NOT in SQL — they're informational only.
            
            result['ant_byte1'] = payload[pos]      # type byte itself
            if pos + 1 < len(payload):
                result['ant_byte2'] = payload[pos + 1]
            pos += 2
        
        elif tlv_type == 0x02:
            # RSSI: [02] already consumed by switch, next 2 bytes
            # From code: param_3[0x4a] = input[local_1e], param_3[0x4b] = input[local_1e+1]
            # local_1e += 2. Same pattern — type byte position.
            result['rssi1'] = payload[pos]
            if pos + 1 < len(payload):
                result['rssi2'] = payload[pos + 1]
            pos += 2
        
        elif tlv_type == 0x03:
            # TID: [03][type][len_hi|len_lo][data...]
            if pos + 3 <= len(payload):
                result['tid_flag'] = payload[pos]
                tid_len = payload[pos + 1] | payload[pos + 2]
                result['tid_len'] = tid_len
                pos += 3
                if pos + tid_len <= len(payload):
                    result['tid'] = payload[pos:pos+tid_len].hex().upper()
                    pos += tid_len
            else:
                break
        
        elif tlv_type == 0x06:
            # Sub-antenna: [06][sub_ant]
            if pos + 1 < len(payload):
                result['sub_ant_num'] = payload[pos + 1]
            pos += 2
        
        else:
            # Unknown TLV type, try to skip
            pos += 1
    
    # Compute physical antenna
    if result['ant_num'] >= 0 and result['sub_ant_num'] >= 0:
        result['physical_antenna'] = result['ant_num'] * 2 + result['sub_ant_num'] + 1
    
    return result


if __name__ == '__main__':
    print("=" * 70)
    print("CL7206C2 TAG DATA STRUCTURE — From Firmware Analysis")
    print("=" * 70)
    
    print("""
tag_data_struct (500 bytes = 0x1F4):

  ┌─────────────────────────────────────────────────────┐
  │ 0x000–0x043: EPC Block                              │
  │   0x000: PC high byte                               │
  │   0x002: EPC length (uint16 BE)                     │
  │   0x004: EPC data (up to 64 bytes)                  │
  ├─────────────────────────────────────────────────────┤
  │ 0x044–0x04F: Antenna & Signal                       │
  │   0x044: Protocol Control word (uint16 BE)          │
  │   0x046: ant_num (RF port 0–3) → SQL col 7          │
  │   0x047: sub_ant_num (0–1)     → SQL col 8          │
  │   0x048: TLV type 1 ant byte                        │
  │   0x049: TLV type 1 sub byte                        │
  │   0x04A: RSSI byte 1                                │
  │   0x04B: RSSI byte 2                                │
  │   0x04C: TID flag (TLV type 3)                      │
  │   0x04E: TID length (uint16 BE)                     │
  ├─────────────────────────────────────────────────────┤
  │ 0x050–0x08F: TID Data (up to 64 bytes)              │
  ├─────────────────────────────────────────────────────┤
  │ 0x090–0x0D3: TLV Type 4 Data Block                  │
  │   0x090: type marker                                │
  │   0x092: data length                                │
  │   0x094: data                                       │
  ├─────────────────────────────────────────────────────┤
  │ 0x0D4–0x0E7: TLV Type 5 Data Block                  │
  │   0x0D4: type marker                                │
  │   0x0D6: data length                                │
  │   0x0D8: data                                       │
  ├─────────────────────────────────────────────────────┤
  │ 0x0E8–0x0EF: Timestamps                             │
  │   0x0E8: time_seconds (uint32 BE, gettimeofday)     │
  │   0x0EC: time_usec    (uint32 BE, gettimeofday)     │
  ├─────────────────────────────────────────────────────┤
  │ 0x0F0–0x1EE: Package Data (raw RF + appended TLVs)  │
  │   Contains original TLV data + appended:            │
  │   [0x07][ts_sec 4B][ts_usec 4B]                     │
  │   [0x08][tag_index 4B]                              │
  │   [CRC16]                                           │
  ├─────────────────────────────────────────────────────┤
  │ 0x1EF: package_len (1 byte)                         │
  │ 0x1F0: tag_index   (uint32 BE, auto-increment)      │
  └─────────────────────────────────────────────────────┘

SQL Schema (verified against sql_insert bindings):

  CREATE TABLE tag_data (
      tag_index    INTEGER PRIMARY KEY,  -- col 1,  struct+0x1F0
      package_len  INT,                  -- col 2,  struct+0x1EF
      package_data BLOB,                 -- col 3,  struct+0x0F0
      epc_len      INT,                  -- col 4,  struct+0x002
      epc_code     BLOB,                 -- col 5,  struct+0x004
      pc           INT,                  -- col 6,  struct+0x044
      ant_num      INT,                  -- col 7,  struct+0x046
      sub_ant_num  INT,                  -- col 8,  struct+0x047
      tid_flag     INT,                  -- col 9,  struct+0x04C
      tid_len      INT,                  -- col 10, struct+0x04E
      tid_code     BLOB,                 -- col 11, struct+0x050
      time_seconds INT,                  -- col 12, struct+0x0E8
      time_usec    INT                   -- col 13, struct+0x0EC
  );

  -- back_tag_data has identical schema (used as primary storage)
  -- tag_data is used when new_db is unavailable

Key Findings for Timing System:
  - Timestamps use gettimeofday() → microsecond precision
  - ant_num (0x046) identifies START vs FINISH antenna
  - sub_ant_num (0x047) set by TLV type 0x06 (GPIO mux position)
  - Physical antenna = ant_num * 2 + sub_ant_num + 1 (1–8)
  - Auto-increment index from max(tag_index) across both tables
  - Raw packet preserved in package_data for forensic replay
""")
