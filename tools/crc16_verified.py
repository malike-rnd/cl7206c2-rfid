#!/usr/bin/env python3
"""
CRC16 for CL7206C2 — VERIFIED from firmware CRCtable dump

Polynomial: 0x8005 (CRC-16/IBM, CRC-16/BUYPASS, CRC-16/UMTS)
Init value: 0x0000
Algorithm:  Non-reflected (MSB-first)
Formula:    crc = (crc << 8) ^ table[(crc >> 8) ^ byte]
"""

def generate_crc16_table(poly=0x8005):
    table = []
    for i in range(256):
        crc = i << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = (crc << 1) ^ poly
            else:
                crc <<= 1
            crc &= 0xFFFF
        table.append(crc)
    return table

CRC16_TABLE = generate_crc16_table(0x8005)

# Verify against Ghidra dump
print("=== VERIFY AGAINST GHIDRA CRCtable ===")
print(f"  table[0] = 0x{CRC16_TABLE[0]:04X}  (expect 0x0000)")
print(f"  table[1] = 0x{CRC16_TABLE[1]:04X}  (expect 0x8005)")
print(f"  table[2] = 0x{CRC16_TABLE[2]:04X}  (expect 0x800F)")
print(f"  table[3] = 0x{CRC16_TABLE[3]:04X}  (expect 0x000A)")
print(f"  table[4] = 0x{CRC16_TABLE[4]:04X}  (expect 0x801B)")
print(f"  table[5] = 0x{CRC16_TABLE[5]:04X}  (expect 0x001E)")
print(f"  table[6] = 0x{CRC16_TABLE[6]:04X}  (expect 0x0014)")
print(f"  table[7] = 0x{CRC16_TABLE[7]:04X}  (expect 0x8011)")

match = (CRC16_TABLE[0] == 0x0000 and 
         CRC16_TABLE[1] == 0x8005 and 
         CRC16_TABLE[2] == 0x800F and 
         CRC16_TABLE[3] == 0x000A and
         CRC16_TABLE[4] == 0x801B and
         CRC16_TABLE[5] == 0x001E and
         CRC16_TABLE[6] == 0x0014 and
         CRC16_TABLE[7] == 0x8011)

print(f"\n  {'✓ PERFECT MATCH!' if match else '✗ MISMATCH'}")

def crc16(data, init=0x0000):
    crc = init
    for byte in data:
        crc = ((crc << 8) & 0xFFFF) ^ CRC16_TABLE[((crc >> 8) ^ byte) & 0xFF]
    return crc

import struct

print("\n=== READY-TO-SEND PACKETS (poly=0x8005, init=0x0000) ===\n")

def build_packet(cmd, sub, data=b''):
    data_len = len(data)
    crc_payload = bytes([cmd, sub, (data_len >> 8) & 0xFF, data_len & 0xFF]) + data
    c = crc16(crc_payload)
    return bytes([0xAA]) + crc_payload + bytes([c >> 8, c & 0xFF])

packets = [
    (0x01, 0x00, b'',       'Get Reader Info'),
    (0x01, 0x05, b'',       'Get Network (IP/Mask/GW)'),
    (0x01, 0x06, b'',       'Get MAC Address'),
    (0x01, 0x11, b'',       'Get System Time'),
    (0x01, 0x0A, b'',       'Get GPI Inputs'),
    (0x01, 0x18, b'',       'Get Tag Cache Switch'),
    (0x01, 0x1A, b'',       'Get Tag Cache Time'),
    (0x01, 0x16, b'',       'Get RS485 Config'),
    (0x01, 0x24, b'',       'Get Relay Config'),
    (0x01, 0x2E, b'',       'Get Ping Config'),
    (0x01, 0x1B, b'',       'Get Tag Records'),
    (0x01, 0x1C, b'',       'Clear All Tags'),
    (0x01, 0x0F, b'',       'REBOOT'),
    (0x01, 0x14, b'',       'FACTORY RESET'),
    (0x02, 0x10, b'',       'Start Inventory'),
    (0x02, 0xFF, b'',       'Stop Inventory'),
]

for cmd, sub, data, name in packets:
    pkt = build_packet(cmd, sub, data)
    hex_str = ' '.join(f'{b:02X}' for b in pkt)
    print(f"  {hex_str:<35s}  {name}")
