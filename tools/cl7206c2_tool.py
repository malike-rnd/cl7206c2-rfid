#!/usr/bin/env python3
"""
CL7206C2 RFID Reader — Discovery & Communication Tool
Based on reverse engineering of firmware CL7206C2_STD_APP (2017-06-02)

Usage:
  python3 cl7206c2_tool.py discover          # Find readers on network
  python3 cl7206c2_tool.py info <ip>          # Get reader info via UDP
  python3 cl7206c2_tool.py dump-config <file> # Parse config_pram binary
  python3 cl7206c2_tool.py edit-config <file> # Interactive config editor
"""

import socket
import struct
import sys
import time
import os

# ═══════════════════════════════════════════════════════════
# CONFIG_PRAM PARSER
# ═══════════════════════════════════════════════════════════

FREQ_REGIONS = {
    0x01: "FCC (US 902-928 MHz)",
    0x02: "ETSI (EU 865-868 MHz)",
    0x04: "China 920-925 MHz",
    0x06: "Korea",
    0x08: "Japan",
    0x10: "China Dual-band (840-845 / 920-925 MHz)",
}

PROTOCOLS = {
    0x00: "ISO 18000-6B",
    0x01: "EPC Gen2 (6C) - Single target",
    0x02: "EPC Gen2 (6C) - Dual target",
}

SESSIONS = {0: "S0", 1: "S1", 2: "S2", 3: "S3"}
TARGETS = {0: "A", 1: "B"}


class ConfigPram:
    """Parser for /config_pram binary file (1072 bytes)"""
    
    SIZE = 0x0430  # 1072 bytes
    ANT_BLOCK_SIZE = 0x100  # 256 bytes per antenna
    ANT_BLOCK_START = 0x1C
    GLOBAL_START = 0x41C
    
    def __init__(self, data=None, filename=None):
        if filename:
            with open(filename, 'rb') as f:
                data = f.read()
        if len(data) != self.SIZE:
            raise ValueError(f"Expected {self.SIZE} bytes, got {len(data)}")
        self.data = bytearray(data)
    
    # --- Network fields ---
    @property
    def dhcp_mode(self): return self.data[0x00]
    
    @property
    def ip(self): return f"{self.data[1]}.{self.data[2]}.{self.data[3]}.{self.data[4]}"
    
    @property
    def mask(self): return f"{self.data[5]}.{self.data[6]}.{self.data[7]}.{self.data[8]}"
    
    @property
    def gateway(self): return f"{self.data[9]}.{self.data[10]}.{self.data[11]}.{self.data[12]}"
    
    @property
    def device_mac(self): return ':'.join(f'{b:02X}' for b in self.data[0x0D:0x12])
    
    @property
    def local_port(self): return struct.unpack('>H', self.data[0x14:0x16])[0]
    
    @property
    def server_ip(self): return f"{self.data[0x16]}.{self.data[0x17]}.{self.data[0x18]}.{self.data[0x19]}"
    
    @property
    def server_port(self): return struct.unpack('>H', self.data[0x1A:0x1C])[0]
    
    # --- Antenna fields ---
    def get_antenna(self, n):
        base = self.ANT_BLOCK_START + n * self.ANT_BLOCK_SIZE
        b = self.data[base:base+12]
        return {
            'index': b[0],
            'power': b[3],
            'protocol': b[4],
            'protocol_name': PROTOCOLS.get(b[4], f"Unknown (0x{b[4]:02X})"),
            'freq_region': b[5],
            'freq_name': FREQ_REGIONS.get(b[5], f"Unknown (0x{b[5]:02X})"),
            'session': b[7],
            'session_name': SESSIONS.get(b[7], f"Unknown ({b[7]})"),
            'target': b[8],
            'target_name': TARGETS.get(b[8], f"Unknown ({b[8]})"),
            'q_value': b[9],
            'param_a': b[10],
            'param_b': b[11],
        }
    
    # --- Global fields ---
    @property
    def wiegand_enabled(self): return self.data[self.GLOBAL_START + 3]
    
    @property
    def wiegand_format(self): return self.data[self.GLOBAL_START + 4]
    
    @property
    def wiegand_bits(self): return self.data[self.GLOBAL_START + 5]
    
    @property
    def buzzer_enabled(self): return self.data[self.GLOBAL_START + 8]
    
    @property
    def tag_filter(self): return self.data[self.GLOBAL_START + 9]
    
    @property
    def auto_read(self): return self.data[self.GLOBAL_START + 11]
    
    @property
    def host_server_ip(self):
        o = self.GLOBAL_START + 13
        return f"{self.data[o]}.{self.data[o+1]}.{self.data[o+2]}.{self.data[o+3]}"
    
    # --- Setters ---
    def set_ip(self, ip_str):
        parts = [int(x) for x in ip_str.split('.')]
        self.data[1:5] = bytes(parts)
    
    def set_mask(self, mask_str):
        parts = [int(x) for x in mask_str.split('.')]
        self.data[5:9] = bytes(parts)
    
    def set_gateway(self, gw_str):
        parts = [int(x) for x in gw_str.split('.')]
        self.data[9:13] = bytes(parts)
    
    def set_antenna_power(self, ant_num, power):
        base = self.ANT_BLOCK_START + ant_num * self.ANT_BLOCK_SIZE
        self.data[base + 3] = power
    
    def save(self, filename):
        with open(filename, 'wb') as f:
            f.write(self.data)
    
    def print_config(self):
        print("╔══════════════════════════════════════════════════╗")
        print("║    CL7206C2 RFID Reader Configuration           ║")
        print("╠══════════════════════════════════════════════════╣")
        dhcp_modes = {0: "OFF (Static)", 1: "ON (DHCP)", 2: "Static (mode 2)"}
        dhcp_str = dhcp_modes.get(self.dhcp_mode, f"Unknown ({self.dhcp_mode})")
        print(f"║  DHCP:           {dhcp_str:<30s}║")
        print(f"║  IP Address:     {self.ip:<30s}║")
        print(f"║  Subnet Mask:    {self.mask:<30s}║")
        print(f"║  Gateway:        {self.gateway:<30s}║")
        print(f"║  Device MAC/ID:  {self.device_mac:<30s}║")
        print(f"║  Local Port:     {self.local_port:<30d}║")
        print(f"║  Server IP:      {self.server_ip:<30s}║")
        print(f"║  Server Port:    {self.server_port:<30d}║")
        print("╠══════════════════════════════════════════════════╣")
        
        for i in range(4):
            ant = self.get_antenna(i)
            print(f"║  Antenna {i}:                                      ║")
            print(f"║    Power:        {ant['power']:<30d}║")
            print(f"║    Protocol:     {ant['protocol_name']:<30s}║")
            print(f"║    Frequency:    {ant['freq_name']:<30s}║")
            print(f"║    Session:      {ant['session_name']:<30s}║")
            print(f"║    Target:       {ant['target_name']:<30s}║")
            print(f"║    Q Value:      {ant['q_value']:<30d}║")
        
        print("╠══════════════════════════════════════════════════╣")
        print(f"║  Wiegand:        {'ON' if self.wiegand_enabled else 'OFF':<30s}║")
        print(f"║  Wiegand Format: {self.wiegand_format:<30d}║")
        print(f"║  Wiegand Bits:   {self.wiegand_bits:<30d}║")
        print(f"║  Buzzer:         {'ON' if self.buzzer_enabled else 'OFF':<30s}║")
        print(f"║  Tag Filter:     {'ON' if self.tag_filter else 'OFF':<30s}║")
        print(f"║  Auto-Read:      {'ON' if self.auto_read else 'OFF':<30s}║")
        print(f"║  Host Server IP: {self.host_server_ip:<30s}║")
        print("╚══════════════════════════════════════════════════╝")


# ═══════════════════════════════════════════════════════════
# UDP DISCOVERY
# ═══════════════════════════════════════════════════════════

def discover_readers(timeout=3, port=9090):
    """Send UDP broadcast to find CL7206C readers on network"""
    print(f"[*] Searching for CLOU RFID readers on port {port}...")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(timeout)
    
    # The reader listens on UDP and responds to broadcasts
    # Try common discovery packets
    discovery_packets = [
        b'\xff\xff\xff\xff',  # Generic broadcast probe
        b'^RFID_READER_INFORMATION',  # Echo request
        b'\x00',  # Null probe
    ]
    
    readers = []
    for packet in discovery_packets:
        try:
            sock.sendto(packet, ('255.255.255.255', port))
            print(f"  Sent {len(packet)} bytes to broadcast:{port}")
        except Exception as e:
            print(f"  Error: {e}")
    
    print(f"[*] Waiting {timeout}s for responses...")
    start = time.time()
    while time.time() - start < timeout:
        try:
            data, addr = sock.recvfrom(4096)
            print(f"  [+] Response from {addr[0]}:{addr[1]}: {data[:100]}")
            readers.append((addr, data))
        except socket.timeout:
            break
    
    sock.close()
    
    if not readers:
        print("  No readers found. Try:")
        print("  - Ensure reader is on same subnet")
        print("  - Check firewall allows UDP broadcast")
        print("  - Try port 9092 instead of 9090")
    
    return readers


def get_reader_info(ip, port=9090, timeout=3):
    """Query a specific reader for its network parameters"""
    print(f"[*] Querying reader at {ip}:{port}...")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    
    # Try various query packets
    queries = [
        b'\xff\xff\xff\xff',
        b'^RFID_READER_INFORMATION',
        b'\x00',
    ]
    
    for q in queries:
        try:
            sock.sendto(q, (ip, port))
            data, addr = sock.recvfrom(4096)
            print(f"  Response: {data}")
            
            # Try to parse key-value response
            text = data.decode('ascii', errors='ignore')
            if 'IP:' in text or 'MAC:' in text:
                print("\n  Parsed fields:")
                for field in text.split(','):
                    if ':' in field:
                        print(f"    {field.strip()}")
            return data
        except socket.timeout:
            continue
        except Exception as e:
            print(f"  Error: {e}")
    
    print("  No response received.")
    sock.close()
    return None


# ═══════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════

def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    
    cmd = sys.argv[1].lower()
    
    if cmd == 'discover':
        port = int(sys.argv[2]) if len(sys.argv) > 2 else 9090
        discover_readers(port=port)
    
    elif cmd == 'info':
        if len(sys.argv) < 3:
            print("Usage: cl7206c2_tool.py info <ip> [port]")
            sys.exit(1)
        ip = sys.argv[2]
        port = int(sys.argv[3]) if len(sys.argv) > 3 else 9090
        get_reader_info(ip, port)
    
    elif cmd == 'dump-config':
        if len(sys.argv) < 3:
            print("Usage: cl7206c2_tool.py dump-config <config_pram_file>")
            sys.exit(1)
        cfg = ConfigPram(filename=sys.argv[2])
        cfg.print_config()
    
    elif cmd == 'edit-config':
        if len(sys.argv) < 3:
            print("Usage: cl7206c2_tool.py edit-config <config_pram_file>")
            sys.exit(1)
        filename = sys.argv[2]
        cfg = ConfigPram(filename=filename)
        cfg.print_config()
        
        print("\nEnter new values (press Enter to keep current):")
        new_ip = input(f"  IP [{cfg.ip}]: ").strip()
        if new_ip: cfg.set_ip(new_ip)
        
        new_mask = input(f"  Mask [{cfg.mask}]: ").strip()
        if new_mask: cfg.set_mask(new_mask)
        
        new_gw = input(f"  Gateway [{cfg.gateway}]: ").strip()
        if new_gw: cfg.set_gateway(new_gw)
        
        for i in range(4):
            ant = cfg.get_antenna(i)
            new_pwr = input(f"  Antenna {i} Power [{ant['power']}]: ").strip()
            if new_pwr: cfg.set_antenna_power(i, int(new_pwr))
        
        out = filename + '.new'
        cfg.save(out)
        print(f"\nSaved modified config to: {out}")
        print(f"Upload to reader: tftp -p -l {out} -r config_pram <reader_ip>")
    
    else:
        print(f"Unknown command: {cmd}")
        print(__doc__)


if __name__ == '__main__':
    main()
