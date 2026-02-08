#!/usr/bin/env python3
"""
CL7206C2 RFID Reader — Protocol Client
=======================================
Complete client based on reverse engineering of protocol_cmd_hdl()

Usage:
  python3 cl7206c2_client.py <reader_ip> [port] <command> [args]

Commands:
  info            Get reader information
  network         Get IP/Mask/Gateway
  mac             Get MAC address
  time            Get system time
  settime <ts>    Set system time (unix timestamp, or 'now')
  gpi             Read GPI input levels
  gpo <n> <0|1>   Set GPO output
  relay           Get relay config
  rs485           Get RS485 config
  tagcache        Get tag cache status
  tagtime         Get tag cache time
  tags            Get stored tag records
  cleartags       Clear tag database
  ping            Get ping/gateway config
  dhcp <0|1>      Set DHCP mode (0=static, 1=DHCP)
  reboot          Reboot reader
  reset           Factory reset (DANGEROUS!)
  inventory       Start continuous inventory (Ctrl+C to stop)
  monitor         Listen for tag notifications

Example:
  python3 cl7206c2_client.py 192.168.1.116 info
  python3 cl7206c2_client.py 192.168.1.116 9090 inventory
  python3 cl7206c2_client.py 192.168.1.116 settime now
"""

import socket
import struct
import sys
import time
import datetime
import select

# ═══════════════════════════════════════════════════════════
# CRC16 IMPLEMENTATION
# ═══════════════════════════════════════════════════════════

def _generate_crc16_table(poly=0x8005):
    """Generate CRC16 lookup table — VERIFIED poly 0x8005 from firmware CRCtable"""
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

_CRC16_TABLE = _generate_crc16_table(0x8005)

def crc16(data, init=0x0000):
    """CRC-16/BUYPASS (poly 0x8005, init 0x0000, non-reflected)
    VERIFIED against firmware CRCtable at 0x00020fe4:
      table[0]=0x0000, table[1]=0x8005, table[2]=0x800F, table[3]=0x000A ✓
    """
    crc = init
    for byte in data:
        crc = ((crc << 8) & 0xFFFF) ^ _CRC16_TABLE[((crc >> 8) ^ byte) & 0xFF]
    return crc


# ═══════════════════════════════════════════════════════════
# PACKET BUILDER / PARSER
# ═══════════════════════════════════════════════════════════

HEADER = 0xAA


def build_packet(cmd, sub, data=b''):
    """Build a complete protocol packet
    
    Frame: [0xAA] [CMD] [SUB] [LEN_Hi] [LEN_Lo] [Data...] [CRC16_Hi] [CRC16_Lo]
    CRC covers: CMD + SUB + LEN + DATA  (0xAA sync byte EXCLUDED from CRC)
    """
    data_len = len(data)
    len_hi = (data_len >> 8) & 0xFF
    len_lo = data_len & 0xFF
    
    # CRC covers CMD + SUB + LEN + DATA (not the 0xAA header!)
    crc_payload = bytes([cmd, sub, len_hi, len_lo]) + data
    crc = crc16(crc_payload)
    
    packet = bytes([HEADER]) + crc_payload + struct.pack('>H', crc)
    return packet


def parse_packet(data):
    """Parse a received packet, returns (cmd, sub, payload) or None"""
    if len(data) < 7:  # Minimum: header + cmd + sub + len(2) + crc(2)
        return None
    
    if data[0] != HEADER:
        # Search for header in received data
        idx = data.find(bytes([HEADER]))
        if idx < 0:
            return None
        data = data[idx:]
        if len(data) < 7:
            return None
    
    cmd = data[1]
    sub = data[2]
    data_len = (data[3] << 8) | data[4]
    
    expected_total = 5 + data_len + 2  # header+cmd+sub+len(2) + data + crc(2)
    if len(data) < expected_total:
        return None
    
    payload = data[5:5+data_len]
    
    # CRC covers bytes [1] through [4+data_len] — excludes 0xAA header and CRC itself
    received_crc = (data[5+data_len] << 8) | data[5+data_len+1]
    calc_crc = crc16(data[1:5+data_len])
    
    if received_crc != calc_crc:
        # Try with init=0xFFFF (CRC-16/CCITT-FALSE) as fallback
        alt_crc = crc16(data[1:5+data_len], init=0xFFFF)
        if received_crc == alt_crc:
            print(f"[*] Note: CRC uses init=0xFFFF, not 0x0000")
        else:
            # Also try CRC over full packet including 0xAA
            full_crc = crc16(data[0:5+data_len])
            if received_crc == full_crc:
                print(f"[*] Note: CRC includes 0xAA header")
            else:
                print(f"[!] CRC mismatch: got 0x{received_crc:04X}, "
                      f"calc 0x{calc_crc:04X} (init=0), 0x{alt_crc:04X} (init=FFFF)")
    
    return (cmd, sub, payload)


def verify_packet(data):
    """Quick verify CRC of a packet"""
    if len(data) < 7 or data[0] != HEADER:
        return False
    data_len = (data[3] << 8) | data[4]
    if len(data) < 5 + data_len + 2:
        return False
    received_crc = (data[5+data_len] << 8) | data[5+data_len+1]
    calc_crc = crc16(data[1:5+data_len])
    return received_crc == calc_crc


def hex_dump(data, prefix="  "):
    """Pretty hex dump of bytes"""
    hex_str = ' '.join(f'{b:02X}' for b in data)
    ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data)
    return f"{prefix}{hex_str}  |{ascii_str}|"


# ═══════════════════════════════════════════════════════════
# READER CLIENT
# ═══════════════════════════════════════════════════════════

class CL7206C2Client:
    """Client for CL7206C2 RFID Reader"""
    
    def __init__(self, ip, port=9090, timeout=3, use_tcp=True):
        self.ip = ip
        self.port = port
        self.timeout = timeout
        self.use_tcp = use_tcp
        self.sock = None
    
    def connect(self):
        """Establish connection to reader"""
        if self.use_tcp:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(self.timeout)
            try:
                self.sock.connect((self.ip, self.port))
                print(f"[+] TCP connected to {self.ip}:{self.port}")
            except (socket.timeout, ConnectionRefusedError):
                print(f"[!] TCP connection failed, trying UDP...")
                self.use_tcp = False
                self.sock.close()
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self.sock.settimeout(self.timeout)
                print(f"[+] UDP mode to {self.ip}:{self.port}")
        else:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.settimeout(self.timeout)
            print(f"[+] UDP mode to {self.ip}:{self.port}")
    
    def close(self):
        if self.sock:
            self.sock.close()
    
    def send(self, packet):
        """Send raw packet"""
        print(f"[TX] {' '.join(f'{b:02X}' for b in packet)}")
        if self.use_tcp:
            self.sock.sendall(packet)
        else:
            self.sock.sendto(packet, (self.ip, self.port))
    
    def recv(self, bufsize=4096):
        """Receive data"""
        try:
            if self.use_tcp:
                data = self.sock.recv(bufsize)
            else:
                data, _ = self.sock.recvfrom(bufsize)
            if data:
                print(f"[RX] {' '.join(f'{b:02X}' for b in data)}")
            return data
        except socket.timeout:
            print("[!] Receive timeout")
            return None
    
    def send_command(self, cmd, sub, data=b''):
        """Send command and receive response"""
        packet = build_packet(cmd, sub, data)
        self.send(packet)
        response = self.recv()
        if response:
            return parse_packet(response)
        return None
    
    # ─── High-level commands ───
    
    def get_reader_info(self):
        """CMD=0x01, SUB=0x00: Get reader information"""
        result = self.send_command(0x01, 0x00)
        if result:
            cmd, sub, payload = result
            print(f"\n=== Reader Information ===")
            if len(payload) >= 4:
                print(f"  Reader Info:  {payload[:4].hex()}")
            if len(payload) >= 6:
                name_offset = 6  # After reader_info(4) + 0x00 + 0x10
                if len(payload) > name_offset + 16:
                    name = payload[name_offset:name_offset+16]
                    print(f"  Reader Name:  {name.decode('ascii', errors='replace').rstrip(chr(0))}")
                if len(payload) > name_offset + 16 + 4:
                    uptime_bytes = payload[name_offset+16:name_offset+20]
                    uptime = struct.unpack('>I', uptime_bytes)[0]
                    print(f"  Uptime:       {uptime}s ({uptime//3600}h {(uptime%3600)//60}m)")
            print(f"  Raw payload:  {payload.hex()}")
        return result
    
    def get_network(self):
        """CMD=0x01, SUB=0x05: Get IP/Mask/Gateway"""
        result = self.send_command(0x01, 0x05)
        if result:
            cmd, sub, payload = result
            print(f"\n=== Network Configuration ===")
            if len(payload) >= 12:
                ip = '.'.join(str(b) for b in payload[0:4])
                mask = '.'.join(str(b) for b in payload[4:8])
                gw = '.'.join(str(b) for b in payload[8:12])
                print(f"  IP Address:   {ip}")
                print(f"  Subnet Mask:  {mask}")
                print(f"  Gateway:      {gw}")
            else:
                print(f"  Raw: {payload.hex()}")
        return result
    
    def get_mac(self):
        """CMD=0x01, SUB=0x06: Get MAC address"""
        result = self.send_command(0x01, 0x06)
        if result:
            cmd, sub, payload = result
            print(f"\n=== MAC Address ===")
            if len(payload) >= 6:
                mac = ':'.join(f'{b:02X}' for b in payload[:6])
                print(f"  MAC: {mac}")
            else:
                print(f"  Raw: {payload.hex()}")
        return result
    
    def get_time(self):
        """CMD=0x01, SUB=0x11: Get system time"""
        result = self.send_command(0x01, 0x11)
        if result:
            cmd, sub, payload = result
            print(f"\n=== System Time ===")
            if len(payload) >= 4:
                ts = struct.unpack('>I', payload[0:4])[0]
                dt = datetime.datetime.fromtimestamp(ts)
                print(f"  Unix timestamp: {ts}")
                print(f"  Date/Time:      {dt.strftime('%Y-%m-%d %H:%M:%S')}")
                if len(payload) >= 8:
                    us = struct.unpack('>I', payload[4:8])[0]
                    print(f"  Microseconds:   {us}")
        return result
    
    def set_time(self, timestamp=None):
        """CMD=0x01, SUB=0x10: Set system time"""
        if timestamp is None:
            timestamp = int(time.time())
        data = struct.pack('>I', timestamp)
        result = self.send_command(0x01, 0x10, data)
        if result:
            cmd, sub, payload = result
            status = payload[0] if payload else -1
            dt = datetime.datetime.fromtimestamp(timestamp)
            print(f"\n=== Set Time ===")
            print(f"  Set to: {dt.strftime('%Y-%m-%d %H:%M:%S')} (ts={timestamp})")
            print(f"  Status: {'OK' if status == 0 else f'Error ({status})'}")
        return result
    
    def get_gpi(self):
        """CMD=0x01, SUB=0x0A: Get GPI input levels"""
        result = self.send_command(0x01, 0x0A)
        if result:
            cmd, sub, payload = result
            print(f"\n=== GPI Inputs ===")
            # Format: [count] [id1][level1] [id2][level2] ...
            i = 0
            while i + 1 < len(payload):
                pin_id = payload[i]
                level = payload[i+1] if i+1 < len(payload) else '?'
                print(f"  GPI {pin_id}: {'HIGH' if level else 'LOW'} ({level})")
                i += 2
        return result
    
    def set_gpo(self, data_bytes):
        """CMD=0x01, SUB=0x09: Set GPO output"""
        result = self.send_command(0x01, 0x09, data_bytes)
        if result:
            cmd, sub, payload = result
            status = payload[0] if payload else -1
            print(f"  GPO Status: {'OK' if status == 0 else f'Error ({status})'}")
        return result
    
    def get_relay(self):
        """CMD=0x01, SUB=0x24: Get relay configuration"""
        result = self.send_command(0x01, 0x24)
        if result:
            cmd, sub, payload = result
            print(f"\n=== Relay Config ===")
            if len(payload) >= 3:
                relay_num = payload[0]
                relay_time = (payload[1] << 8) | payload[2]
                print(f"  Relay number: {relay_num}")
                print(f"  On-time:      {relay_time} ms")
        return result
    
    def get_rs485(self):
        """CMD=0x01, SUB=0x16: Get RS485 configuration"""
        result = self.send_command(0x01, 0x16)
        if result:
            cmd, sub, payload = result
            print(f"\n=== RS485 Config ===")
            if len(payload) >= 2:
                print(f"  Address: {payload[0]}")
                print(f"  COM Mode: {payload[1]}")
        return result
    
    def get_tag_cache(self):
        """CMD=0x01, SUB=0x18: Get tag cache switch"""
        result = self.send_command(0x01, 0x18)
        if result:
            cmd, sub, payload = result
            print(f"\n=== Tag Cache ===")
            if payload:
                print(f"  Cache: {'ON' if payload[0] else 'OFF'}")
        return result
    
    def get_tag_cache_time(self):
        """CMD=0x01, SUB=0x1A: Get tag cache time"""
        result = self.send_command(0x01, 0x1A)
        if result:
            cmd, sub, payload = result
            print(f"\n=== Tag Cache Time ===")
            if len(payload) >= 2:
                cache_time = (payload[0] << 8) | payload[1]
                print(f"  Cache time: {cache_time}")
        return result
    
    def get_tags(self):
        """CMD=0x01, SUB=0x1B: Get stored tag records"""
        print("\n=== Requesting Tag Records ===")
        packet = build_packet(0x01, 0x1B)
        self.send(packet)
        
        # May receive multiple response packets
        tag_count = 0
        start = time.time()
        while time.time() - start < 5:
            try:
                data = self.recv()
                if not data:
                    break
                result = parse_packet(data)
                if result:
                    cmd, sub, payload = result
                    tag_count += 1
                    print(f"  Tag {tag_count}: {payload.hex()}")
            except socket.timeout:
                break
        
        if tag_count == 0:
            print("  No tags stored")
        else:
            print(f"  Total: {tag_count} tag record(s)")
    
    def clear_tags(self):
        """CMD=0x01, SUB=0x1C: Clear all tag records"""
        result = self.send_command(0x01, 0x1C)
        if result:
            cmd, sub, payload = result
            status = payload[0] if payload else -1
            print(f"\n=== Clear Tags ===")
            print(f"  Status: {'OK — all tags cleared' if status == 0 else f'Error ({status})'}")
        return result
    
    def get_ping_config(self):
        """CMD=0x01, SUB=0x2E: Get ping/gateway config"""
        result = self.send_command(0x01, 0x2E)
        if result:
            cmd, sub, payload = result
            print(f"\n=== Ping Config ===")
            if payload:
                print(f"  Ping Switch: {'ON' if payload[0] else 'OFF'}")
                if len(payload) >= 6 and payload[0] == 1:
                    # IP is stored in little-endian in this response
                    ip = '.'.join(str(b) for b in payload[2:6])
                    print(f"  Ping Target: {ip}")
        return result
    
    def set_dhcp(self, mode):
        """CMD=0x01, SUB=0x2F: Set DHCP mode"""
        result = self.send_command(0x01, 0x2F, bytes([mode]))
        if result:
            print(f"\n=== DHCP Mode ===")
            print(f"  Set to: {'DHCP' if mode else 'Static'}")
        return result
    
    def reboot(self):
        """CMD=0x01, SUB=0x0F: Reboot reader"""
        print("\n=== REBOOTING READER ===")
        packet = build_packet(0x01, 0x0F)
        self.send(packet)
        print("  Reboot command sent. Reader will restart in ~5s.")
    
    def factory_reset(self):
        """CMD=0x01, SUB=0x14: Factory reset"""
        print("\n=== FACTORY RESET ===")
        confirm = input("  Type 'YES' to confirm factory reset: ")
        if confirm != 'YES':
            print("  Cancelled.")
            return
        result = self.send_command(0x01, 0x14)
        if result:
            cmd, sub, payload = result
            status = payload[0] if payload else -1
            print(f"  Status: {'OK — reset complete' if status == 0 else f'Error ({status})'}")
    
    def start_inventory(self):
        """Start continuous EPC inventory and display tags"""
        print("\n=== Starting Inventory (Ctrl+C to stop) ===\n")
        
        # CMD=0x02, SUB=0x10: Start inventory
        # RF passthrough — try basic start command
        start_pkt = build_packet(0x02, 0x10)
        self.send(start_pkt)
        
        tag_count = 0
        try:
            while True:
                try:
                    data = self.recv()
                    if not data:
                        continue
                    
                    # Parse all packets in received data
                    offset = 0
                    while offset < len(data):
                        idx = data.find(bytes([HEADER]), offset)
                        if idx < 0:
                            break
                        
                        result = parse_packet(data[idx:])
                        if result:
                            cmd, sub, payload = result
                            
                            # Tag notification: CMD=0x12
                            if cmd == 0x12 and sub in (0x00, 0x20, 0x30):
                                tag_count += 1
                                epc_hex = payload.hex().upper()
                                tag_type = {0x00: 'EPC', 0x20: 'EPC+', 0x30: 'EPC+TID'}.get(sub, '???')
                                ts = datetime.datetime.now().strftime('%H:%M:%S.%f')[:-3]
                                print(f"  [{ts}] Tag #{tag_count} ({tag_type}): {epc_hex}")
                            else:
                                print(f"  [Response CMD={cmd:02X} SUB={sub:02X}] {payload.hex()}")
                        
                        offset = idx + 7  # Minimum packet size, move forward
                
                except socket.timeout:
                    pass  # Normal during inventory, keep waiting
        
        except KeyboardInterrupt:
            print(f"\n\n  Stopping inventory...")
            # CMD=0x02, SUB=0xFF: Stop inventory
            stop_pkt = build_packet(0x02, 0xFF)
            self.send(stop_pkt)
            time.sleep(0.3)
            # Try to receive stop confirmation
            try:
                self.recv()
            except:
                pass
            print(f"  Total tags read: {tag_count}")
    
    def monitor(self):
        """Passive monitoring — just listen for any packets"""
        print("\n=== Monitoring (Ctrl+C to stop) ===\n")
        self.sock.settimeout(1.0)
        
        try:
            while True:
                try:
                    data = self.recv()
                    if data:
                        result = parse_packet(data)
                        if result:
                            cmd, sub, payload = result
                            ts = datetime.datetime.now().strftime('%H:%M:%S.%f')[:-3]
                            print(f"  [{ts}] CMD=0x{cmd:02X} SUB=0x{sub:02X} "
                                  f"LEN={len(payload)} DATA={payload.hex()}")
                except socket.timeout:
                    pass
        except KeyboardInterrupt:
            print("\n  Monitoring stopped.")


# ═══════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════

def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)
    
    ip = sys.argv[1]
    
    # Check if second arg is port number or command
    try:
        port = int(sys.argv[2])
        cmd_idx = 3
    except ValueError:
        port = 9090
        cmd_idx = 2
    
    if cmd_idx >= len(sys.argv):
        print("Error: No command specified")
        print(__doc__)
        sys.exit(1)
    
    command = sys.argv[cmd_idx].lower()
    args = sys.argv[cmd_idx+1:]
    
    client = CL7206C2Client(ip, port)
    
    try:
        client.connect()
        
        if command == 'info':
            client.get_reader_info()
        elif command == 'network':
            client.get_network()
        elif command == 'mac':
            client.get_mac()
        elif command == 'time':
            client.get_time()
        elif command == 'settime':
            if args and args[0].lower() == 'now':
                client.set_time()
            elif args:
                client.set_time(int(args[0]))
            else:
                client.set_time()
        elif command == 'gpi':
            client.get_gpi()
        elif command == 'gpo':
            if len(args) >= 2:
                client.set_gpo(bytes([int(args[0]), int(args[1])]))
            else:
                print("Usage: gpo <pin> <0|1>")
        elif command == 'relay':
            client.get_relay()
        elif command == 'rs485':
            client.get_rs485()
        elif command == 'tagcache':
            client.get_tag_cache()
        elif command == 'tagtime':
            client.get_tag_cache_time()
        elif command == 'tags':
            client.get_tags()
        elif command == 'cleartags':
            client.clear_tags()
        elif command == 'ping':
            client.get_ping_config()
        elif command == 'dhcp':
            if args:
                client.set_dhcp(int(args[0]))
            else:
                print("Usage: dhcp <0|1>")
        elif command == 'reboot':
            client.reboot()
        elif command == 'reset':
            client.factory_reset()
        elif command == 'inventory':
            client.start_inventory()
        elif command == 'monitor':
            client.monitor()
        elif command == 'raw':
            # Send raw hex bytes
            if args:
                raw = bytes.fromhex(''.join(args))
                client.send(raw)
                resp = client.recv()
                if resp:
                    parse_packet(resp)
        else:
            print(f"Unknown command: {command}")
            print(__doc__)
    
    except KeyboardInterrupt:
        print("\n[*] Interrupted")
    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        client.close()


if __name__ == '__main__':
    main()
