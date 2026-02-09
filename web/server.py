"""
CL7206C2 RFID Reader — Web Test Tool Backend
=============================================
Thin FastAPI server bridging browser ↔ reader via TCP/9090.

Usage:
    pip install fastapi uvicorn
    cd cl7206c2-rfid/web
    uvicorn server:app --host 0.0.0.0 --port 8080

Then open http://localhost:8080 in browser.
"""

import sys
import os
import json
import asyncio
import time
import struct
import threading
import logging
from pathlib import Path
from datetime import datetime
from contextlib import asynccontextmanager
from collections import deque

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional

# Add tools/ to path so we can import the client
sys.path.insert(0, str(Path(__file__).parent.parent / "tools"))
from cl7206c2_client import CL7206C2Client, parse_packet

# ─── Logging Setup ────────────────────────────────────────────────────────────

LOG_DIR = Path(__file__).parent / "logs"
LOG_DIR.mkdir(exist_ok=True)

# Ring buffer for serving logs to frontend
log_ring: deque = deque(maxlen=2000)

class RingHandler(logging.Handler):
    """Push log records to in-memory ring buffer for frontend consumption."""
    def emit(self, record):
        entry = {
            "ts": datetime.fromtimestamp(record.created).strftime("%H:%M:%S.%f")[:-3],
            "level": record.levelname,
            "msg": record.getMessage(),
            "cat": getattr(record, 'cat', 'SYS'),  # category: SYS, PROTO, CMD, TAG
        }
        log_ring.append(entry)

# Configure root logger
log = logging.getLogger("rfid")
log.setLevel(logging.DEBUG)

# File handler — all logs
fh_all = logging.FileHandler(LOG_DIR / "all.log", encoding="utf-8")
fh_all.setLevel(logging.DEBUG)
fh_all.setFormatter(logging.Formatter("%(asctime)s [%(levelname)-5s] [%(cat)-5s] %(message)s",
                                       datefmt="%Y-%m-%d %H:%M:%S"))

# File handler — warnings and errors only
fh_warn = logging.FileHandler(LOG_DIR / "warnings.log", encoding="utf-8")
fh_warn.setLevel(logging.WARNING)
fh_warn.setFormatter(logging.Formatter("%(asctime)s [%(levelname)-5s] [%(cat)-5s] %(message)s",
                                        datefmt="%Y-%m-%d %H:%M:%S"))

# Ring buffer handler (for frontend)
rh = RingHandler()
rh.setLevel(logging.DEBUG)

# Console handler
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
ch.setFormatter(logging.Formatter("[%(levelname)-5s] %(message)s"))

log.addHandler(fh_all)
log.addHandler(fh_warn)
log.addHandler(rh)
log.addHandler(ch)

def logm(level, msg, cat="SYS"):
    """Log with category."""
    log.log(level, msg, extra={"cat": cat})

def log_info(msg, cat="SYS"):    logm(logging.INFO, msg, cat)
def log_warn(msg, cat="SYS"):    logm(logging.WARNING, msg, cat)
def log_error(msg, cat="SYS"):   logm(logging.ERROR, msg, cat)
def log_debug(msg, cat="SYS"):   logm(logging.DEBUG, msg, cat)
def log_proto(msg):               logm(logging.DEBUG, msg, "PROTO")
def log_cmd(msg):                 logm(logging.INFO, msg, "CMD")
def log_tag(msg):                 logm(logging.INFO, msg, "TAG")

# ─── Global State ─────────────────────────────────────────────────────────────

reader: Optional[CL7206C2Client] = None
reader_lock = threading.Lock()
inventory_active = False
inventory_ws_clients: list[WebSocket] = []


# ─── Pydantic Models ──────────────────────────────────────────────────────────

class ConnectRequest(BaseModel):
    ip: str
    port: int = 9090

class SetTimeRequest(BaseModel):
    timestamp: Optional[int] = None  # None = use current PC time

class SetPowerRequest(BaseModel):
    port: int
    power_dbm: int

class SetAntennaRequest(BaseModel):
    port: int
    power: int
    session: int = 2
    target: int = 0
    q_value: int = 4

class SetTriggerRequest(BaseModel):
    gpi_pin: int
    start_mode: int
    stop_mode: int
    delay_10ms: int = 0

class SetRelayRequest(BaseModel):
    relay_num: int
    on_time_ms: int

class SetIPRequest(BaseModel):
    ip: str
    mask: str
    gateway: str

class SetMACRequest(BaseModel):
    mac: str

class SetTagCacheRequest(BaseModel):
    enable: int

class SetTagCacheTimeRequest(BaseModel):
    cache_time: int

class SetDHCPRequest(BaseModel):
    enable: int  # 1=DHCP on, 0=static


# ─── App Setup ────────────────────────────────────────────────────────────────

app = FastAPI(title="CL7206C2 RFID Test Tool", version="1.0.0")

# Serve static files (index.html)
static_dir = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


@app.get("/")
async def index():
    return FileResponse(str(static_dir / "index.html"))


# ─── Helper ───────────────────────────────────────────────────────────────────

def require_reader():
    """Raise 400 if not connected."""
    if reader is None:
        raise HTTPException(status_code=400, detail="Not connected to reader")
    return reader


def sanitize(obj):
    """Recursively convert bytes to hex strings and tuples to lists for JSON serialization."""
    if isinstance(obj, bytes):
        return obj.hex()
    if isinstance(obj, dict):
        return {k: sanitize(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [sanitize(v) for v in obj]
    return obj


def parse_result(result, label=""):
    """Convert (cmd, sub, payload) tuple to a JSON-safe dict."""
    if result is None:
        if label:
            log_warn(f"{label}: no response from reader", "CMD")
        raise HTTPException(status_code=504, detail="No response from reader")
    if isinstance(result, dict):
        return sanitize(result)
    if isinstance(result, (tuple, list)) and len(result) == 3:
        cmd, sub, payload = result
        response = {
            "cmd": f"0x{cmd:02X}" if isinstance(cmd, int) else str(cmd),
            "sub": f"0x{sub:02X}" if isinstance(sub, int) else str(sub),
            "payload_hex": payload.hex() if isinstance(payload, bytes) else str(payload),
            "payload_len": len(payload) if isinstance(payload, bytes) else 0,
        }
        # Add human-readable parsing for known commands
        if isinstance(payload, bytes):
            _enrich_response(cmd, sub, payload, response)
        if label:
            log_cmd(f"{label}: OK ({response.get('payload_len', 0)} bytes)")
            log_proto(f"{label}: {response.get('payload_hex', '')}")
        return response
    return sanitize(result)


def _enrich_response(cmd, sub, p, r):
    """Add human-readable fields for known command responses."""
    try:
        # Network config: CMD=0x01, SUB=0x05
        if cmd == 0x01 and sub == 0x05 and len(p) >= 12:
            r["ip"] = '.'.join(str(b) for b in p[0:4])
            r["mask"] = '.'.join(str(b) for b in p[4:8])
            r["gateway"] = '.'.join(str(b) for b in p[8:12])

        # MAC: CMD=0x01, SUB=0x06
        elif cmd == 0x01 and sub == 0x06 and len(p) >= 6:
            r["mac"] = ':'.join(f'{b:02X}' for b in p[:6])

        # Reader info: CMD=0x01, SUB=0x00
        elif cmd == 0x01 and sub == 0x00 and len(p) >= 6:
            r["reader_info"] = p[0:4].hex()
            name_len = (p[4] << 8) | p[5]
            if len(p) >= 6 + name_len:
                r["reader_name"] = p[6:6+name_len].decode('ascii', errors='replace')

        # Time: CMD=0x01, SUB=0x11
        elif cmd == 0x01 and sub == 0x11 and len(p) >= 4:
            ts = struct.unpack('>I', p[0:4])[0]
            r["seconds"] = ts
            r["reader_time_str"] = datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
            if len(p) >= 8:
                r["microseconds"] = struct.unpack('>I', p[4:8])[0]

        # GPI: CMD=0x01, SUB=0x0A
        elif cmd == 0x01 and sub == 0x0A:
            gpis = {}
            i = 0
            while i + 1 < len(p):
                gpis[f"gpi_{p[i]}"] = "HIGH" if p[i+1] else "LOW"
                i += 2
            r["inputs"] = gpis

        # Antenna config: CMD=0x01, SUB=0x0C
        elif cmd == 0x01 and sub == 0x0C and len(p) >= 12:
            sessions = {0: "S0", 1: "S1", 2: "S2", 3: "S3"}
            targets = {0: "A", 1: "B"}
            r["antenna_index"] = p[0]
            r["power_dbm"] = p[3]
            r["protocol"] = f"0x{p[4]:02X}"
            r["frequency"] = f"0x{p[5]:02X}"
            r["session"] = sessions.get(p[7], str(p[7]))
            r["target"] = targets.get(p[8], str(p[8]))
            r["q_value"] = p[9]

        # Wiegand: CMD=0x01, SUB=0x16
        elif cmd == 0x01 and sub == 0x16 and len(p) >= 3:
            r["wiegand_enable"] = p[0]
            r["wiegand_format"] = {0: "Wiegand-26", 1: "Wiegand-34", 2: "Wiegand-66"}.get(p[1], str(p[1]))
            r["wiegand_bits"] = p[2]

        # Server mode: CMD=0x01, SUB=0x07
        elif cmd == 0x01 and sub == 0x07 and len(p) >= 1:
            r["mode"] = "SERVER" if p[0] == 0 else "CLIENT"

        # Tag cache: CMD=0x01, SUB=0x17
        elif cmd == 0x01 and sub == 0x17 and len(p) >= 1:
            r["cache_enabled"] = bool(p[0])

        # Tag cache time: CMD=0x01, SUB=0x19
        elif cmd == 0x01 and sub == 0x19 and len(p) >= 1:
            r["cache_time"] = p[0]

        # Relay: CMD=0x01, SUB=0x08
        elif cmd == 0x01 and sub == 0x08:
            relays = {}
            i = 0
            while i + 1 < len(p):
                relays[f"relay_{p[i]}"] = "ON" if p[i+1] else "OFF"
                i += 2
            r["relays"] = relays

        # RS485: CMD=0x01, SUB=0x0E
        elif cmd == 0x01 and sub == 0x0E and len(p) >= 2:
            r["rs485_addr"] = p[0]
            r["rs485_mode"] = p[1]

    except Exception:
        pass  # Parsing failed, raw payload_hex is still available


# ─── Connection ───────────────────────────────────────────────────────────────

@app.post("/api/connect")
async def connect(req: ConnectRequest):
    global reader
    with reader_lock:
        if reader is not None:
            try:
                reader.close()
            except:
                pass
        try:
            log_info(f"Connecting to {req.ip}:{req.port}...")
            reader = CL7206C2Client(req.ip, req.port)
            reader.connect()
            log_info(f"Connected to {req.ip}:{req.port}", "CMD")
            return {"status": "connected", "ip": req.ip, "port": req.port}
        except Exception as e:
            reader = None
            log_error(f"Connection failed: {e}")
            raise HTTPException(status_code=502, detail=f"Connection failed: {e}")


@app.post("/api/disconnect")
async def disconnect():
    global reader, inventory_active
    inventory_active = False
    with reader_lock:
        if reader:
            try:
                reader.close()
            except:
                pass
            reader = None
    log_info("Disconnected", "CMD")
    return {"status": "disconnected"}


@app.get("/api/status")
async def status():
    return {
        "connected": reader is not None,
        "inventory_active": inventory_active,
        "ws_clients": len(inventory_ws_clients),
    }


@app.get("/api/logs")
async def get_logs(after: int = 0, cat: str = "", level: str = ""):
    """Get log entries from ring buffer. Filters: after=index, cat=SYS|CMD|PROTO|TAG, level=DEBUG|INFO|WARNING|ERROR"""
    entries = list(log_ring)
    if after > 0:
        entries = entries[after:]
    if cat:
        cats = cat.upper().split(",")
        entries = [e for e in entries if e["cat"] in cats]
    if level:
        levels = level.upper().split(",")
        entries = [e for e in entries if e["level"] in levels]
    return {"logs": entries, "total": len(log_ring)}


# ─── GET Commands ─────────────────────────────────────────────────────────────

@app.get("/api/info")
async def get_info():
    r = require_reader()
    with reader_lock:
        result = r.get_reader_info()
    return parse_result(result, "get_info")


@app.get("/api/network")
async def get_network():
    r = require_reader()
    with reader_lock:
        result = r.get_network()
    return parse_result(result, "get_network")


@app.get("/api/mac")
async def get_mac():
    r = require_reader()
    with reader_lock:
        result = r.get_mac()
    return parse_result(result, "get_mac")


@app.get("/api/time")
async def get_time():
    r = require_reader()
    with reader_lock:
        result = r.get_time()
    
    response = parse_result(result, "get_time")
    response["pc_time"] = int(time.time())
    response["pc_time_str"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if "seconds" in response:
        response["drift_seconds"] = response["seconds"] - int(time.time())
    return response


@app.get("/api/gpi")
async def get_gpi():
    r = require_reader()
    with reader_lock:
        return parse_result(r.get_gpi(), "get_gpi")


@app.get("/api/relay")
async def get_relay():
    r = require_reader()
    with reader_lock:
        return parse_result(r.get_relay(), "get_relay")


@app.get("/api/rs485")
async def get_rs485():
    r = require_reader()
    with reader_lock:
        return parse_result(r.get_rs485(), "get_rs485")


@app.get("/api/tagcache")
async def get_tag_cache():
    r = require_reader()
    with reader_lock:
        return parse_result(r.get_tag_cache(), "get_tag_cache")


@app.get("/api/tagtime")
async def get_tag_cache_time():
    r = require_reader()
    with reader_lock:
        return parse_result(r.get_tag_cache_time(), "get_tag_cache_time")


@app.get("/api/wiegand")
async def get_wiegand():
    r = require_reader()
    with reader_lock:
        return parse_result(r.get_wiegand(), "get_wiegand")


@app.get("/api/server")
async def get_server_mode():
    r = require_reader()
    with reader_lock:
        return parse_result(r.get_server_mode(), "get_server_mode")


@app.get("/api/com")
async def get_com():
    r = require_reader()
    with reader_lock:
        return parse_result(r.get_com_config(), "get_com_config")


@app.get("/api/ping")
async def get_ping():
    r = require_reader()
    with reader_lock:
        return parse_result(r.get_ping_config(), "get_ping")


@app.get("/api/antenna/{port}")
async def get_antenna(port: int):
    r = require_reader()
    with reader_lock:
        return parse_result(r.get_antenna_config(port), f"get_antenna_{port}")


@app.get("/api/antennas")
async def get_all_antennas():
    r = require_reader()
    ports = {}
    with reader_lock:
        for port in range(4):
            result = r.get_antenna_config(port)
            ports[f"port_{port}"] = parse_result(result) if result else {}
    return {"ports": ports}


@app.get("/api/trigger/{gpi}")
async def get_trigger(gpi: int):
    r = require_reader()
    with reader_lock:
        return parse_result(r.get_trigger_config(gpi), f"get_trigger_{gpi}")


@app.get("/api/triggers")
async def get_all_triggers():
    r = require_reader()
    triggers = {}
    with reader_lock:
        for pin in range(4):
            result = r.get_trigger_config(pin)
            triggers[f"gpi_{pin}"] = parse_result(result) if result else {}
    return {"triggers": triggers}


@app.get("/api/tags")
async def get_tags():
    r = require_reader()
    with reader_lock:
        return parse_result(r.get_tags(), "get_tags")


# ─── SET Commands ─────────────────────────────────────────────────────────────

@app.post("/api/settime")
async def set_time(req: SetTimeRequest):
    r = require_reader()
    with reader_lock:
        return parse_result(r.set_time(req.timestamp), "set_time")


@app.post("/api/setpower")
async def set_power(req: SetPowerRequest):
    r = require_reader()
    with reader_lock:
        return parse_result(r.set_antenna_power(req.port, req.power_dbm), f"set_power_{req.port}")


@app.post("/api/setantenna")
async def set_antenna(req: SetAntennaRequest):
    r = require_reader()
    with reader_lock:
        return parse_result(r.set_antenna_config(
            req.port, req.power, req.session, req.target, req.q_value
        ), f"set_antenna_{req.port}")


@app.post("/api/settrigger")
async def set_trigger(req: SetTriggerRequest):
    r = require_reader()
    with reader_lock:
        return parse_result(r.set_trigger(
            req.gpi_pin, req.start_mode, req.stop_mode, req.delay_10ms
        ), f"set_trigger_{req.gpi_pin}")


@app.post("/api/setrelay")
async def set_relay(req: SetRelayRequest):
    r = require_reader()
    with reader_lock:
        return parse_result(r.set_relay(req.relay_num, req.on_time_ms), f"set_relay_{req.relay_num}")


@app.post("/api/setip")
async def set_ip(req: SetIPRequest):
    r = require_reader()
    with reader_lock:
        return parse_result(r.set_ip(req.ip, req.mask, req.gateway), "set_ip")


@app.post("/api/setmac")
async def set_mac(req: SetMACRequest):
    r = require_reader()
    with reader_lock:
        return parse_result(r.set_mac(req.mac), "set_mac")


@app.post("/api/settagcache")
async def set_tag_cache(req: SetTagCacheRequest):
    r = require_reader()
    with reader_lock:
        return parse_result(r.set_tag_cache(req.enable), "set_tag_cache")


@app.post("/api/settagcachetime")
async def set_tag_cache_time(req: SetTagCacheTimeRequest):
    r = require_reader()
    with reader_lock:
        return parse_result(r.set_tag_cache_time(req.cache_time), "set_tag_cache_time")


@app.post("/api/setdhcp")
async def set_dhcp(req: SetDHCPRequest):
    r = require_reader()
    with reader_lock:
        return parse_result(r.set_dhcp(req.enable), "set_dhcp")


@app.post("/api/cleartags")
async def clear_tags():
    r = require_reader()
    with reader_lock:
        return parse_result(r.clear_tags(), "clear_tags")


@app.post("/api/reboot")
async def reboot():
    global reader
    r = require_reader()
    with reader_lock:
        try:
            result = r.reboot()
        except Exception:
            result = None
        # Reader drops TCP before responding — this is normal
        try:
            r.close()
        except Exception:
            pass
        reader = None
    log_warn("Reader rebooting (~20s)", "CMD")
    return {"status": "rebooting", "message": "Reader is rebooting. Reconnect in ~20 seconds."}


@app.post("/api/factoryreset")
async def factory_reset():
    global reader
    r = require_reader()
    with reader_lock:
        try:
            r.send_command(0x01, 0x14)
        except Exception:
            pass
        try:
            r.close()
        except Exception:
            pass
        reader = None
    log_warn("Factory reset — reader rebooting with defaults (MAC preserved)", "CMD")
    return {"status": "factory_reset", "message": "Factory reset sent. Reader rebooting with defaults. Reconnect to 192.168.1.116."}


# ─── Inventory WebSocket ──────────────────────────────────────────────────────

@app.websocket("/ws/inventory")
async def inventory_ws(ws: WebSocket):
    """
    WebSocket for live tag stream.
    
    Client sends: {"action": "start"} or {"action": "stop"}
    Server sends: tag data JSON objects in real-time
    """
    global inventory_active
    
    await ws.accept()
    inventory_ws_clients.append(ws)
    
    try:
        while True:
            msg = await ws.receive_text()
            data = json.loads(msg)
            action = data.get("action", "")
            
            if action == "start":
                if reader is None:
                    await ws.send_json({"error": "Not connected"})
                    continue
                
                inventory_active = True
                await ws.send_json({"status": "inventory_started"})
                
                # Run inventory in background thread
                loop = asyncio.get_event_loop()
                asyncio.ensure_future(
                    _run_inventory(ws, loop)
                )
                
            elif action == "stop":
                inventory_active = False
                with reader_lock:
                    if reader and reader.sock:
                        try:
                            from cl7206c2_client import build_packet
                            stop_pkt = build_packet(0x02, 0xFF)
                            reader.send(stop_pkt)
                        except:
                            pass
                await ws.send_json({"status": "inventory_stopped"})
                
    except WebSocketDisconnect:
        pass
    finally:
        inventory_active = False
        if ws in inventory_ws_clients:
            inventory_ws_clients.remove(ws)


async def _run_inventory(ws: WebSocket, loop):
    """Background task: read tags from reader and push to WebSocket."""
    global inventory_active
    
    try:
        with reader_lock:
            if reader is None:
                return
            from cl7206c2_client import build_packet
            
            # Start inventory command
            start_pkt = build_packet(0x02, 0x10, bytes([
                0x01, 0x00,  # antenna config follows
                0x02, 0x00,  # session
                0x03, 0x00,  # target
                0x04, 0x04,  # Q value
            ]))
            reader.send(start_pkt)
            reader.sock.settimeout(0.5)
        
        tag_count = 0
        
        while inventory_active and reader is not None:
            try:
                with reader_lock:
                    if reader is None or reader.sock is None:
                        break
                    try:
                        raw = reader.sock.recv(4096)
                    except Exception:
                        raw = b''
                
                if not raw:
                    await asyncio.sleep(0.05)
                    continue
                
                # Parse packets from raw data
                offset = 0
                while offset < len(raw):
                    if raw[offset] != 0xAA:
                        offset += 1
                        continue
                    
                    remaining = raw[offset:]
                    if len(remaining) < 7:
                        break
                    
                    pkt_len = (remaining[3] << 8) | remaining[4]
                    total = pkt_len + 7
                    
                    if len(remaining) < total:
                        break
                    
                    packet = remaining[:total]
                    offset += total
                    
                    # Tag notification: CMD=0x12
                    if packet[1] == 0x12:
                        tag_count += 1
                        tag_info = _parse_tag_notification(packet, tag_count)
                        
                        try:
                            await ws.send_json(tag_info)
                        except:
                            inventory_active = False
                            break
                
                await asyncio.sleep(0.01)
                
            except Exception as e:
                await asyncio.sleep(0.1)
        
    except Exception as e:
        try:
            await ws.send_json({"error": str(e)})
        except:
            pass
    finally:
        inventory_active = False
        with reader_lock:
            if reader and reader.sock:
                reader.sock.settimeout(3)


def _parse_tag_notification(packet, count):
    """Parse CMD=0x12 tag notification into JSON-friendly dict."""
    result = {
        "type": "tag",
        "count": count,
        "timestamp": time.time(),
        "raw_hex": packet.hex(),
    }
    
    try:
        sub = packet[2]
        data = packet[5:-2]
        
        # EPC is in the data payload
        # Format: [PC_H][PC_L][EPC bytes...]
        if len(data) >= 4:
            pc = (data[0] << 8) | data[1]
            epc_word_count = (pc >> 11) & 0x1F
            epc_len = epc_word_count * 2
            
            if epc_len > 0 and len(data) >= 2 + epc_len:
                epc_bytes = data[2:2 + epc_len]
                result["epc"] = epc_bytes.hex().upper()
                result["pc"] = f"0x{pc:04X}"
            
            # Parse TLV extensions after EPC
            tlv_offset = 2 + epc_len
            while tlv_offset < len(data):
                if tlv_offset >= len(data):
                    break
                tlv_type = data[tlv_offset]
                
                if tlv_type == 0x01 and tlv_offset + 2 < len(data):
                    result["ant_num"] = data[tlv_offset + 1]
                    result["sub_ant"] = data[tlv_offset + 2] if tlv_offset + 3 <= len(data) else 0
                    result["antenna"] = result["ant_num"] * 2 + result.get("sub_ant", 0) + 1
                    tlv_offset += 3
                elif tlv_type == 0x02 and tlv_offset + 2 < len(data):
                    result["rssi"] = data[tlv_offset + 1]
                    tlv_offset += 3
                elif tlv_type == 0x06 and tlv_offset + 1 < len(data):
                    result["sub_ant"] = data[tlv_offset + 1]
                    if "ant_num" in result:
                        result["antenna"] = result["ant_num"] * 2 + result["sub_ant"] + 1
                    tlv_offset += 2
                else:
                    break
        
        result["sub_cmd"] = f"0x{sub:02X}"
        
    except Exception as e:
        result["parse_error"] = str(e)
    
    return result


# ─── Entry Point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
