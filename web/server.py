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
import threading
from pathlib import Path
from datetime import datetime
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional

# Add tools/ to path so we can import the client
sys.path.insert(0, str(Path(__file__).parent.parent / "tools"))
from cl7206c2_client import CL7206C2Client, parse_packet

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
            reader = CL7206C2Client(req.ip, req.port)
            reader.connect()
            return {"status": "connected", "ip": req.ip, "port": req.port}
        except Exception as e:
            reader = None
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
    return {"status": "disconnected"}


@app.get("/api/status")
async def status():
    return {
        "connected": reader is not None,
        "inventory_active": inventory_active,
        "ws_clients": len(inventory_ws_clients),
    }


# ─── GET Commands ─────────────────────────────────────────────────────────────

@app.get("/api/info")
async def get_info():
    r = require_reader()
    with reader_lock:
        return r.get_reader_info()


@app.get("/api/network")
async def get_network():
    r = require_reader()
    with reader_lock:
        return r.get_network()


@app.get("/api/mac")
async def get_mac():
    r = require_reader()
    with reader_lock:
        return r.get_mac()


@app.get("/api/time")
async def get_time():
    r = require_reader()
    with reader_lock:
        result = r.get_time()
    result["pc_time"] = int(time.time())
    result["pc_time_str"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if "seconds" in result:
        try:
            result["reader_time_str"] = datetime.fromtimestamp(
                result["seconds"]
            ).strftime("%Y-%m-%d %H:%M:%S")
            result["drift_seconds"] = result["seconds"] - int(time.time())
        except:
            pass
    return result


@app.get("/api/gpi")
async def get_gpi():
    r = require_reader()
    with reader_lock:
        return r.get_gpi()


@app.get("/api/relay")
async def get_relay():
    r = require_reader()
    with reader_lock:
        return r.get_relay()


@app.get("/api/rs485")
async def get_rs485():
    r = require_reader()
    with reader_lock:
        return r.get_rs485()


@app.get("/api/tagcache")
async def get_tag_cache():
    r = require_reader()
    with reader_lock:
        return r.get_tag_cache()


@app.get("/api/tagtime")
async def get_tag_cache_time():
    r = require_reader()
    with reader_lock:
        return r.get_tag_cache_time()


@app.get("/api/wiegand")
async def get_wiegand():
    r = require_reader()
    with reader_lock:
        return r.get_wiegand()


@app.get("/api/server")
async def get_server_mode():
    r = require_reader()
    with reader_lock:
        return r.get_server_mode()


@app.get("/api/com")
async def get_com():
    r = require_reader()
    with reader_lock:
        return r.get_com_config()


@app.get("/api/ping")
async def get_ping():
    r = require_reader()
    with reader_lock:
        return r.get_ping_config()


@app.get("/api/antenna/{port}")
async def get_antenna(port: int):
    r = require_reader()
    with reader_lock:
        return r.get_antenna_config(port)


@app.get("/api/antennas")
async def get_all_antennas():
    r = require_reader()
    with reader_lock:
        return r.get_all_antennas()


@app.get("/api/trigger/{gpi}")
async def get_trigger(gpi: int):
    r = require_reader()
    with reader_lock:
        return r.get_trigger_config(gpi)


@app.get("/api/triggers")
async def get_all_triggers():
    r = require_reader()
    with reader_lock:
        return r.get_all_triggers()


@app.get("/api/tags")
async def get_tags():
    r = require_reader()
    with reader_lock:
        return r.get_tags()


# ─── SET Commands ─────────────────────────────────────────────────────────────

@app.post("/api/settime")
async def set_time(req: SetTimeRequest):
    r = require_reader()
    with reader_lock:
        return r.set_time(req.timestamp)


@app.post("/api/setpower")
async def set_power(req: SetPowerRequest):
    r = require_reader()
    with reader_lock:
        return r.set_antenna_power(req.port, req.power_dbm)


@app.post("/api/setantenna")
async def set_antenna(req: SetAntennaRequest):
    r = require_reader()
    with reader_lock:
        return r.set_antenna_config(
            req.port, req.power, req.session, req.target, req.q_value
        )


@app.post("/api/settrigger")
async def set_trigger(req: SetTriggerRequest):
    r = require_reader()
    with reader_lock:
        return r.set_trigger(
            req.gpi_pin, req.start_mode, req.stop_mode, req.delay_10ms
        )


@app.post("/api/setrelay")
async def set_relay(req: SetRelayRequest):
    r = require_reader()
    with reader_lock:
        return r.set_relay(req.relay_num, req.on_time_ms)


@app.post("/api/setip")
async def set_ip(req: SetIPRequest):
    r = require_reader()
    with reader_lock:
        return r.set_ip(req.ip, req.mask, req.gateway)


@app.post("/api/setmac")
async def set_mac(req: SetMACRequest):
    r = require_reader()
    with reader_lock:
        return r.set_mac(req.mac)


@app.post("/api/settagcache")
async def set_tag_cache(req: SetTagCacheRequest):
    r = require_reader()
    with reader_lock:
        return r.set_tag_cache(req.enable)


@app.post("/api/settagcachetime")
async def set_tag_cache_time(req: SetTagCacheTimeRequest):
    r = require_reader()
    with reader_lock:
        return r.set_tag_cache_time(req.cache_time)


@app.post("/api/cleartags")
async def clear_tags():
    r = require_reader()
    with reader_lock:
        return r.clear_tags()


@app.post("/api/reboot")
async def reboot():
    global reader
    r = require_reader()
    with reader_lock:
        result = r.reboot()
        reader = None
    return result


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
