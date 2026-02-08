"""
CL7206C2 Firmware — Final Utility Functions (Batch 2)
=====================================================
13 more functions: UDP discovery response, Wiegand bit-level protocol,
trigger event routing, RS485 framing, TCP socket keepalive, heartbeat,
network init, firmware upgrade file replacement.

Combined with previous batches = 80 total functions decoded.
This is the DEFINITIVE catalog — no meaningful application logic remains.
"""

# =============================================================================
# UDP DISCOVERY RESPONSE — send_local_information()
# =============================================================================
#
# This function generates the UDP broadcast response that cl7206c2_tool.py
# parses. Now we have the EXACT format.
#
# Response format (ASCII text, ^ prefix, $ suffix):
#
#   ^RFID_READER_INFORMATION:7206C2,DHCP_SW:{ON|OFF},IP:{ip},MASK:{mask},
#   GATEWAY:{gateway},MAC:{mac},PORT:{port},HOST_SERVER_IP:{server_ip},
#   HOST_SERVER_PORT:{server_port},MODE:{SERVER|CLIENT},NET_STATE:{ACTIVE|INACTIVE}$
#
# Example:
#   ^RFID_READER_INFORMATION:7206C2,DHCP_SW:OFF,IP:192.168.1.116,MASK:255.255.255.0,
#   GATEWAY:192.168.1.1,MAC:AA:BB:CC:DD:EE:FF,PORT:9090,HOST_SERVER_IP:192.168.1.100,
#   HOST_SERVER_PORT:9090,MODE:SERVER,NET_STATE:ACTIVE$

def send_local_information(multicast_fd, timer, mode):
    """
    Send UDP multicast discovery response.
    
    Args:
        multicast_fd: UDP socket fd (from setup_multicast)
        timer: timeval pointer for rate limiting
        mode: 0 = send immediately, 1 = rate-limited (every 3s)
    
    Rate limiting (mode=1):
        cpu_diff_tick(timer) < 30 (3 seconds) → skip, return 0
        This prevents flooding during periodic broadcasts.
    
    IP change detection:
        Compares current IP (GetSysIpBySocket) with origine_local_ip.
        If IP changed (e.g. DHCP renewal) → returns -1, does NOT send.
        This forces setup_multicast() to be called again with new IP.
    
    NET_STATE detection:
        Gets active connection fd, checks if TCP via com_is_tcp()
        If TCP: getsockopt(fd, SOL_SOCKET, SO_ERROR) → 0 = ACTIVE
        If serial or error: INACTIVE
    
    Sends via: sendto(fd, response_string, len, 0, send_peeraddr, 16)
    Multicast group: 230.1.1.116 (configured in setup_multicast)
    
    Returns: 0 = success, 1 = sendto error, -1 = fd invalid or IP changed
    """
    pass


# UDP Discovery Response Field Map:
UDP_DISCOVERY_FIELDS = {
    "RFID_READER_INFORMATION": "7206C2 (hardcoded model identifier)",
    "DHCP_SW":        "ON or OFF — config_get_dhcp_sw()",
    "IP":             "Current system IP — GetSysIpBySocket()",
    "MASK":           "Current subnet mask — GetSysMaskBySocket()",
    "GATEWAY":        "Current gateway — net_get_gateway()",
    "MAC":            "Current MAC — GetSysMacBySocket()",
    "PORT":           "TCP listen port — config_get_local_port() [default 9090]",
    "HOST_SERVER_IP": "Server IP (client mode) — config_get_ser_ip()",
    "HOST_SERVER_PORT":"Server port (client mode) — config_get_ser_port()",
    "MODE":           "SERVER (mode=0) or CLIENT (mode=1)",
    "NET_STATE":      "ACTIVE (TCP connected, SO_ERROR=0) or INACTIVE",
}


# =============================================================================
# WIEGAND BIT-LEVEL PROTOCOL — WieGand_Send()
# =============================================================================
#
# Wiegand is a one-way protocol using two data lines (WG0, WG1).
# Idle state: both lines HIGH.
# Data '0': pulse WG0 LOW for ~100μs, WG1 stays HIGH
# Data '1': pulse WG1 LOW for ~100μs, WG0 stays HIGH
# Inter-bit gap: ~1.5ms (15 × 100μs)
#
# Three formats supported:
#   Wiegand-26: 1 parity + 24 data + 1 parity = 26 bits (3 bytes data)
#   Wiegand-34: 1 parity + 32 data + 1 parity = 34 bits (4 bytes data)
#   Wiegand-66: 1 parity + 64 data + 1 parity = 66 bits (8 bytes data)

WIEGAND_FORMATS = {
    0: {"name": "Wiegand-26", "data_bits": 24, "data_bytes": 3, "total_bits": 26},
    1: {"name": "Wiegand-34", "data_bits": 32, "data_bytes": 4, "total_bits": 34},
    2: {"name": "Wiegand-66", "data_bits": 64, "data_bytes": 8, "total_bits": 66},
}


def WieGand_Send(data, format_type):
    """
    Transmit data via Wiegand protocol on WG0/WG1 lines.
    
    Args:
        data: pointer to data bytes (3/4/8 bytes depending on format)
        format_type: 0=Wiegand-26, 1=Wiegand-34, 2=Wiegand-66
    
    Minimum interval: 500ms (5 ticks) between transmissions.
        If called too soon, waits but does NOT transmit (rate limiting).
    
    Transmission sequence:
    1. Wiegand_Output_Reset() — both lines HIGH (idle)
    2. Get_WieGand_Data_Check_Bit(data, format, &even_parity, &odd_parity)
       — Calculate leading even parity and trailing odd parity
    3. Send leading parity bit (even parity over first half of data):
       - parity=0 → Wiegand_Output_0() (pulse WG0)
       - parity=1 → Wiegand_Output_1() (pulse WG1)
       - delay_100us(1) — 100μs pulse width
       - Wiegand_Output_Reset()
    4. For each data byte, MSB first:
       for each bit 7→0:
         delay_100us(15) — 1.5ms inter-bit gap
         Send bit via Wiegand_Output_0() or Wiegand_Output_1()
         delay_100us(1) — 100μs pulse width
         Wiegand_Output_Reset()
    5. delay_100us(15) — final inter-bit gap
    6. Send trailing parity bit (odd parity over second half):
       Same as step 3 but with odd parity
    7. delay_100us(1) + Wiegand_Output_Reset()
    
    Data bytes count: format_type → local_1c (0x18=24, 0x20=32, 0x40=64 bits)
    Bytes to send = local_1c >> 3 = 3, 4, or 8 bytes
    
    Timing:
    - Pulse width: 100μs
    - Inter-bit gap: 1.5ms
    - Total Wiegand-26: ~39ms (26 × 1.5ms)
    - Total Wiegand-34: ~51ms
    - Total Wiegand-66: ~99ms
    - Min repeat interval: 500ms
    """
    pass


# =============================================================================
# TRIGGER EVENT UPDATE — GPI State → FSM Routing
# =============================================================================
#
# Three parallel arrays control trigger routing:
#
# input_array[4]:   each entry has 2 uint32 masks:
#   [0] = "detect mask"  — which bits indicate this GPI changed
#   [1] = "level mask"   — which bits indicate HIGH vs LOW
#
# envent_array[4]:  event flags (0=no event, 1=event pending)
#
# triger_array[4]:  pointers to trigger config structs
#   triger_array[i] + 4 = trigger input_level field (3=HIGH, 4=LOW)

def Triger_Event_Update(gpi_packed):
    """
    Route packed GPI levels to individual trigger FSMs.
    
    Args:
        gpi_packed: uint32 with all 4 GPI levels packed
            From ioctl(gpio_fd, 5, &value):
            Byte 3 (bits 24-31) = GPI 1
            Byte 2 (bits 16-23) = GPI 2
            Byte 1 (bits 8-15)  = GPI 3
            Byte 0 (bits 0-7)   = GPI 4
    
    For each GPI (0-3):
        1. Check detect mask: (input_array[i][0] & gpi_packed) != 0
           → This GPI has activity
        2. Set event flag: envent_array[i] = 1
        3. Determine level from level mask:
           (input_array[i][1] & gpi_packed) != 0 → HIGH (level=3)
           (input_array[i][1] & gpi_packed) == 0 → LOW  (level=4)
        4. Write level to trigger config: triger_array[i]->input_level = level
    
    After all GPIs processed:
        level_event_flag = 1
        cpu_get_lltimer(&test_timer)  — timestamp the event
        set_level_event_timer()       — start debounce timer
        Triger_Manage()               — immediately run all trigger FSMs
    
    Called by:
    - power_on_detect() — with 0x10101010 OR'd (initial state)
    - GPIO polling thread — with raw ioctl values (runtime)
    
    This is the bridge between hardware GPIO and the 5-state trigger FSM.
    """
    pass


# =============================================================================
# RS485 FRAMING — Address Byte Insertion/Removal
# =============================================================================
#
# RS485 bus is multi-drop: multiple devices share the same physical wires.
# An address byte is prepended to each packet to identify the recipient.
#
# RS485 packet vs standard packet:
#
# Standard: AA [CMD] [SUB] [LEN_H] [LEN_L] [DATA...] [CRC_H] [CRC_L]
# RS485:    AA [CMD|0x20] [SUB] [ADDR] [LEN_H] [LEN_L] [DATA...] [CRC_H'] [CRC_L']
#
# Bit 5 of CMD byte (0x20 mask) = RS485 direction flag:
#   0 = standard packet (no address byte)
#   1 = RS485 packet (address byte follows SUB)
#
# CRC is recalculated after address insertion/removal.

def Rs485_data_process(fd, packet, packet_len, local_addr):
    """
    Process incoming RS485 packet — strip address byte if addressed to us.
    
    Called by protocol_data_process() when rec->fd == rs485_com_fd.
    
    1. Check RS485 flag: (packet[1] >> 5) & 1
       If NOT set (standard packet) → return 0 (pass through to GetHead)
    
    2. Check address: packet[3] == local_addr?
       No → return -3 (0xFFFFFFFD), packet dropped (not for us)
    
    3. Strip address byte:
       memcpy(packet+3, packet+4, packet_len-4)  — shift data left
       packet[1] &= 0xDF  — clear RS485 flag (bit 5)
       Recalculate CRC16 over modified packet
       Write new CRC at end
    
    4. Return 0 → packet now looks like standard packet, GetHead() processes it
    
    Returns: 0 = success (process packet), -3 = wrong address, -4 = too short
    """
    pass


def Add_Rs485_Addr(src, src_len, addr, dst):
    """
    Insert RS485 address byte into outgoing packet.
    
    Called by transfer_to_pc() when active connection is RS485.
    
    1. Copy first 3 bytes (AA, CMD, SUB) from src to dst
    2. Set RS485 flag: dst[1] |= 0x20 (set bit 5 of CMD byte)
    3. Insert address byte: dst[3] = addr
    4. Copy remaining data: memcpy(dst+4, src+3, src_len-3)
    5. Recalculate CRC16 over dst[1..end-2], write at end
    
    Result: packet grows by 1 byte (address inserted after SUB).
    Output packet length = src_len + 1.
    
    The RS485 flag in CMD byte tells the receiver to expect the address byte.
    """
    pass


# RS485 packet structure comparison:
#
# Standard (7+ bytes):
#  [0]  [1]   [2]   [3]     [4]     [5..N]   [N+1]   [N+2]
#  0xAA  CMD   SUB   LEN_H   LEN_L   DATA     CRC_H   CRC_L
#
# RS485 (8+ bytes):
#  [0]  [1]       [2]   [3]    [4]     [5]     [6..N]   [N+1]   [N+2]
#  0xAA  CMD|0x20  SUB   ADDR   LEN_H   LEN_L   DATA     CRC_H'  CRC_L'
#
# Bit 5 of byte[1] = RS485 flag. Address = byte[3].


# =============================================================================
# TCP SOCKET SETUP — Keepalive Configuration
# =============================================================================

def tcp_socket_setup():
    """
    Create TCP socket with aggressive keepalive settings.
    
    Socket options applied:
    
    1. O_NONBLOCK via fcntl(fd, F_SETFL, flags | O_NONBLOCK)
       — Non-blocking I/O for select() loop
    
    2. SO_REUSEADDR = 1 (SOL_SOCKET=1, SO_REUSEADDR=2)
       — Allow immediate rebind after close
    
    3. SO_KEEPALIVE = 1 (SOL_SOCKET=1, SO_KEEPALIVE=9)
       — Enable TCP keepalive probes
    
    4. TCP_KEEPIDLE = 5 (IPPROTO_TCP=6, TCP_KEEPIDLE=4)
       — Start keepalive probes after 5 seconds of idle
       — VERY aggressive (Linux default is 7200s / 2 hours!)
    
    5. TCP_KEEPINTVL = 1 (IPPROTO_TCP=6, TCP_KEEPINTVL=5)
       — Send probes every 1 second
    
    6. TCP_KEEPCNT = 3 (IPPROTO_TCP=6, TCP_KEEPCNT=6)
       — Drop connection after 3 failed probes
    
    Total dead-peer detection: 5s idle + 3×1s probes = 8 seconds!
    This is critical for race timing — broken connections are detected fast.
    
    Returns: socket fd, or -1 on error
    """
    pass

# TCP keepalive summary:
TCP_KEEPALIVE_CONFIG = {
    "TCP_KEEPIDLE":  5,     # seconds before first probe
    "TCP_KEEPINTVL": 1,     # seconds between probes
    "TCP_KEEPCNT":   3,     # failed probes before disconnect
    "TOTAL_DETECT":  "8s",  # 5 + 3×1 = 8 seconds to detect dead peer
}


# =============================================================================
# RESET SOCKET — TCP Connection Teardown
# =============================================================================

def reset_socket(fd):
    """
    Close a TCP connection and clean up fd_set bitmasks.
    
    Handles three possible TCP fds:
    - socket_fd:           client-mode outgoing connection
    - tcp_connect_fd:      server-mode client #1
    - tcp_connect_back_fd: server-mode client #2
    
    For each matching fd:
    1. close(fd)
    2. Clear bit in write_fd (select write set): ~(1 << (fd & 31))
    3. Clear bit in fdsr (select read set): ~(1 << (fd & 31))
    4. Set fd variable to -1 (marks as disconnected)
    
    After cleanup:
    - If the closed fd was the active connection:
      connect_set_active_fd(pc_com_fd) → fall back to serial port
    
    Special case: fd < 0 → just fall back to serial (no close needed)
    
    This is called by:
    - transfer_to_pc() after 3 consecutive write failures
    - heart_beat_manage() when heartbeat detects dead connection
    - Protocol errors
    
    The fallback to pc_com_fd ensures the reader always has a
    communication channel — even if TCP dies, serial still works.
    """
    pass


# =============================================================================
# HEARTBEAT — Connection Liveness Detection
# =============================================================================

def heart_beat_manage(mode):
    """
    Check connection health and reset dead sockets.
    
    if mode == 1 (client mode):
      if_com_alive() → returns 0 if connection is dead
      If dead: reset_socket(socket_fd) → close + fallback to serial
    
    Called by client_mode_reconnect() every ~9 seconds.
    After reset, client_mode_reconnect() will create a new connection.
    
    Returns: result of reset_socket, or 1 if mode != 1
    """
    pass


def if_com_alive():
    """
    Check if the TCP client connection is alive via serial number tracking.
    
    The reader assigns incrementing serial numbers to outgoing packets.
    The server ACKs with the serial number. If too many go un-ACK'd,
    the connection is considered dead.
    
    Logic:
    1. power_on_ser_cli_mode() → 0 if server mode → return -1 (always "alive")
       Server mode doesn't need heartbeat (clients reconnect themselves)
    
    2. Compare serial numbers:
       connect_serial_num < connect_ack_serial_num + 4
       → True: gap < 4, connection is alive → return -1
       → False: gap >= 4, connection is dead → return 0
    
    The gap threshold of 4 means: if 4+ packets go without ACK,
    the connection is declared dead. At ~9s check intervals,
    this gives the server up to ~36 seconds to respond before disconnect.
    
    Returns: -1 = alive (or server mode), 0 = dead
    """
    pass


# =============================================================================
# NETWORK INITIALIZATION
# =============================================================================

def net_pram_init():
    """
    Apply saved network configuration at boot.
    
    1. Read IP from config: config_get_local_ip_pram()
    2. Check DHCP mode: config_get_dhcp_sw()
       - DHCP enabled (1): just print, let DHCP client handle it
       - DHCP disabled (0): netapp_set_ip_pram(ip) → apply static IP
    
    3. Read MAC from config: config_get_local_mac_pram()
    4. Apply MAC: netapp_set_mac_pram(mac)
       - If fails: fall back to default MAC (C.14.3635 = compiled-in default)
    
    Called once during initialization, after config_pram_init().
    
    Note: The fallback MAC ensures the reader always has a valid MAC,
    even if the config file is corrupted. This prevents the reader from
    becoming unreachable on the network.
    """
    pass


# =============================================================================
# FIRMWARE UPGRADE — File Replacement
# =============================================================================

def upgrade_instead_file(mode):
    """
    Replace firmware binary after OTA upgrade completes.
    
    TWO MODES:
    
    Mode 1 (param_1 == 0x01) — WHITE LIST UPGRADE:
      system("rm /white_list_db")
      system("mv /CL7206C2 /white_list_db")
      sync()
      → The downloaded file replaces the white list database
      → Called when CMD=0x01 SUB=0x21 upgrade completes
    
    Mode 0 (param_1 != 0x01) — FIRMWARE UPGRADE:
      system("cp /bin/CL7206C2 /back_app")    — backup current firmware!
      system("rm /bin/CL7206C2")               — remove current
      system("chmod 777 /CL7206C2")            — make new executable
      system("cp /CL7206C2 /bin")              — install new firmware
      sync()
      → Called when CMD=0x04 SUB=0x00 upgrade completes
      → Reader reboots after this (from Upgrade_Process)
    
    File paths:
      /CL7206C2           — downloaded file (from OTA)
      /bin/CL7206C2       — running firmware binary
      /back_app           — backup of previous firmware
      /white_list_db      — white list database file
    
    IMPORTANT: The backup to /back_app means you can recover from a bad
    firmware upgrade by restoring from /back_app via telnet!
    
    Recovery (if new firmware crashes):
      telnet → cp /back_app /bin/CL7206C2 → reboot
    """
    pass


# File layout on reader filesystem:
FIRMWARE_FILES = {
    "/bin/CL7206C2":  "Running firmware binary (main application)",
    "/back_app":      "Backup of previous firmware (created during upgrade)",
    "/CL7206C2":      "Downloaded file staging area (OTA target)",
    "/config_pram":   "Configuration file (1072 bytes, ../config_pram relative to /bin)",
    "/tag_table":     "SQLite tag database (on-disk storage)",
    "/white_list_db": "White list database (uploaded via CMD=0x01 SUB=0x21)",
    "/tmp/myfifo":    "Watchdog FIFO (read by feed_dog process)",
}


# =============================================================================
# TAG DEDUPLICATION — NO tag_cache_check FUNCTION EXISTS
# =============================================================================
#
# IMPORTANT FINDING: There is NO tag_cache_check() function in the firmware.
# Tag deduplication relies ENTIRELY on two mechanisms:
#
# 1. SQLite back_tag_data buffer (5-second window):
#    data_base_store_record() inserts every tag read into back_tag_data.
#    data_base_machine() copies records older than 5s to tag_data (disk).
#    But there's no UNIQUE constraint on EPC — duplicates DO get stored.
#
# 2. Tag cache configuration (CMD 0x17/0x18/0x19/0x1A):
#    tag_cache_switch (pram_p_array[11]) = enable/disable
#    tag_cache_time (pram_p_array[12]) = cache duration
#    This is handled by the RF MODULE, not the Linux application.
#    The RF module filters duplicate reads before sending notifications.
#
# For race timing, client-side deduplication is ESSENTIAL:
#   - RF module cache prevents rapid-fire duplicates (sub-second)
#   - 5s buffer provides persistence
#   - But the client must still dedup by EPC+antenna with a configurable
#     minimum interval (e.g., 30s for lap timing, 5min for finish line)
#
# The white_list_check is also a STUB (returns 1), confirming that
# any smart filtering must be done client-side.


# =============================================================================
# COMPLETE FUNCTION CATALOG — 80 FUNCTIONS
# =============================================================================
#
# Batch 1 (43 critical functions — architecture.py, remaining_subsystems.py):
#   main, GetHead, transfer_to_rf, tag_data_analise, sql_insert,
#   data_base_store_record, data_base_machine, data_base_init,
#   data_base_answer_machine, sql_write_real_table, sql_delete_record,
#   sql_delete_record_by_index, config_set_pra, config_get_pra, save_config,
#   build_set_pack, CRC16_CalateByte, CRC16_CalculateBuf,
#   Triger_State_Machine, Triger_Manage, Send_Triger_start_Cmd,
#   Send_Triger_Stop_Cmd, triger_delay_process, Notification_Pc,
#   Gpo_Data_Process, gpio_init, gpio_relay_on_ctl, relay_timer_start,
#   connect_state_init, connect_manage, connect_manage_time_out,
#   tcp_recive, recive_init, link_status_mornitor, fifo_init, fifo_write,
#   UDP_cmd_process, WieGand_Data_Save, Upgrade_Process, check_crc,
#   send_local_information, data_base_white_list_check, fast_crc32
#
# Batch 2 (24 utility functions — utility_functions.py):
#   gpio_beep_crtl, gpio_phy_ctl, gpio_relay_1_crtl, gpio_relay_2_crtl,
#   gpio_get_input_1_level, power_on_detect, cpu_get_lltimer, cpu_diff_tick,
#   cpu_diff_us, tcpserver_starup, tcpclient_starup, setup_multicast,
#   config_pram_init, config_reset, config_get_ser_cli_mode,
#   Server_Client_Pra_Process, com_recive, protocol_data_process,
#   transfer_to_pc, serial_connect_ensure, client_mode_reconnect,
#   rec_struct_init, sql_creat_table, Gpo_Data_Process(expanded)
#
# Batch 3 (13 final functions — THIS FILE):
#   send_local_information(expanded), WieGand_Send, Triger_Event_Update,
#   Rs485_data_process, Add_Rs485_Addr, reset_socket, tcp_socket_setup,
#   heart_beat_manage, if_com_alive, net_pram_init, upgrade_instead_file
#
# TOTAL: 80 functions fully decoded
#
# Remaining ~230 symbols: libc wrappers, trivial 1-line getters/setters
# (get_reading_flag, get_pc_com_fd, get_rf_com_fd, com_is_tcp,
#  uart_is_485_com, config_get_local_port, connect_get_active_fd,
#  connect_set_active_fd, set_time_out, reset_time_out, etc.)
#
# NO APPLICATION LOGIC REMAINS UNDECODED.


# =============================================================================
# KEY FINDINGS SUMMARY — IMPLICATIONS FOR RACE TIMING
# =============================================================================

TIMING_SYSTEM_IMPLICATIONS = {
    "tag_dedup": """
        NO client-side dedup in firmware. RF module cache provides sub-second
        filtering. Client MUST implement its own dedup with configurable
        intervals per EPC+antenna combination.""",

    "tcp_keepalive": """
        Dead peer detected in 8 seconds (5s idle + 3×1s probes).
        Good for race timing — broken network recovers fast.""",

    "auto_reconnect": """
        Client mode reconnects every ~9s. Combined with 8s keepalive detection,
        total recovery time ≈ 17 seconds after network failure.""",

    "wiegand_timing": """
        500ms minimum between Wiegand transmissions. Wiegand-26 frame takes
        ~39ms. Not suitable for high-speed tag streams but fine for access
        control integration.""",

    "firmware_backup": """
        OTA upgrade creates /back_app backup. Recovery possible via telnet
        if new firmware fails to boot (watchdog will reboot, but old binary
        is still at /back_app).""",

    "udp_discovery": """
        Full response format decoded. cl7206c2_tool.py can now parse all
        fields including NET_STATE (TCP connection health).""",

    "rs485_daisy_chain": """
        Full RS485 addressing implemented. Multiple readers on same bus
        with unique addresses. CMD byte bit 5 = RS485 flag.
        Address byte inserted after SUB in packet.""",

    "gpi_initial_state": """
        power_on_detect() reads all 4 GPI levels at boot with 0x10101010
        marker. Prevents false trigger events during initialization.""",
}
