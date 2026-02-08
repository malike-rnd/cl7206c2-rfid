"""
CL7206C2 Firmware Architecture — Complete Decoded Map
=====================================================

Source: main(), GetHead (protocol router), all subsystem functions.
Binary: /bin/CL7206C2 (ARM ELF, unstripped, 310 symbols)

## Application Architecture

    ┌──────────────────────────────────────────────────────────┐
    │                    MAIN SELECT() LOOP                     │
    │                                                          │
    │  File Descriptors monitored:                             │
    │  ┌──────────────────────────────────────────────┐        │
    │  │ rf_com_fd       — RF module serial            │        │
    │  │ pc_com_fd       — PC serial (RS-232)          │        │
    │  │ reserv_com_fd   — Reserved serial             │        │
    │  │ rs485_com_fd    — RS-485 serial               │        │
    │  │ usb_com_fd      — USB serial gadget           │        │
    │  │ usb_disk_fd     — USB hotplug (netlink)       │        │
    │  │ multicast_rec_fd— UDP broadcast receiver      │        │
    │  │ socket_fd       — Main TCP socket             │        │
    │  │ tcp_connect_fd  — TCP client #1               │        │
    │  │ tcp_connect_back_fd — TCP client #2           │        │
    │  └──────────────────────────────────────────────┘        │
    │                                                          │
    │  Each iteration:                                         │
    │  1. select() with 1s timeout                             │
    │  2. fifo_write()                                         │
    │  3. send_local_information() — multicast heartbeat       │
    │  4. data_base_machine()     — tag DB maintenance         │
    │  5. connect_manage()        — connection management      │
    │  6. link_status_mornitor()  — ethernet cable detect      │
    │  7. DHCP check (every 30s if enabled)                    │
    │  8. Process ready FDs:                                   │
    │     - TCP accept/receive                                 │
    │     - Serial port receive (pc, rs485, usb, rf, reserv)   │
    │     - UDP broadcast commands                             │
    │     - USB disk hotplug → firmware upgrade                │
    │  9. connect_manage_time_out()                            │
    │  10. Client mode reconnect logic                         │
    └──────────────────────────────────────────────────────────┘

## Initialization Sequence

    config_pram_init()       — Load /config_pram (1072 bytes)
    uart_com_init()          — Open serial ports
    net_pram_init()          — Apply network config
    connect_man_init()       — Init connection manager
    gpio_init()              — GPIO, LEDs, buzzer, relays
    recive_init()            — Receive buffers
    Wiegand_Init()           — Wiegand output
    data_base_init()         — Open SQLite databases
    file_gateway_init()      — Gateway file
    usb_upgrade_timer_init() — USB upgrade watchdog

    if server_mode:
        tcpserver_starup()   — Listen on port 9090
    else:
        tcpclient_starup()   — Connect to configured server

    setup_multicast()        — UDP discovery (broadcast)
    setup_brocast_rec_socket() — UDP command receiver
    fifo_init()              — FIFO IPC

## Network Modes

    server_client_mode = 0: TCP SERVER (default)
        Reader listens on port 9090
        Accepts up to 2 simultaneous TCP clients
        tcp_connect_fd + tcp_connect_back_fd

    server_client_mode = 1: TCP CLIENT
        Reader connects to configured server IP:port
        Auto-reconnect with timeout (120s = 0x77+1 ticks)
        Keepalive via connect_ensure_cmd

## Command Router (GetHead / protocol_cmd_hdl)

    Source check:
        uart_is_rf_com() → from RF module
        connect_get_active_fd() → from network/serial client

    ┌─────────────────────────────────────────────────────────┐
    │ FROM NETWORK CLIENT (local_25 == 0):                     │
    │                                                          │
    │ CMD=0x02 (RF passthrough):                               │
    │   SUB=0x10/0x40 → reading_flag = 1, transfer_to_rf()    │
    │   SUB=0xFF      → reading_flag = 0, transfer_to_rf()    │
    │                                                          │
    │ CMD=0x04 SUB=0x01 (firmware upgrade via RF):             │
    │   → transfer_to_rf()                                     │
    │                                                          │
    │ CMD=0x05 (pass to RF):                                   │
    │   → transfer_to_rf()                                     │
    │                                                          │
    │ CMD=0x01 (management) — full protocol_cmd_hdl:           │
    │   SUB=0x00: Reader info (model, name, uptime)            │
    │   SUB=0x01: RF passthrough (transfer_to_rf)              │
    │   SUB=0x02: COM/baud → save_config + pc_com_init         │
    │   SUB=0x03: GET config (baud, server, wiegand, dhcp)     │
    │   SUB=0x04: SET IP → ip_pra_check + netapp_set_ip_pram  │
    │   SUB=0x05: GET network (IP/mask/GW)                     │
    │   SUB=0x06: GET MAC                                      │
    │   SUB=0x07: SET server/client mode                       │
    │   SUB=0x08: GET server/client config                     │
    │   SUB=0x09: SET GPO (Gpo_Data_Process)                   │
    │   SUB=0x0A: GET GPI (4× gpio_get_input_N_level)         │
    │   SUB=0x0B: SET antenna/trigger config                   │
    │   SUB=0x0C: GET antenna/trigger config                   │
    │   SUB=0x0D: SET wiegand → save_config                    │
    │   SUB=0x0E: GET wiegand config                           │
    │   SUB=0x0F: REBOOT → transfer_to_rf + system("reboot")  │
    │   SUB=0x10: SET time → settimeofday + hwclock -w         │
    │   SUB=0x11: GET time (sec + usec)                        │
    │   SUB=0x12: ACK connection (keepalive)                   │
    │   SUB=0x13: SET MAC → netapp_set_mac_pram                │
    │   SUB=0x14: RESET → transfer_to_rf + config_reset        │
    │   SUB=0x15: SET RS485 → config_set_pra + rs485_com_init  │
    │   SUB=0x16: GET RS485 (addr + mode)                      │
    │   SUB=0x17: SET tag cache → save_config                  │
    │   SUB=0x18: GET tag cache switch                         │
    │   SUB=0x19: SET tag cache time → save_config             │
    │   SUB=0x1A: GET tag cache time                           │
    │   SUB=0x1B: GET tags → data_base_answer_machine          │
    │   SUB=0x1C: CLEAR tags → data_base_clear_data            │
    │   SUB=0x1D: DELETE tag by index                          │
    │   SUB=0x20: GET white list (by offset)                   │
    │   SUB=0x21: SET white list (Upgrade_Process variant)     │
    │   SUB=0x23: SET relay → save_config                      │
    │   SUB=0x24: GET relay (num + on_time)                    │
    │   SUB=0x2D: SET ping → ping_addr_check + save_config     │
    │   SUB=0x2E: GET ping config                              │
    │   SUB=0x2F: SET DHCP → save_config                       │
    │   SUB=0x30: GET DHCP config                              │
    │   SUB=0x54: RS485 passthrough → write to rs485_com_fd    │
    │   SUB=0x55: DELETE tag by index (alias)                  │
    │                                                          │
    │ CMD=0x04 SUB=0x00 (firmware upgrade via network):        │
    │   → Upgrade_Process()                                    │
    └─────────────────────────────────────────────────────────┘

    ┌─────────────────────────────────────────────────────────┐
    │ FROM RF MODULE (local_25 == 1):                          │
    │                                                          │
    │ CMD=0x12 (tag notification):                             │
    │   SUB=0x00/0x20/0x30:                                    │
    │     1. Wiegand output (if enabled)                       │
    │     2. If tag_cache ON:                                  │
    │        → data_base_store_record() + return               │
    │     3. If tag_cache OFF:                                 │
    │        → data_base_white_list_check() [stub, returns 1]  │
    │        → If white_list match (==0):                      │
    │          gpio_relay_on_ctl() + relay_timer_start()       │
    │     4. transfer_to_pc() — always forward to client       │
    │                                                          │
    │ CMD=0x02/0x04/0x10/0x05/0x01(SUB=0x01):                 │
    │   → transfer_to_pc() — forward RF responses to client   │
    │                                                          │
    │ CMD=0x32 ('2'):                                          │
    │   → (unknown, possibly RS485 passthrough response)       │
    └─────────────────────────────────────────────────────────┘

## Database Architecture

    ┌────────────────┐     ┌────────────────┐
    │ back_tag_data  │     │   tag_data      │
    │ (new_db)       │────►│ (permanent)     │
    │ Buffer: last   │     │ All records     │
    │ 5 seconds      │     │ (deduplicated)  │
    └────────────────┘     └────────────────┘

    data_base_machine() — called every main loop iteration:
        Every 5 seconds:
            sql_write_real_table():
                INSERT INTO tag_data SELECT * FROM back_tag_data
                WHERE time_seconds <= (now - 5)
            sql_delete_record():
                DELETE FROM back_tag_data WHERE time_seconds <= (now - 5)
            data_base_record_num_check() — limit total records

    SQL queries (verified from decompiled strings):
        INSERT INTO tag_data VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
        INSERT INTO back_tag_data VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
        SELECT max(tag_index) as maxid FROM back_tag_data
        SELECT max(tag_index) as maxid FROM tag_data
        DELETE FROM back_tag_data WHERE time_seconds <= N
        DELETE FROM tag_data WHERE time_seconds = N AND time_usec = M
        DELETE FROM back_tag_data WHERE tag_index = N

## Wiegand Output

    WieGand_Data_Save():
        Circular buffer: 300 entries × 12 bytes
        wiegand_param[0] = data length
        wiegand_param[1] = mode (0=off, 1=on)
        wiegand_param[4] = data type (0=EPC, 1=TID)
        wiegand_param[8] = offset in EPC/TID to extract

        if mode == 1:
            Find free slot in 300-entry buffer
            Extract bytes from tag EPC or TID at configured offset
            WieGand_Send(data, format)

    Wiegand formats (from config):
        0 = Off
        1 = Wiegand-26
        2 = Wiegand-34
        3 = Wiegand-66

## Firmware Upgrade Protocol

    Upgrade_Process():
        CMD=0x04 SUB=0x00 (network) or CMD=0x01 SUB=0x21 (white list variant)

        Packet format:
            [offset(4B BE)][chunk_len(2B BE)][data...]

        Flow:
            1. offset == 0: rm /CL7206B2, rm /CL7206C2, create new file
            2. Sequential writes at specified offsets
            3. offset == 0xFFFFFFFF: finalize
               - Read last 4 bytes = expected CRC32
               - Read app signature (16 bytes before CRC)
               - Verify CRC32 over entire file (excluding last 4 bytes)
               - Verify app signature (upgrade_check_app_sign)
               - If OK: upgrade_instead_file() — replace binary

        CRC: fast_crc32() over 256-byte blocks
        Safety: Sequential packet index check (upgrade_pack_index)

## Complete Function Decode Status

    FULLY DECODED (with struct/offset mapping):
    ✅ main()                    — Full select() loop architecture
    ✅ GetHead/protocol_cmd_hdl  — All 37+ command handlers
    ✅ transfer_to_rf()          — Direct write() to RF serial
    ✅ tag_data_analise()        — TLV parser, 500-byte struct
    ✅ sql_insert()              — 13-column SQLite binding
    ✅ data_base_store_record()  — RF→struct→SQL→PC pipeline
    ✅ data_base_machine()       — 5s buffer + cleanup
    ✅ sql_write_real_table()    — Buffer→permanent copy
    ✅ sql_delete_record()       — Time-based cleanup
    ✅ config_set_pra()          — Config write via pram_p_array
    ✅ config_get_pra()          — Config read via pram_p_array
    ✅ pram_p_array              — 16 config params fully mapped
    ✅ CRC16_CalateByte()        — Poly 0x8005 verified
    ✅ Triger_State_Machine()    — 5-state FSM for GPI triggers
    ✅ Triger_Manage()           — 4-GPI trigger loop
    ✅ Send_Triger_start_Cmd()   — RF command from trigger config
    ✅ Send_Triger_Stop_Cmd()    — Hardcoded AA 02 FF stop
    ✅ triger_delay_process()    — POSIX timer, 10ms units
    ✅ Notification_Pc()         — Trigger event notification
    ✅ Gpo_Data_Process()        — GPIO relay switching
    ✅ connect_state_init()      — TCP handshake + keepalive
    ✅ WieGand_Data_Save()       — EPC/TID extraction + Wiegand send
    ✅ Upgrade_Process()         — Network OTA with CRC32 verify
    ✅ check_crc()               — Firmware CRC check (not packets)
    ✅ data_base_white_list_check() — STUB (returns 1, not implemented)

    NOT DECODED (low priority):
    ⬜ recive_init / tcp_recive  — Receive buffer management
    ⬜ connect_manage            — Connection lifecycle
    ⬜ link_status_mornitor      — Ethernet cable detection
    ⬜ fifo_write / fifo_init    — IPC to fifo_read process
    ⬜ usb_upgrade_timer_init    — USB hotplug upgrade
    ⬜ Various gpio_* helpers    — LED, buzzer control
"""
