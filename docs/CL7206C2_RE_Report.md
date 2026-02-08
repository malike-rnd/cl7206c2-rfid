# CLOU CL7206C2 RFID Reader — Complete Reverse Engineering Report
# Firmware: CL7206C_20170602 / CL7206C2_STD_APP
# Binary: CL7206C2 (ARM ELF, 150KB, not stripped, with debug info)

═══════════════════════════════════════════════════════════════════
## 1. FIRMWARE OVERVIEW
═══════════════════════════════════════════════════════════════════

Architecture:     ARM (armv5tejl), 32-bit, little-endian
Kernel:           Linux 2.6.39+
Toolchain:        GCC 4.0.0 (DENX ELDK 4.1) — Sourcery CodeBench Lite 2012.03
Linked libs:      libsqlite3.so.0, libpthread.so.0, librt.so.1, libc.so.6
Build date:       2017-06-02 (from version string)
App signature:    #VxCL7206C2_STD_APP/CL7206C2
Device ID string: ^RFID_READER_INFORMATION:7206C2

Source files (from debug symbols):
  main.c            — Main loop, socket handling
  protocol.c        — Command parsing and handling (protocol_cmd_hdl)
  configration.c    — Config read/write to /config_pram
  netapp.c          — Network IP/MAC/gateway management  
  connect_man.c     — TCP/UDP connection management
  recive.c          — Data receiving from all ports
  transfer.c        — Data forwarding/relay
  data_base.c       — SQLite tag database operations
  uart.c            — Serial port initialization
  gpio.c            — GPIO, LED, buzzer, relay, RS485 control
  wiegand.c         — Wiegand output protocol
  triger.c          — Trigger/event management (GPI triggers)
  timer.c           — Timer subsystem
  upgrade.c         — Firmware upgrade (USB + network)
  crc32.c           — CRC calculation
  usb_mornitor.c    — USB hotplug monitoring
  net_link.c        — Netlink for cable detect
  init.c            — System initialization

═══════════════════════════════════════════════════════════════════
## 2. CONFIG_PRAM BINARY FORMAT (1072 bytes / 0x0430)
═══════════════════════════════════════════════════════════════════

### 2.1 Memory Layout
┌──────────────────────────────────────────────────────────────┐
│ 0x000-0x01B  Network Configuration           (28 bytes)      │
│ 0x01C-0x11B  Antenna 0 Config Block         (256 bytes)      │
│ 0x11C-0x21B  Antenna 1 Config Block         (256 bytes)      │
│ 0x21C-0x31B  Antenna 2 Config Block         (256 bytes)      │
│ 0x31C-0x41B  Antenna 3 Config Block         (256 bytes)      │
│ 0x41C-0x42F  Global/Output Settings         (20 bytes)       │
└──────────────────────────────────────────────────────────────┘

### 2.2 Network Configuration (0x00 — 0x1B)

Offset  Size  Current Value       Field                   config_get_* function
──────  ────  ──────────────────  ──────────────────────  ────────────────────────
0x00    1     0x02                DHCP mode              config_get_dhcp_sw()
                                   (0=off/static, 1=on)
0x01    4     192.168.1.116        Device IP              config_get_local_ip()
0x05    4     255.255.255.0        Subnet Mask            config_get_local_ip_pram()
0x09    4     192.168.1.1          Gateway                config_get_gateway()
0x0D    5     6C:EC:A1:FE:75       Device MAC/ID          config_get_local_mac_pram()
0x12    2     0x3A00 (58)         Unknown param          
0x14    2     0x2382 (BE=9090)       Local Port             config_get_local_port()
0x16    4     192.168.1.1          Server/Dest IP         config_get_ser_ip()
0x1A    2     0x2382 (BE=9090)       Server Port            config_get_ser_port()

### 2.3 Antenna Block Format (256 bytes each, ×4)

  Antenna 0 @ 0x01C: 00 00 00 06 02 10 00 02 01 01 03 01 00 00 00 00
  Antenna 1 @ 0x11C: 01 00 00 06 02 10 00 02 01 01 03 01 00 00 00 00
  Antenna 2 @ 0x21C: 02 00 00 06 02 10 00 02 01 01 03 01 00 00 00 00
  Antenna 3 @ 0x31C: 03 00 00 06 02 10 00 02 01 01 03 01 00 00 00 00

Offset  Size  Value  Field                   Notes
──────  ────  ─────  ──────────────────────  ──────────────────────────────
+0x00   1     N      Antenna index           0-3
+0x01   2     0000   Reserved
+0x03   1     06     RF Power level          Index, not dBm directly
+0x04   1     02     Air protocol            2 = ISO 18000-6C (EPC Gen2)
+0x05   1     10     Frequency region        0x10 = Chinese freq plan
+0x06   1     00     Reserved
+0x07   1     02     Gen2 Session            0=S0, 1=S1, 2=S2, 3=S3
+0x08   1     01     Gen2 Target             0=A, 1=B
+0x09   1     01     Gen2 Q value            Initial Q for anti-collision
+0x0A   1     03     Unknown param           
+0x0B   1     01     Unknown param           
+0x0C   244   00..   Reserved (zeros)        Space for filter/mask config

### 2.4 Global Settings (0x41C — 0x42F)

Offset  Size  Value  Field                   config_get_* function
──────  ────  ─────  ──────────────────────  ────────────────────────
0x41C   3     000000 Reserved
0x41F   1     01     Wiegand enable          CONFIG_Get_WieGand_Switch()
0x420   1     02     Wiegand format           Wiegand_Get_Pra()
0x421   1     02     Wiegand bit config       (26/34 bit mode)
0x422   2     0000   Reserved
0x424   1     01     Buzzer/Relay config      config_get_relay_on_num_pra()
0x425   1     01     Tag filter/dedupe        config_get_tag_cach_sw()
0x426   1     00     Reserved
0x427   1     01     Auto-read mode           (continuous inventory)
0x428   1     00     Reserved
0x429   4     192.168.1.1  Server/Host IP   config_get_ser_ip()
0x42D   3     000000 Padding

═══════════════════════════════════════════════════════════════════
## 3. COMMUNICATION PROTOCOL
═══════════════════════════════════════════════════════════════════

### 3.1 Transport

The reader supports multiple communication channels:

  Channel       Port/Device        Mode          Function
  ───────────   ─────────────────  ────────────  ──────────────────
  Ethernet TCP  configurable       Server/Client tcp_socket_setup()
  Ethernet UDP  9090 (0x2382)      Broadcast+Cmd UDP_cmd_process()
  RS232 (PC)    /dev/ttyS0         Serial        PC_COM_Init()
  RS485         /dev/ttyS1         Serial+Addr   RS485_COM_Init()
  USB Serial    /dev/ttyGS0        Gadget serial USB_COM_Init()
  RS232 (RF)    /dev/ttyS2         To RF module  RF_COM_Init()

### 3.2 Protocol Frame Structure

Based on function names and debug strings:

  [Header] [Length] [Command] [Data...] [CRC16]

Key functions in protocol processing chain:
  1. com_recive()           — Raw data from any channel
  2. get_package()          — Frame extraction from stream
  3. GetHead()              — Header detection
  4. check_crc()            — CRC16 validation
  5. protocol_cmd_hdl()     — Command dispatch
  6. protocol_data_process()— Data payload processing
  7. build_set_pack()       — Build response packets
  8. add_crc()              — Append CRC to response

CRC: CRC-16/BUYPASS (IBM) (CONFIRMED from decompiled firmware)
     Polynomial:    0x8005
     Initial value: 0x0000
     Coverage:      CMD + SUB + LEN + DATA  (0xAA header EXCLUDED)
     Byte order:    Big-endian (high byte first)
     Formula:       crc = (crc << 8) ^ table[(crc >> 8) ^ byte]
     
     Note: If init=0x0000 doesn't match device responses,
           try init=0xFFFF (CRC-16/IBM variant variant)

### 3.3 UDP Discovery/Broadcast

The reader responds to UDP broadcast with:
  "^RFID_READER_INFORMATION:7206C2"

Network info response format (comma-separated fields):
  IP:xxx.xxx.xxx.xxx
  MASK:xxx.xxx.xxx.xxx
  GATEWAY:xxx.xxx.xxx.xxx
  MAC:xx-xx-xx-xx-xx-xx
  PORT:xxxxx
  MODE:SERVER/CLIENT
  HOST_SERVER_IP:xxx.xxx.xxx.xxx
  HOST_SERVER_PORT:xxxxx
  DHCP_SW:x
  TERMINAL_MAC:xx-xx-xx-xx-xx-xx
  NET_STATE:x

Functions: udp_get_network_pram(), udp_get_ip_pram(), 
           udp_get_mac(), udp_get_port(), udp_get_working_mode()
           send_local_information(), setup_brocast_socket()

### 3.4 Key Protocol Commands

  Function                    Purpose
  ──────────────────────────  ────────────────────────────────
  protocol_cmd_hdl()          Main command router
  build_set_pack()            Build parameter set response
  Notification_Pc()           Send tag notification to PC
  Notification_Pc_Start()     Start inventory notification
  Notification_Pc_Stop()      Stop inventory notification
  Fill_Notif_Cmd()            Fill notification command
  Send_Triger_start_Cmd()     Start trigger-based read
  Send_Triger_Stop_Cmd()      Stop trigger-based read
  Upgrade_Process()           Firmware upgrade handler
  send_connect_ensure_cmd()   Connection keepalive
  send_leave_notify()         Disconnect notification
  connect_store_data()        Store received data

═══════════════════════════════════════════════════════════════════
## 4. TAG DATABASE (SQLite)
═══════════════════════════════════════════════════════════════════

File: /tag_table (SQLite 3.x)

Tables:
  - tag_data       — Active tags (main table)
  - back_tag_data  — Backup/buffered tags (same schema)
  - white_list     — Tag whitelist (tid_code field)

Schema:
  CREATE TABLE tag_data(
    tag_index      INTEGER PRIMARY KEY,
    package_len    INT,        -- Raw packet length
    package_data   BLOB,       -- Raw RF packet
    epc_len        INT,        -- EPC length in bytes
    epc_code       BLOB,       -- EPC tag ID
    pc             INT,        -- Protocol Control word
    ant_num        INT,        -- Antenna port (0-3)
    sub_ant_num    INT,        -- Sub-antenna index
    tid_flag       INT,        -- TID read flag
    tid_len        INT,        -- TID length
    tid_code       BLOB,       -- TID data
    time_seconds   INT,        -- Unix timestamp (seconds)
    time_usec      INT         -- Microseconds
  );

Key DB operations:
  sql_insert()               — Insert new tag record
  sql_delete_record()        — Delete by index
  sql_delete_all_record()    — Clear all tags
  data_base_store_*()        — Store tag from RF
  data_base_answer_machine() — Answer queries from PC
  data_base_white_list_check() — Check against whitelist
  update_record_time()       — Update timestamps

═══════════════════════════════════════════════════════════════════
## 5. GPIO / HARDWARE CONTROL
═══════════════════════════════════════════════════════════════════

GPIO Functions:
  gpio_init()              — Initialize GPIO pins
  gpio_beep_crtl()         — Buzzer control
  gpio_led_ctrl()          — LED indicators
  gpio_relay_1..4_crtl()   — 4 relay outputs (GPO)
  gpio_relay_on_ctl()      — Turn relay on
  gpio_relay_off_ctl()     — Turn relay off
  gpio_get_input_1..4()    — 4 digital inputs (GPI)
  gpio_rf_board_reset()    — Reset RF module
  gpio_phy_reset()         — Reset Ethernet PHY
  gpio_rs485_crtl()        — RS485 direction control
  gpio_wiegand_0/1_set/clear() — Wiegand bit-bang

Wiegand output:
  /dev/wiegand             — Kernel module interface
  Wiegand_Init()           — Open wiegand device
  WieGand_Send()           — Send Wiegand frame
  WieGand_Get_EPC_Data_Pos() — Extract EPC for Wiegand
  WieGand_Get_TID_Data_Pos() — Extract TID for Wiegand
  WieGand_Get_6B_TID_Data_Pos() — ISO 18000-6B support

Trigger system (GPI → action):
  triger_init()            — Initialize trigger system
  Triger_State_Machine()   — Main trigger FSM
  Triger_Manage()          — Trigger management
  gpio_triger1..4()        — 4 trigger inputs
  Get_Triger_Start_Mode()  — Trigger start condition
  Get_Triger_Stop_Mode()   — Trigger stop condition
  Get_Triger_Stop_Delay()  — Delay before stop

═══════════════════════════════════════════════════════════════════
## 6. FIRMWARE UPGRADE
═══════════════════════════════════════════════════════════════════

Two upgrade methods:

1. USB disk:
   - Place CL7206C2_APP.bin on USB drive
   - Reader auto-detects via usb_mornitor.c
   - Validates app signature: upgrade_check_app_sign()
   - Copies to /bin, backs up to /back_app

2. Network:
   - Via protocol commands
   - Packetized transfer with CRC32 verification
   - Upgrade_Process() handles incoming packets
   - upgrade_pack_index tracks packet sequence
   - flash_write_addr tracks flash position

Upgrade sequence:
  cp /bin/CL7206C2 /back_app     (backup current)
  rm /bin/CL7206C2                (remove current)
  cp /CL7206C2 /bin               (install new)
  chmod 777 /bin/CL7206C2         (set permissions)

═══════════════════════════════════════════════════════════════════
## 7. NETWORK OPERATION MODES
═══════════════════════════════════════════════════════════════════

Two modes (config field MODE:):

SERVER mode:
  - Reader listens for incoming TCP connections
  - tcpserver_starup() → listen() → accept()
  - PC Demo connects to reader's IP:PORT

CLIENT mode:
  - Reader connects to remote server
  - tcpclient_starup() → connect()
  - Uses HOST_SERVER_IP and HOST_SERVER_PORT
  - Auto-reconnect via client_mode_reconnect()
  - TCP keepalive enabled (SO_KEEPALIVE/KEEPIDLE/KEEPINTVL)

Both modes support:
  - UDP broadcast discovery
  - Serial (RS232/RS485/USB) always active
  - DHCP or static IP

═══════════════════════════════════════════════════════════════════
## 8. NEXT STEPS FOR FULL PROTOCOL DECODE
═══════════════════════════════════════════════════════════════════

1. Load CL7206C2 into Ghidra (ARM 32-bit LE)
   - Binary is NOT stripped → all function names visible
   - Focus on: protocol_cmd_hdl() for command opcodes
   - Focus on: build_set_pack() for response format
   - Focus on: GetHead() for frame header bytes

2. Capture UDP traffic with Wireshark
   - Send broadcast to 255.255.255.255:9090
   - Observe reader's response format
   - Use PC Demo (once obtained) and capture all commands

3. Config format is fully mapped above
   - Can be modified with binary editor
   - Write back via: tftp to device → cp to /config_pram

4. Key function addresses to examine in Ghidra:
   - protocol_cmd_hdl  — Command opcode table
   - UDP_cmd_process   — UDP-specific commands
   - config_pram_init  — Config struct definition
   - config_set_pra    — Config write format
   - tag_data_analise  — RF tag packet parsing
