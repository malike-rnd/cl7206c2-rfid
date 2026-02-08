#!/usr/bin/env python3
"""
CL7206C2 Trigger System — Complete Analysis from Firmware
=========================================================

Decoded from: Triger_State_Machine(), Triger_Manage(), Send_Triger_start_Cmd(),
              Send_Triger_Stop_Cmd(), config_get_triger_pram(), Get_Triger_Stop_Mode(),
              Notification_Pc(), triger_delay_process()

## Architecture

The reader has 4 GPI (opto-isolated) inputs. Each GPI can be configured as a trigger
that automatically starts/stops RFID inventory when an external signal is detected.

    Triger_Manage() — called in main loop
        ↓
        for each GPI (0-3):
            config = config_get_triger_pram(gpi_index)    # from triger_pram[i]
            state  = triger_array[gpi_index]              # runtime state
            Triger_State_Machine(state, config, 0x100)
                ↓
                State 0: Read start_mode & stop_mode from config
                State 1: Check GPI event against start/stop modes
                State 2: START → Send_Triger_start_Cmd() + Notification_Pc_Start()
                State 3: STOP  → Send_Triger_Stop_Cmd()  + Notification_Pc_Stop()
                State 4: EXIT

## Trigger Config Structure (per GPI)

The config is a variable-length blob stored in memory:

    Offset  Size   Description
    ------  -----  -----------
    +0x00   1      GPI pin index (0-3)
    +0x01   1      Start trigger mode
    +0x02   2      RF command length (big-endian)
    +0x04   N      RF command data (the actual inventory start command)
    +0x04+N 1      Stop trigger mode

## Trigger Modes

    Value  Name              Description
    -----  ----------------  ------------------------------------------
    0      Disabled          No trigger on this condition
    1      Rising Edge       GPI LOW → HIGH transition
    2      Falling Edge      GPI HIGH → LOW transition
    3      Level HIGH        GPI is at HIGH level
    4      Level LOW         GPI is at LOW level
    5      Any Edge          Any change (matches both 3 and 4)
    6      Delay Timer       Stop after configurable delay (10ms units)

## Trigger State Machine

    ┌──────────────────────────────────────────────────────┐
    │  State 0: INIT                                       │
    │  Read start_mode (config+1)                          │
    │  Read stop_mode  (config+4+cmd_len)                  │
    │  If start_mode == 0 → State 4 (disabled)             │
    │  Else → State 1                                      │
    └───────────────────────┬──────────────────────────────┘
                            ↓
    ┌──────────────────────────────────────────────────────┐
    │  State 1: WAIT FOR EVENT                             │
    │  Read GPI event from state+4                         │
    │  If event == 0 → State 4 (no event)                  │
    │  Clear event (state+4 = 0)                           │
    │  If event matches start_mode → State 2               │
    │  If event matches stop_mode  → State 3               │
    │  Special: if event is 3 or 4 (level):                │
    │    start_mode 5 (any) → State 2                      │
    │    stop_mode 5 (any)  → State 3                      │
    │  If stop_mode==0 and never_stop_ntf:                 │
    │    event 1 or 2 → Notification_Pc_Stop()             │
    └──┬────────────────────────┬──────────────────────────┘
       ↓                        ↓
    ┌──────────────┐    ┌──────────────┐
    │  State 2:    │    │  State 3:    │
    │  START       │    │  STOP        │
    │  Notify PC   │    │  Notify PC   │
    │  Send RF cmd │    │  Send RF     │
    │  from config │    │  stop cmd    │
    │              │    │  (AA 02 FF)  │
    │  If stop=6:  │    │              │
    │  Start timer │    │              │
    └──────────────┘    └──────────────┘

## Trigger Runtime State Structure (triger_array entry)

    Offset  Size  Description
    ------  ----  -----------
    +0x00   4     Delay value (in 10ms units)
    +0x04   4     Current GPI event (1=rising, 2=falling, 3=high, 4=low)
    +0x08   4     (unknown)
    +0x0C   4     (unknown)
    +0x10   4     (unknown)
    +0x14   1     Timer active flag
    +0x18   4     (padding/alignment)

## Protocol Commands for Trigger Config

### SET Trigger Config (CMD=0x01, SUB=0x0B)

The trigger config is stored as part of the antenna/trigger config block (256 bytes per port).
Each RF port block at config_pram offset 0x1C + port*256 contains both antenna AND trigger params.

### GET Trigger Config (CMD=0x01, SUB=0x0C)

    TX: AA 01 0C 00 01 [gpi_index] [CRC16]
    RX: AA 01 0C [LEN] [config_data...] [CRC16]

## stop_triger_cmd (hardcoded at 0x0002bc90)

    AA 02 FF 00 00 A4 0F
    
    = Stop Inventory (CMD=0x02, SUB=0xFF, no data, CRC=0xA40F)

## Notification_Pc() — Trigger Event Notification

When a trigger fires, the reader sends a notification to PC:

    AA [cmd] [sub] 00 0E [gpi_pin] [start/stop] [gpi_level]
    [timestamp_sec(4B BE)] [timestamp_usec(4B BE)] [CRC16]

    Total: 17 bytes (0x0F data + header + CRC)

## triger_delay_process() — Timer-based Auto-Stop

    Delay value is in units of 10ms:
      tv_sec  = delay / 100    (integer seconds)
      tv_nsec = (delay % 100) * 10,000,000  (remainder as nanoseconds)
    
    Example: delay=150 → 1.5 seconds
    Example: delay=500 → 5.0 seconds
    Example: delay=50  → 0.5 seconds

## Practical Setup for Race Timing

### Button Start (Rising Edge):
    GPI-1 start_mode = 1 (rising edge)
    GPI-1 stop_mode  = 0 (manual stop) or 6 (timer stop)
    RF command = AA 02 10 (start inventory)
    
    Press button → GPI goes HIGH → inventory starts
    Release → no effect (stop_mode=0)

### Photocell Gate (Level-based):
    GPI-1 start_mode = 3 (level HIGH)  
    GPI-1 stop_mode  = 4 (level LOW)
    
    Beam broken (HIGH) → start reading
    Beam restored (LOW) → stop reading

### Timed Reading (Edge + Delay):
    GPI-1 start_mode = 1 (rising edge)
    GPI-1 stop_mode  = 6 (delay timer)
    Delay = 3000 (30 seconds)
    
    Button press → start inventory → auto-stop after 30s
"""

# ═══════════════════════════════════════════════════════════
# Trigger configuration builder
# ═══════════════════════════════════════════════════════════

TRIGGER_MODES = {
    'disabled':  0,
    'rising':    1,  # LOW → HIGH
    'falling':   2,  # HIGH → LOW
    'high':      3,  # Level HIGH
    'low':       4,  # Level LOW
    'any':       5,  # Any change
    'delay':     6,  # Timer-based stop
}

# Standard RF commands for trigger actions
RF_CMD_START_INVENTORY = bytes([0x02, 0x10, 0x00, 0x00])  # CMD=0x02 SUB=0x10 LEN=0
RF_CMD_STOP_INVENTORY  = bytes([0x02, 0xFF, 0x00, 0x00])  # CMD=0x02 SUB=0xFF LEN=0

def build_trigger_config(gpi_pin, start_mode, stop_mode, rf_command=None):
    """Build a trigger configuration blob.
    
    Args:
        gpi_pin:    0-3 (GPI input index)
        start_mode: 0-6 (trigger start condition)
        stop_mode:  0-6 (trigger stop condition)
        rf_command: bytes - RF command to execute on start (default: start inventory)
    
    Returns:
        bytes - trigger config blob
    """
    if rf_command is None:
        rf_command = RF_CMD_START_INVENTORY
    
    cmd_len = len(rf_command)
    
    config = bytearray()
    config.append(gpi_pin)                    # +0: GPI pin
    config.append(start_mode)                 # +1: start mode
    config.append((cmd_len >> 8) & 0xFF)      # +2: cmd length high
    config.append(cmd_len & 0xFF)             # +3: cmd length low
    config.extend(rf_command)                 # +4: RF command data
    config.append(stop_mode)                  # +4+N: stop mode
    
    return bytes(config)


def parse_trigger_config(data):
    """Parse a trigger configuration blob."""
    if len(data) < 5:
        return None
    
    MODE_NAMES = {0: 'Disabled', 1: 'Rising Edge', 2: 'Falling Edge',
                  3: 'Level HIGH', 4: 'Level LOW', 5: 'Any Edge', 6: 'Delay Timer'}
    
    gpi_pin = data[0]
    start_mode = data[1]
    cmd_len = (data[2] << 8) | data[3]
    
    if len(data) < 4 + cmd_len + 1:
        return {
            'gpi_pin': gpi_pin,
            'start_mode': start_mode,
            'start_mode_name': MODE_NAMES.get(start_mode, f'Unknown({start_mode})'),
            'cmd_len': cmd_len,
            'error': 'truncated'
        }
    
    rf_command = data[4:4+cmd_len]
    stop_mode = data[4+cmd_len]
    
    return {
        'gpi_pin': gpi_pin,
        'start_mode': start_mode,
        'start_mode_name': MODE_NAMES.get(start_mode, f'Unknown({start_mode})'),
        'cmd_len': cmd_len,
        'rf_command': rf_command.hex(),
        'stop_mode': stop_mode,
        'stop_mode_name': MODE_NAMES.get(stop_mode, f'Unknown({stop_mode})'),
    }


# ═══════════════════════════════════════════════════════════
# Example configurations for race timing
# ═══════════════════════════════════════════════════════════

if __name__ == '__main__':
    print("=" * 70)
    print("CL7206C2 TRIGGER SYSTEM — Configuration Examples")
    print("=" * 70)
    
    # Example 1: Button start, manual stop
    config1 = build_trigger_config(
        gpi_pin=0,
        start_mode=TRIGGER_MODES['rising'],
        stop_mode=TRIGGER_MODES['disabled'],
        rf_command=RF_CMD_START_INVENTORY
    )
    print(f"\n1. Button Start (GPI-1, rising edge, manual stop):")
    print(f"   Config bytes: {config1.hex()}")
    print(f"   Parsed: {parse_trigger_config(config1)}")
    
    # Example 2: Button start, timer auto-stop after 30s
    config2 = build_trigger_config(
        gpi_pin=0,
        start_mode=TRIGGER_MODES['rising'],
        stop_mode=TRIGGER_MODES['delay'],
    )
    print(f"\n2. Button Start + 30s Auto-Stop (GPI-1):")
    print(f"   Config bytes: {config2.hex()}")
    print(f"   Parsed: {parse_trigger_config(config2)}")
    
    # Example 3: Photocell gate
    config3 = build_trigger_config(
        gpi_pin=1,
        start_mode=TRIGGER_MODES['high'],
        stop_mode=TRIGGER_MODES['low'],
    )
    print(f"\n3. Photocell Gate (GPI-2, level-based):")
    print(f"   Config bytes: {config3.hex()}")
    print(f"   Parsed: {parse_trigger_config(config3)}")
    
    # Example 4: Start on falling (NC button), stop on rising
    config4 = build_trigger_config(
        gpi_pin=0,
        start_mode=TRIGGER_MODES['falling'],
        stop_mode=TRIGGER_MODES['rising'],
    )
    print(f"\n4. NC Button (GPI-1, falling=start, rising=stop):")
    print(f"   Config bytes: {config4.hex()}")
    print(f"   Parsed: {parse_trigger_config(config4)}")
    
    print(f"\n{'=' * 70}")
    print("VERIFIED CONSTANTS FROM FIRMWARE:")
    print(f"  stop_triger_cmd @ 0x0002bc90 = AA 02 FF 00 00 A4 0F")
    print(f"  triger_delay units = 10ms (delay/100=sec, delay%100*10M=nsec)")
    print(f"  Trigger modes: {TRIGGER_MODES}")
    print(f"{'=' * 70}")
