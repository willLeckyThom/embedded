# ESP32 BLE DoorLock Security Prototype

## Overview
BLE-controlled door lock built on ESP32 (NimBLE stack) for ELEC-H550 Embedded System Security. The project evaluates how attackers could remotely open the lock and which countermeasures stop them. We iterate from an insecure baseline to a hardened rolling-code design, and capture BLE traffic (encrypted/unencrypted) for analysis.

## Repository Layout
- `DOORLOCK_no_security/` — baseline NimBLE server with no security requirements; single-byte commands toggle an LED as the door actuator.
- `DOORLOCK_security_no_screen/` — requires encryption/MITM with a static passkey, tracks failed attempts, and bans MACs for 5 minutes after 3 failures.
- `DOORLOCK_full_security_screen/` — bonded + MITM-protected server that enforces an HMAC-SHA256 rolling code; includes a Python client.
- `sketch_oct28a/` — early exploration sketch kept for reference.
- `sniffing_*.pcapng` — BLE traffic captures (no security, no security with PIN prompt, and secured).

## Firmware Variants
- `DOORLOCK_no_security/sketch_nov22a.ino`: no bonding/mitm/encryption; characteristic supports read/write/notify. Command `0x01` opens the door (LED on) and then the latch closes after 3 seconds. Useful to demonstrate trivial replay/spoofing.
- `DOORLOCK_security_no_screen/sketch_nov22c.ino`: static passkey `123456`, bonding + MITM, encryption required on read/write. Tracks failed authentications per MAC; after 3 failures the MAC is banned for 5 minutes. Simple on/off command handler once encrypted.
- `DOORLOCK_full_security_screen/sketch_nov22b.ino`: full stack security plus rolling code:
  - Bonding, MITM, encrypted read/write; numeric comparison pairing flow.
  - Rolling code: 4-byte little-endian counter + 32-byte HMAC-SHA256(shared_secret, counter); message size 36 bytes.
  - Counter persisted in flash (`Preferences`), rejects replays, enforces a sliding window (`COUNTER_WINDOW` = 100) to handle out-of-order packets.
  - Constant-time HMAC verification; successful writes open the door for 3 seconds via GPIO 27.

## Python Client (rolling-code demo)
- Location: `DOORLOCK_full_security_screen/client.py`
- Dependencies: Python 3, `pip install bleak`
- Behavior: scans for `DOORLOCK`, pairs if needed, increments a local counter (`doorlock_counter.json`), builds `[counter][HMAC]`, writes to the characteristic, and reads the response. Counter rolls back on failure to avoid desync.
- Run: `python DOORLOCK_full_security_screen/client.py`

## Rolling-Code Protocol (security build)
- Message: `[4B counter (LE)][32B HMAC-SHA256]`
- Verification: device recomputes HMAC on the counter and compares in constant time.
- Anti-replay: rejects stale counters and counters beyond the acceptance window; persists the last valid counter across reboots.

## Threat Model & Research Focus
- Goal: identify/mitigate ways an attacker could remotely open the lock (replay, spoofing, brute forcing, pairing abuse).
- Assets: door actuator GPIO, BLE credentials/keys, rolling-code state.
- Adversaries: nearby BLE attackers with sniffing/injection capability, potentially able to prompt pairing or replay captures.
- Countermeasures implemented: encrypted + MITM-protected pairing, static-passkey lockout/banning, rolling-code with HMAC, replay window checks, constant-time MAC comparison, stored counters.
- Open analysis tasks: evaluate metadata leakage in encrypted mode, validate rolling-code robustness, and map captures to observed attacks.

## Captures
- `sniffing_no_security.pcapng`: traffic when the insecure firmware is used.
- `sniffing_no_security_pin.pcapng`: traffic with pairing prompt but minimal protections.
- `sniffing_security.pcapng`: traffic for the secured build.
