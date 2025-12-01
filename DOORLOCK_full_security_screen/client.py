#!/usr/bin/env python3
"""
DOORLOCK Client.

Sends authenticated door open requests to the ESP32.

Send Packet:
- Message: [4 bytes counter (little-endian)][32 bytes HMAC-SHA256] = 36Bytes
- HMAC = HMAC-SHA256(shared_secret, counter_bytes)

Requirements:
    pip install bleak
"""

import asyncio
import hashlib
import hmac
import json
import os
import sys

from bleak import BleakClient, BleakScanner

# BLE Configuration
DEVICE_NAME = "DOORLOCK"
SERVICE_UUID = "4fafc201-1fb5-459e-8fcc-c5c9c331914b"
CHARACTERISTIC_UUID = "beb5483e-36e1-4688-b7f5-ea07361b26a8"

# Shared secret (hardcoded for simplicity)
SHARED_SECRET = bytes(
    [
        0x2B,
        0x7E,
        0x15,
        0x16,
        0x28,
        0xAE,
        0xD2,
        0xA6,
        0xAB,
        0xF7,
        0x97,
        0x75,
        0x46,
        0xCF,
        0x34,
        0xE5,
        0x89,
        0x32,
        0x4B,
        0x6C,
        0x12,
        0x93,
        0x5D,
        0x8F,
        0xA9,
        0x78,
        0xBC,
        0x3E,
        0x6F,
        0x21,
        0x45,
        0xD1,
    ]
)

# Counter storage file
COUNTER_FILE = "doorlock_counter.json"


class DoorLockClient:
    def __init__(self):
        self.counter = self.load_counter()
        self.device_address = None

    def load_counter(self):
        if os.path.exists(COUNTER_FILE):
            try:
                with open(COUNTER_FILE, "r") as f:
                    data = json.load(f)
                    counter = data.get("counter", 0)
                    print(f"[INFO] Loaded counter from file: {counter}")
                    return counter
            except Exception as e:
                print(f"[WARNING] Failed to load counter: {e}")
                return 0
        else:
            print("[INFO] No counter file found, starting from 0")
            return 0

    def save_counter(self):
        try:
            with open(COUNTER_FILE, "w") as f:
                json.dump({"counter": self.counter}, f)
            print(f"[INFO] Counter saved: {self.counter}")
        except Exception as e:
            print(f"[ERROR] Failed to save counter: {e}")

    def increment_counter(self):
        self.counter += 1
        self.save_counter()

    def decrement_counter(self):
        self.counter -= 1
        self.save_counter()

    def generate_message(self):
        """
        Generate authenticated message: [counter][HMAC]

        Returns:
            bytes: 36-byte message (4 bytes counter + 32 bytes HMAC)
        """
        counter_bytes = self.counter.to_bytes(4, byteorder="little")
        hmac_value = hmac.new(SHARED_SECRET, counter_bytes, hashlib.sha256).digest()
        message = counter_bytes + hmac_value

        print(f"[INFO] Generated message:")
        print(f"  Counter: {self.counter}")
        print(f"  Counter bytes (hex): {counter_bytes.hex()}")
        print(f"  HMAC (hex): {hmac_value.hex()}")
        print(f"  Full message (hex): {message.hex()}")
        print(f"  Message length: {len(message)} bytes")

        return message

    async def scan_for_device(self, timeout=10):
        print(f"[INFO] Scanning for '{DEVICE_NAME}' device...")

        devices = await BleakScanner.discover(timeout=timeout)

        for device in devices:
            if device.name == DEVICE_NAME:
                print(f"[SUCCESS] Found {DEVICE_NAME} at address: {device.address}")
                self.device_address = device.address
                return device.address

        print(f"[ERROR] Device '{DEVICE_NAME}' not found")
        return None

    async def send_door_open_request(self):
        if not self.device_address:
            print("[ERROR] Device address not set. Run scan_for_device() first.")
            return False

        print(f"\n[INFO] Connecting to {self.device_address}...")

        try:
            async with BleakClient(self.device_address) as client:
                print(f"[SUCCESS] Connected to {DEVICE_NAME}")
                is_paired = await client.pair()
                if is_paired:
                    print("[INFO] Device pairing successful")
                else:
                    print("[INFO] Using existing pairing")

                self.increment_counter()
                message = self.generate_message()

                print(f"\n[INFO] Sending door open request...")
                await client.write_gatt_char(
                    CHARACTERISTIC_UUID, message, response=True
                )

                print("[SUCCESS] Door open request sent!")

                # Waits for response
                await asyncio.sleep(1)

                # Try to read response
                try:
                    response = await client.read_gatt_char(CHARACTERISTIC_UUID)
                    response_str = response.decode("utf-8", errors="ignore")
                    print(f"[RESPONSE] ESP32 says: {response_str}")
                except Exception as e:
                    print(f"[INFO] Could not read response: {e}")
                return True

        except Exception as e:
            print(f"[ERROR] Failed to communicate with device: {e}")
            print("[INFO] Rolling back counter due to failure...")
            self.decrement_counter()
            self.save_counter()
            return False


async def main():
    """Main entry point"""
    print("=" * 60)
    print("  DOORLOCK Client - HMAC-Authenticated Rolling Code")
    print("=" * 60)

    client = DoorLockClient()
    address = await client.scan_for_device(timeout=10)
    if not address:
        print("\n[ERROR] Could not find DOORLOCK device")
        sys.exit(1)

    print("\n" + "=" * 60)
    success = await client.send_door_open_request()

    if success:
        print("\n" + "=" * 60)
        print("[V] Door open request completed successfully!")
        print("=" * 60)
    else:
        print("\n" + "=" * 60)
        print("[X] Failed to open door")
        print("=" * 60)
        sys.exit(1)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[INFO] Interrupted by user")
        sys.exit(0)
