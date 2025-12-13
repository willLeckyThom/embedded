#!/usr/bin/env python3
"""
DOORLOCK Client for NimBLE ESP32 server with HMAC-Authenticated Rolling Code + Bonding/MITM
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

# Shared secret (must match ESP32)
SHARED_SECRET = bytes([
    0x2B,0x7E,0x15,0x16,0x28,0xAE,0xD2,0xA6,
    0xAB,0xF7,0x97,0x75,0x46,0xCF,0x34,0xE5,
    0x89,0x32,0x4B,0x6C,0x12,0x93,0x5D,0x8F,
    0xA9,0x78,0xBC,0x3E,0x6F,0x21,0x45,0xD1
])

COUNTER_FILE = "doorlock_counter.json"


class DoorLockClient:
    def __init__(self):
        self.counter = self.load_counter()
        self.device_address = None

    def load_counter(self):
        if os.path.exists(COUNTER_FILE):
            try:
                with open(COUNTER_FILE, "r") as f:
                    return json.load(f).get("counter", 0)
            except:
                return 0
        return 0

    def save_counter(self):
        with open(COUNTER_FILE, "w") as f:
            json.dump({"counter": self.counter}, f)

    def increment_counter(self):
        self.counter += 1
        self.save_counter()

    def decrement_counter(self):
        self.counter -= 1
        self.save_counter()

    def generate_message(self):
        counter_bytes = self.counter.to_bytes(4, "little")
        hmac_value = hmac.new(SHARED_SECRET, counter_bytes, hashlib.sha256).digest()
        return counter_bytes + hmac_value  # 36 bytes

    async def scan_for_device(self, timeout=10):
        devices = await BleakScanner.discover(timeout=timeout)
        for d in devices:
            if d.name == DEVICE_NAME:
                self.device_address = d.address
                return d.address
        return None

    async def send_door_open_request(self):
        if not self.device_address:
            print("[ERROR] Device address not found")
            return False

        async with BleakClient(self.device_address) as client:
            print(f"[INFO] Connected to {self.device_address}")

            # Pair and ensure encrypted connection
            paired = await client.pair()
            if paired:
                print("[INFO] Paired successfully")
            else:
                print("[INFO] Already paired / using existing bond")

            # BLE requires some delay to ensure encryption is established
            await asyncio.sleep(0.5)

            self.increment_counter()
            message = self.generate_message()

            # Send HMAC-authenticated rolling code
            await client.write_gatt_char(CHARACTERISTIC_UUID, message, response=True)
            print(f"[INFO] Sent door open request (counter={self.counter})")

            # Read response if available (notification may be received asynchronously)
            try:
                response = await client.read_gatt_char(CHARACTERISTIC_UUID)
                print("[RESPONSE]", response.decode("utf-8", errors="ignore"))
            except Exception as e:
                print("[INFO] No immediate read response:", e)

            return True


async def main():
    client = DoorLockClient()
    address = await client.scan_for_device()
    if not address:
        print("[ERROR] DOORLOCK device not found")
        sys.exit(1)

    success = await client.send_door_open_request()
    if success:
        print("[SUCCESS] Door open request sent")
    else:
        print("[FAIL] Could not open door")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)
