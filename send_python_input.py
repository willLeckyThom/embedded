from bleak import BleakClient
import asyncio

address = "34:98:7A:68:FB:FA" # target BLE MAC
char_uuid = "beb5483e-36e1-4688-b7f5-ea07361b26a8"  # writable characteristic UUID
payload_on  = bytes.fromhex("010e08000400040012100001")
payload_off = bytes.fromhex("000e08000400040012100000")

async def send_and_receive():
    async with BleakClient(address) as client:
        # Write the payload
        await client.write_gatt_char(char_uuid, payload_on)
        print("Payload sent!")

        # Optional: read response (if characteristic supports notify or read)
        response = await client.read_gatt_char(char_uuid)
        print("Response:", response.hex())
        
        await client.write_gatt_char(char_uuid, payload_off)
        print("Payload sent!")

        # Optional: read response (if characteristic supports notify or read)
        response = await client.read_gatt_char(char_uuid)
        print("Response:", response.hex())

asyncio.run(send_and_receive())

