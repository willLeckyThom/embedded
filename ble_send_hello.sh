#!/bin/bash
# BLE Script using bluetoothctl only
# Sends "hello" to ESP32 DOORLOCK via GATT, responds to pairing, then forgets device

DEVICE_NAME="DOORLOCK"
CHAR_PATH="/org/bluez/hci0/dev_34_98_7A_68_FB_FA/service000e/char000f"
DEVICE_MAC="34:98:7A:68:FB:FA"

echo "Restarting Bluetooth..."
sudo systemctl daemon-reload 2>/dev/null
sudo systemctl restart bluetooth
sleep 2

echo "Powering on adapter..."
bluetoothctl power on >/dev/null

echo "Scanning for BLE devices..."
bluetoothctl --timeout 10 scan on | grep "$DEVICE_NAME"

echo "Trusting device and initiating connection..."
# Start bluetoothctl in a subshell to handle pairing and connection
(
  echo "trust $DEVICE_MAC"
  echo "pair $DEVICE_MAC"
  # wait for pairing request
  sleep 2
  # respond with PIN 123456 if prompted
  echo "123456"
  echo "connect $DEVICE_MAC"

  # Wait until connected before proceeding
  sleep 5
  echo "menu gatt"
  echo "list-attributes"
  echo "select-attribute $CHAR_PATH"
  echo "notify on"
  sleep 1
  echo "write \"0x01\" 0 request"
  sleep 2
  echo "write \"0X00\" 0 request" 
  echo "back"
  echo "disconnect $DEVICE_MAC"
  sleep 3
  echo "remove $DEVICE_MAC"
  echo "exit"
) | bluetoothctl | tee ble_response.log

echo "Done. Notifications saved in ble_response.log"
