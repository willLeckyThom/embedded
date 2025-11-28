/**
 * DOORLOCK - NimBLE Server with Secure Read/Write and Rolling Code
 *
 * Security Features:
 * - BLE bonding, MITM protection, and encrypted read/write
 * - Rolling code mechanism to prevent replay attacks
 *
 * Rolling Code Protocol:
 * - Command format: [1 byte command][4 bytes counter (little-endian)]
 * - Counter must increment with each command
 * - Counter is persisted in flash memory across reboots
 * - Commands with old/replayed counters are rejected
 * - Accepts counters within a window (default: 100) to handle out-of-order packets
 *
 * Client Implementation Example:
 *   uint32_t counter = <get_from_storage>();
 *   counter++;
 *   uint8_t cmd[5] = {0x01, counter & 0xFF, (counter >> 8) & 0xFF,
 *                     (counter >> 16) & 0xFF, (counter >> 24) & 0xFF};
 *   characteristic.writeValue(cmd, 5);
 *   <save_counter_to_storage>(counter);
 */

#include <Arduino.h>
#include <NimBLEDevice.h>
#include <Preferences.h>

#define SERVICE_UUID        "4fafc201-1fb5-459e-8fcc-c5c9c331914b"
#define CHARACTERISTIC_UUID "beb5483e-36e1-4688-b7f5-ea07361b26a8"
#define DEVICE_NAME         "DOORLOCK"
#define LED_PIN             27

// Rolling code configuration
#define COUNTER_WINDOW      100  // Accept counters within this window ahead of expected
#define COUNTER_NAMESPACE   "doorlock"
#define COUNTER_KEY         "counter"

static NimBLEServer* pServer = nullptr;
static NimBLECharacteristic* pDoorChr = nullptr;
static Preferences preferences;
static uint32_t expectedCounter = 0;

/** ---------------------------
 *  Server callbacks
 *  --------------------------- */
class ServerCallbacks : public NimBLEServerCallbacks {
    void onConnect(NimBLEServer* pServerInst, NimBLEConnInfo& connInfo) override {
        Serial.printf("Client connected: %s (handle %u)\n",
                      connInfo.getAddress().toString().c_str(),
                      connInfo.getConnHandle());
        pServerInst->updateConnParams(connInfo.getConnHandle(), 24, 48, 0, 180);
    }

    void onDisconnect(NimBLEServer* pServerInst, NimBLEConnInfo& connInfo, int reason) override {
        Serial.printf("Client disconnected: %s - reason %d\n",
                      connInfo.getAddress().toString().c_str(), reason);
        NimBLEDevice::startAdvertising();
    }

    void onMTUChange(uint16_t MTU, NimBLEConnInfo& connInfo) override {
        Serial.printf("MTU updated: %u for handle %u\n", MTU, connInfo.getConnHandle());
    }

    /** Security callbacks */
    uint32_t onPassKeyDisplay() override {
        Serial.println("Server Passkey Display (static 123456 for demo)");
        return 123456; // in production, generate random passkey
    }

    void onConfirmPassKey(NimBLEConnInfo& connInfo, uint32_t pass_key) override {
        Serial.printf("Confirm Passkey %u for %s\n", pass_key, connInfo.getAddress().toString().c_str());
        NimBLEDevice::injectConfirmPasskey(connInfo, true);
    }

    void onAuthenticationComplete(NimBLEConnInfo& connInfo) override {
        if (!connInfo.isEncrypted()) {
            Serial.printf("Connection to %s completed WITHOUT encryption!\n", connInfo.getAddress().toString().c_str());
        } else {
            Serial.printf("Secured connection to: %s\n", connInfo.getAddress().toString().c_str());
        }
    }
} serverCallbacks;

/** ---------------------------
 *  Rolling Code Functions
 *  --------------------------- */
bool validateAndUpdateCounter(uint32_t receivedCounter) {
    if (receivedCounter <= expectedCounter) {
        Serial.printf(">>> REPLAY ATTACK DETECTED: received %u, expected > %u <<<\n",
                     receivedCounter, expectedCounter);
        return false;
    }

    // Check if counter is within acceptable window (prevents desync)
    if (receivedCounter > expectedCounter + COUNTER_WINDOW) {
        Serial.printf(">>> COUNTER OUT OF WINDOW: received %u, expected %u-%u <<<\n",
                     receivedCounter, expectedCounter + 1, expectedCounter + COUNTER_WINDOW);
        return false;
    }

    // Valid counter - update expected and persist
    expectedCounter = receivedCounter;
    preferences.begin(COUNTER_NAMESPACE, false);
    preferences.putUInt(COUNTER_KEY, expectedCounter);
    preferences.end();

    Serial.printf(">>> Counter validated: %u <<<\n", receivedCounter);
    return true;
}

/** ---------------------------
 *  Characteristic callbacks
 *  --------------------------- */
class DoorCharacteristicCallbacks : public NimBLECharacteristicCallbacks {
    void onRead(NimBLECharacteristic* pCharacteristic, NimBLEConnInfo& connInfo) override {
        if (!connInfo.isEncrypted()) {
            Serial.println("Rejecting read: connection not encrypted!");
            pCharacteristic->setValue("ENCRYPTION REQUIRED");
            return;
        }
        Serial.printf("Read request from %s: %s\n",
                      connInfo.getAddress().toString().c_str(),
                      pCharacteristic->getValue().c_str());
    }

    void onWrite(NimBLECharacteristic* pCharacteristic, NimBLEConnInfo& connInfo) override {
        if (!connInfo.isEncrypted()) {
            Serial.println("Rejecting write: connection not encrypted!");
            return;
        }

        const std::string &val = pCharacteristic->getValue();
        Serial.printf("Write request from %s, length %d, value (hex): ",
                      connInfo.getAddress().toString().c_str(), (int)val.length());
        for (size_t i = 0; i < val.length(); ++i) Serial.printf("%02X ", (uint8_t)val[i]);
        Serial.println();

        // Command format: [1 byte cmd][4 bytes counter (little-endian)]
        if (val.length() != 5) {
            Serial.printf(">>> INVALID LENGTH: expected 5 bytes, got %d <<<\n", (int)val.length());
            return;
        }

        uint8_t cmd = (uint8_t)val[0];

        // Extract counter (little-endian)
        uint32_t receivedCounter = ((uint32_t)(uint8_t)val[1])       |
                                   ((uint32_t)(uint8_t)val[2] << 8)  |
                                   ((uint32_t)(uint8_t)val[3] << 16) |
                                   ((uint32_t)(uint8_t)val[4] << 24);

        // Validate rolling code
        if (!validateAndUpdateCounter(receivedCounter)) {
            Serial.println(">>> COMMAND REJECTED: Invalid counter <<<");
            return;
        }

        // Execute command if counter is valid
        if (cmd == 0x01) {
            digitalWrite(LED_PIN, HIGH);
            Serial.println(">>> LED turned ON <<<");
            pCharacteristic->setValue("ON");
            pCharacteristic->notify(true);
            delay(1000);
            digitalWrite(LED_PIN, LOW);
        } else if (cmd == 0x00) {
            digitalWrite(LED_PIN, LOW);
            Serial.println(">>> LED turned OFF <<<");
            pCharacteristic->setValue("OFF");
            pCharacteristic->notify(true);
        } else {
            Serial.printf(">>> UNKNOWN command: 0x%02X <<<\n", cmd);
        }
    }

    void onStatus(NimBLECharacteristic* pCharacteristic, int code) override {
        Serial.printf("Notification/Indication return code: %d, %s\n",
                      code, NimBLEUtils::returnCodeToString(code));
    }

    void onSubscribe(NimBLECharacteristic* pCharacteristic, NimBLEConnInfo& connInfo, uint16_t subValue) override {
        String msg = "Client " + String(connInfo.getConnHandle()) + " " + connInfo.getAddress().toString().c_str();
        if (subValue == 0) msg += " unsubscribed from ";
        else if (subValue == 1) msg += " subscribed to notifications for ";
        else if (subValue == 2) msg += " subscribed to indications for ";
        else if (subValue == 3) msg += " subscribed to notifications and indications for ";
        msg += pCharacteristic->getUUID().toString().c_str();
        Serial.println(msg);
    }
} chrCallbacks;

/** ---------------------------
 *  Descriptor callbacks
 *  --------------------------- */
class DscCallbacks : public NimBLEDescriptorCallbacks {
    void onWrite(NimBLEDescriptor* pDescriptor, NimBLEConnInfo& connInfo) override {
        std::string dval = pDescriptor->getValue();
        Serial.printf("Descriptor %s written by %s, value: %s\n",
                      pDescriptor->getUUID().toString().c_str(),
                      connInfo.getAddress().toString().c_str(),
                      dval.c_str());
    }
    void onRead(NimBLEDescriptor* pDescriptor, NimBLEConnInfo& connInfo) override {
        Serial.printf("%s Descriptor read by %s\n",
                      pDescriptor->getUUID().toString().c_str(),
                      connInfo.getAddress().toString().c_str());
    }
} dscCallbacks;

/** ---------------------------
 *  Setup and loop
 *  --------------------------- */
void setup() {
    Serial.begin(115200);
    delay(500);
    Serial.println("\nStarting DOORLOCK NimBLE Server");

    pinMode(LED_PIN, OUTPUT);
    digitalWrite(LED_PIN, LOW);

    // Initialize rolling code counter from persistent storage
    preferences.begin(COUNTER_NAMESPACE, false);
    expectedCounter = preferences.getUInt(COUNTER_KEY, 0);
    preferences.end();
    Serial.printf("Rolling code initialized: expectedCounter = %u\n", expectedCounter);

    NimBLEDevice::init(DEVICE_NAME);

    // Enable security: bonding, MITM, encryption
    NimBLEDevice::setSecurityAuth(true, true, true); // bond, MITM, secure connection
    NimBLEDevice::setSecurityIOCap(BLE_HS_IO_DISPLAY_YESNO); // numeric comparison
    NimBLEDevice::setSecurityInitKey(BLE_SM_PAIR_KEY_DIST_ENC | BLE_SM_PAIR_KEY_DIST_ID);
    NimBLEDevice::setSecurityRespKey(BLE_SM_PAIR_KEY_DIST_ENC | BLE_SM_PAIR_KEY_DIST_ID);


    // Create server and assign callbacks
    pServer = NimBLEDevice::createServer();
    pServer->setCallbacks(&serverCallbacks);

    // Create service and characteristic
    NimBLEService* pService = pServer->createService(SERVICE_UUID);
    pDoorChr = pService->createCharacteristic(
        CHARACTERISTIC_UUID,
        NIMBLE_PROPERTY::READ |
        NIMBLE_PROPERTY::WRITE |
        NIMBLE_PROPERTY::WRITE_NR |
        NIMBLE_PROPERTY::NOTIFY |
        NIMBLE_PROPERTY::READ_ENC |   // require encryption for read
        NIMBLE_PROPERTY::WRITE_ENC     // require encryption for write
    );

    pDoorChr->setValue("OFF");
    pDoorChr->setCallbacks(&chrCallbacks);

    // Add 2904 descriptor
    NimBLE2904* p2904 = pDoorChr->create2904();
    p2904->setFormat(NimBLE2904::FORMAT_UTF8);
    p2904->setCallbacks(&dscCallbacks);

    // Add custom descriptor
    NimBLEDescriptor* pC01D = pDoorChr->createDescriptor("C01D", NIMBLE_PROPERTY::READ | NIMBLE_PROPERTY::WRITE, 20);
    pC01D->setValue("DoorLock Descriptor");
    pC01D->setCallbacks(&dscCallbacks);

    // Start service
    pService->start();

    // Start advertising
    NimBLEAdvertising* pAdvertising = NimBLEDevice::getAdvertising();
    pAdvertising->setName(DEVICE_NAME);
    pAdvertising->addServiceUUID(pService->getUUID());
    pAdvertising->enableScanResponse(true);
    pAdvertising->start();

    Serial.println("Advertising Started");
}

void loop() {
    delay(2000);
    if (pServer->getConnectedCount()) {
        pDoorChr->notify(true);
    }
}