/**
 * DOORLOCK - NimBLE Server (based on NimBLE_Server demo)
 *
 * Uses server-style callbacks and signatures from H2zero's NimBLE_Server example.
 * - Supports passkey / confirm pairing hooks (just-works by default)
 * - Uses connection info inside callbacks
 * - Characteristic read/write, notify, CCCD handling
 */

#include <Arduino.h>
#include <NimBLEDevice.h>

#define SERVICE_UUID        "4fafc201-1fb5-459e-8fcc-c5c9c331914b"
#define CHARACTERISTIC_UUID "beb5483e-36e1-4688-b7f5-ea07361b26a8"
#define DEVICE_NAME         "DOORLOCK"
#define LOCK_PIN             27

static NimBLEServer* pServer = nullptr;
static NimBLECharacteristic* pDoorChr = nullptr;

/** ---------------------------
 *  Server callbacks
 *  --------------------------- */
class ServerCallbacks : public NimBLEServerCallbacks {
    void onConnect(NimBLEServer* pServerInst, NimBLEConnInfo& connInfo) override {
        Serial.printf("Client address: %s (conn handle %u)\n",
                      connInfo.getAddress().toString().c_str(),
                      connInfo.getConnHandle());

        // Optionally update connection params (units of 1.25ms)
        pServerInst->updateConnParams(connInfo.getConnHandle(), 24, 48, 0, 180);
    }

    void onDisconnect(NimBLEServer* pServerInst, NimBLEConnInfo& connInfo, int reason) override {
        Serial.printf("Client disconnected (addr %s) - reason %d - start advertising\n",
                      connInfo.getAddress().toString().c_str(), reason);
        // Restart advertising
        NimBLEDevice::startAdvertising();
    }

    void onMTUChange(uint16_t MTU, NimBLEConnInfo& connInfo) override {
        Serial.printf("MTU updated: %u for connection ID: %u\n", MTU, connInfo.getConnHandle());
    }

    /********************* Security handled here *********************/
    uint32_t onPassKeyDisplay() override {
        Serial.printf("Server Passkey Display (returning static 15)\n");
        // In production you would generate a random 6-digit passkey
        return 15;
    }

    void onConfirmPassKey(NimBLEConnInfo& connInfo, uint32_t pass_key) override {
        Serial.printf("Confirm Passkey %u for %s\n", pass_key, connInfo.getAddress().toString().c_str());
        // Accept passkey
        NimBLEDevice::injectConfirmPasskey(connInfo, true);
    }

    void onAuthenticationComplete(NimBLEConnInfo& connInfo) override {
    if (!connInfo.isEncrypted()) {
        Serial.printf("Connection to %s completed WITHOUT encryption (testing mode).\n", connInfo.getAddress().toString().c_str());
    } else {
        Serial.printf("Secured connection to: %s\n", connInfo.getAddress().toString().c_str());
    }
}

} serverCallbacks;

/** ---------------------------
 *  Characteristic callbacks (from NimBLE_Server demo)
 *  --------------------------- */
class DoorCharacteristicCallbacks : public NimBLECharacteristicCallbacks {
    void onRead(NimBLECharacteristic* pCharacteristic, NimBLEConnInfo& connInfo) override {
        Serial.printf("%s : onRead(), value: %s\n",
                      pCharacteristic->getUUID().toString().c_str(),
                      pCharacteristic->getValue().c_str());
    }

    void onWrite(NimBLECharacteristic* pCharacteristic, NimBLEConnInfo& connInfo) override {
        const std::string &val = pCharacteristic->getValue();
        Serial.printf("%s : onWrite() from %s, length: %d, value(raw hex): ",
                      pCharacteristic->getUUID().toString().c_str(),
                      connInfo.getAddress().toString().c_str(),
                      (int)val.length());
        for (size_t i = 0; i < val.length(); ++i) Serial.printf("%02X ", (uint8_t)val[i]);
        Serial.println();

        if (val.length() == 0) {
            Serial.println("Empty write received");
            return;
        }
        uint8_t cmd = (uint8_t)val[0];
        if (cmd == 0x01) {
            digitalWrite(LOCK_PIN, HIGH);
            Serial.println(">>> LED turned ON <<<");
            pCharacteristic->setValue("ON");
            pCharacteristic->notify(true); // indicate/notify to all subscribed peers
            sleep(1);
            digitalWrite(LOCK_PIN, LOW);
        }else{
            Serial.printf(">>> UNKNOWN command: 0x%02X <<<\n", cmd);
        }
    }

    void onStatus(NimBLECharacteristic* pCharacteristic, int code) override {
        Serial.printf("Notification/Indication return code: %d, %s\n",
                      code, NimBLEUtils::returnCodeToString(code));
    }

    void onSubscribe(NimBLECharacteristic* pCharacteristic, NimBLEConnInfo& connInfo, uint16_t subValue) override {
        String msg = "Client ";
        msg += String(connInfo.getConnHandle());
        msg += " ";
        msg += connInfo.getAddress().toString().c_str();
        if (subValue == 0) msg += " unsubscribed from ";
        else if (subValue == 1) msg += " subscribed to notifications for ";
        else if (subValue == 2) msg += " subscribed to indications for ";
        else if (subValue == 3) msg += " subscribed to notifications and indications for ";
        msg += pCharacteristic->getUUID().toString().c_str();
        Serial.println(msg);
    }
} chrCallbacks;

/** ---------------------------
 *  Descriptor callbacks (from NimBLE_Server demo)
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
        Serial.printf("%s Descriptor read by %s\n", pDescriptor->getUUID().toString().c_str(),
                      connInfo.getAddress().toString().c_str());
    }
} dscCallbacks;

/** ---------------------------
 *  Setup and main loop
 *  --------------------------- */
void setup() {
    Serial.begin(115200);
    delay(500);
    Serial.println("\nStarting DOORLOCK NimBLE Server");

    // write to a light    
    pinMode(LOCK_PIN, OUTPUT);
    digitalWrite(LOCK_PIN, LOW);

    // Initialize NimBLE and set device name
    NimBLEDevice::init(DEVICE_NAME);

    //NimBLEDevice::setSecurityAuth(true,true,true); 
    // Disable security requirements for testing (allow unencrypted connections)
    NimBLEDevice::setSecurityAuth(false,false,false); // no bonding, no MITM, no secure connection required
    //NimBLEDevice::setSecurityIOCap(BLE_HS_IO_NO_INPUT_OUTPUT); // "Just Works" / no IO
    NimBLEDevice::setSecurityIOCap(BLE_HS_IO_DISPLAY_ONLY);
    //NimBLEDevice::setSecurityIOCap(BLE_HS_IO_DISPLAY_YESNO);
    // Optional: avoid distributing pairing keys
    NimBLEDevice::setSecurityInitKey(0);
    NimBLEDevice::setSecurityRespKey(0);


    // Security IO Capabilities: default is NO_INPUT_OUTPUT, uncomment to change:
    // NimBLEDevice::setSecurityIOCap(BLE_HS_IO_DISPLAY_YESNO); // numeric comparison, etc.

    // Set minimal security/auth behavior if needed (comment/uncomment depending on your library)
    // NimBLEDevice::setSecurityAuth(false, false, true);

    // Create server and set callbacks (demo-style)
    pServer = NimBLEDevice::createServer();
    // set the callback for the server
    pServer->setCallbacks(&serverCallbacks);

    // Create service and characteristic
    NimBLEService* pService = pServer->createService(SERVICE_UUID);
    // set the characteristic for the service -> only one here, opening and closing door
    pDoorChr = pService->createCharacteristic(
        CHARACTERISTIC_UUID,
        NIMBLE_PROPERTY::READ |
        NIMBLE_PROPERTY::WRITE |
        NIMBLE_PROPERTY::WRITE_NR |
        NIMBLE_PROPERTY::NOTIFY
    );

    // Set initial value and callbacks
    pDoorChr->setValue("OFF");
    pDoorChr->setCallbacks(&chrCallbacks);

    // Create 2904 descriptor to describe format, descriptor allows to say if notifications are turned on or off
    NimBLE2904* p2904 = pDoorChr->create2904();
    p2904->setFormat(NimBLE2904::FORMAT_UTF8);
    p2904->setCallbacks(&dscCallbacks);

    // Create a custom descriptor (C01D) like demo
    NimBLEDescriptor* pC01D = pDoorChr->createDescriptor("C01D", NIMBLE_PROPERTY::READ | NIMBLE_PROPERTY::WRITE, 20);
    pC01D->setValue("DoorLock Descriptor");
    pC01D->setCallbacks(&dscCallbacks);

    // Start service
    pService->start();

    // Advertising
    NimBLEAdvertising* pAdvertising = NimBLEDevice::getAdvertising();
    pAdvertising->setName(DEVICE_NAME);
    pAdvertising->addServiceUUID(pService->getUUID());
    // demo uses enableScanResponse(true)
    pAdvertising->enableScanResponse(true);
    pAdvertising->start();

    Serial.println("Advertising Started");
}

void loop() {
    // Periodically notify subscribed clients of the current state (optional)
    delay(2000);

    if (pServer->getConnectedCount()) {
        // notify the characteristic to any subscribed client
        pDoorChr->notify(true); // true -> indicate/notify and wait for confirmation where appropriate
    }
}
