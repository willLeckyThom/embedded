/**
 * DOORLOCK - NimBLE Server with HMAC-Authenticated Rolling Code + OLED UI
 *
 * Security Features:
 * - BLE bonding, MITM protection, and encrypted read/write
 * - Rolling code mechanism to prevent replay attacks
 * - HMAC-SHA256 authentication with shared secret key
 *
 * Rolling Code Protocol:
 * - Message format: [4 bytes counter (little-endian)][32 bytes HMAC-SHA256]
 * - Total size: 36 bytes
 * - Counter must increment with each request
 * - Counter is persisted in flash memory across reboots (Preferences)
 * - Requests with old/replayed counters are rejected
 * - Accepts counters within a window (default: 100) to handle out-of-order packets
 * - HMAC is computed as: HMAC-SHA256(shared_secret, counter_bytes)
 *
 * OLED behavior:
 * - During pairing: show "PAIR KEY:" and passkey
 * - After successful authentication: show "PAIRED!" briefly then clear
 * - On successful unlock: show "UNLOCKED" then "LOCKED"
 * - On errors: show "INVALID HMAC", "REPLAY", "BAD COUNTER", "HMAC ERROR"
 *
 * Client Implementation Example:
 *   counter++;
 *   counter_bytes = counter.to_bytes(4, 'little')
 *   hmac_value = hmac.new(shared_secret, counter_bytes, hashlib.sha256).digest()
 *   message = counter_bytes + hmac_value  # 36 bytes total
 *   characteristic.write(message)
 */

#include <Arduino.h>
#include <NimBLEDevice.h>
#include <Preferences.h>
#include <mbedtls/md.h>          // For HMAC-SHA256
#include <SPI.h>
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>

/*** Shared configuration ***/
#define SERVICE_UUID        "4fafc201-1fb5-459e-8fcc-c5c9c331914b"
#define CHARACTERISTIC_UUID "beb5483e-36e1-4688-b7f5-ea07361b26a8"
#define DEVICE_NAME         "DOORLOCK"
#define LOCK_PIN             27

// Rolling code configuration
#define COUNTER_WINDOW      100  // Accept counters within this window ahead of expected
#define COUNTER_NAMESPACE   "doorlock"
#define COUNTER_KEY         "counter"

// HMAC configuration
#define HMAC_SIZE           32   // SHA-256 produces 32-byte output
#define MESSAGE_SIZE        36   // 4 bytes counter + 32 bytes HMAC

// OLED configuration
#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64
#define OLED_RESET -1
#define SCREEN_ADDRESS 0x3C

/*** Shared Secret (hardcoded for simplicity) ***/
const uint8_t SHARED_SECRET[32] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x97, 0x75, 0x46, 0xcf, 0x34, 0xe5,
    0x89, 0x32, 0x4b, 0x6c, 0x12, 0x93, 0x5d, 0x8f,
    0xa9, 0x78, 0xbc, 0x3e, 0x6f, 0x21, 0x45, 0xd1
};

/*** Globals ***/
static NimBLEServer* pServer = nullptr;
static NimBLECharacteristic* pDoorChr = nullptr;
static Preferences preferences;
static uint32_t expectedCounter = 0;

Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, OLED_RESET);

/*** Helper: display helpers (centralized) ***/
void oledShowMessageCentered(const char* line1, const char* line2 = nullptr, uint8_t size1 = 2, uint8_t size2 = 2, unsigned long durationMs = 0) {
    display.clearDisplay();
    display.setTextColor(WHITE);

    if (line1) {
        display.setTextSize(size1);
        int16_t x1, y1;
        uint16_t w1, h1;
        display.getTextBounds(line1, 0, 0, &x1, &y1, &w1, &h1);
        int16_t xPos = max(0, (SCREEN_WIDTH - (int)w1) / 2);
        display.setCursor(xPos, 8);
        display.println(line1);
    }

    if (line2) {
        display.setTextSize(size2);
        int16_t x2, y2;
        uint16_t w2, h2;
        display.getTextBounds(line2, 0, 0, &x2, &y2, &w2, &h2);
        int16_t xPos2 = max(0, (SCREEN_WIDTH - (int)w2) / 2);
        display.setCursor(xPos2, 32);
        display.println(line2);
    }

    display.display();

    if (durationMs > 0) {
        delay(durationMs);
        display.clearDisplay();
        display.display();
    }
}

/*** ---------------------------
 *  Server callbacks
 *  --------------------------- */
class ServerCallbacks : public NimBLEServerCallbacks {
    void onConnect(NimBLEServer* pServerInst, NimBLEConnInfo& connInfo) override {
        Serial.printf("Client connected: %s (handle %u)\n",
                      connInfo.getAddress().toString().c_str(),
                      connInfo.getConnHandle());
        // Slightly tighten connection parameters
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
        // For numeric comparison, NimBLE will call onConfirmPassKey instead; keep fallback passkey if needed.
        Serial.println("Server Passkey Display (static 123456 for demo)");
        return 123456;
    }

    void onConfirmPassKey(NimBLEConnInfo& connInfo, uint32_t pass_key) override {
        // Show passkey on OLED and auto-confirm
        Serial.printf("Confirm Passkey %u for %s\n", pass_key, connInfo.getAddress().toString().c_str());

        // Display "PAIR KEY:" and the passkey centered
        char buf[10];
        sprintf(buf, "%06u", pass_key);
        oledShowMessageCentered("PAIR KEY:", buf, 2, 2, 0);

        // Auto-confirm numeric comparison
        NimBLEDevice::injectConfirmPasskey(connInfo, true);
    }

    void onAuthenticationComplete(NimBLEConnInfo& connInfo) override {
        if (!connInfo.isEncrypted()) {
            Serial.printf("Connection to %s completed WITHOUT encryption!\n", connInfo.getAddress().toString().c_str());
            // Show failed pairing briefly
            oledShowMessageCentered("PAIRING", "FAILED", 2, 2, 1500);
            display.clearDisplay();
            display.display();
        } else {
            Serial.printf("Secured connection to: %s\n", connInfo.getAddress().toString().c_str());
            // Show "PAIRED!" then clear
            oledShowMessageCentered("PAIRED!", nullptr, 2, 2, 1500);
            display.clearDisplay();
            display.display();
        }
    }
} serverCallbacks;

/*** ---------------------------
 *  HMAC and Rolling Code Functions
 *  --------------------------- */
bool computeHMAC(const uint8_t* data, size_t dataLen, uint8_t* output) {
    mbedtls_md_context_t ctx;
    mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;

    mbedtls_md_init(&ctx);

    if (mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 1) != 0) {
        Serial.println(">>> HMAC setup failed <<<");
        mbedtls_md_free(&ctx);
        return false;
    }

    if (mbedtls_md_hmac_starts(&ctx, SHARED_SECRET, sizeof(SHARED_SECRET)) != 0) {
        Serial.println(">>> HMAC key setup failed <<<");
        mbedtls_md_free(&ctx);
        return false;
    }

    if (mbedtls_md_hmac_update(&ctx, data, dataLen) != 0) {
        Serial.println(">>> HMAC update failed <<<");
        mbedtls_md_free(&ctx);
        return false;
    }

    if (mbedtls_md_hmac_finish(&ctx, output) != 0) {
        Serial.println(">>> HMAC finalize failed <<<");
        mbedtls_md_free(&ctx);
        return false;
    }

    mbedtls_md_free(&ctx);
    return true;
}

bool verifyHMAC(const uint8_t* hmac1, const uint8_t* hmac2) {
    // constant-time comparison
    uint8_t result = 0;
    for (int i = 0; i < HMAC_SIZE; ++i) {
        result |= hmac1[i] ^ hmac2[i];
    }
    return result == 0;
}

/*
 * Validate counter (reject replay/out-of-window), persist on success.
 * Returns:
 *  - true = valid (expectedCounter updated and persisted)
 *  - false = invalid
 */
bool validateAndUpdateCounter(uint32_t receivedCounter) {
    if (receivedCounter <= expectedCounter) {
        Serial.printf(">>> REPLAY ATTACK DETECTED: received %u, expected > %u <<<\n",
                      receivedCounter, expectedCounter);
        oledShowMessageCentered("REPLAY", nullptr, 2, 2, 1500);
        display.clearDisplay();
        display.display();
        return false;
    }

    // Check window
    if (receivedCounter > expectedCounter + COUNTER_WINDOW) {
        Serial.printf(">>> COUNTER OUT OF WINDOW: received %u, expected %u-%u <<<\n",
                      receivedCounter, expectedCounter + 1, expectedCounter + COUNTER_WINDOW);
        oledShowMessageCentered("BAD COUNTER", nullptr, 2, 2, 1500);
        display.clearDisplay();
        display.display();
        return false;
    }

    // Valid: update expected and persist
    expectedCounter = receivedCounter;
    preferences.begin(COUNTER_NAMESPACE, false);
    preferences.putUInt(COUNTER_KEY, expectedCounter);
    preferences.end();

    Serial.printf(">>> Counter validated: %u <<<\n", receivedCounter);
    return true;
}

/*** ---------------------------
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
            oledShowMessageCentered("NOT ENCRYPTED", nullptr, 2, 2, 1500);
            display.clearDisplay();
            display.display();
            return;
        }

        const std::string &val = pCharacteristic->getValue();
        Serial.printf("Write request from %s, length %d, value (hex): ",
                      connInfo.getAddress().toString().c_str(), (int)val.length());
        for (size_t i = 0; i < val.length(); ++i) Serial.printf("%02X ", (uint8_t)val[i]);
        Serial.println();

        // Message format: [4 bytes counter (little-endian)][32 bytes HMAC-SHA256]
        if (val.length() != MESSAGE_SIZE) {
            Serial.printf(">>> INVALID LENGTH: expected %d bytes, got %d <<<\n", MESSAGE_SIZE, (int)val.length());
            oledShowMessageCentered("BAD MSG LEN", nullptr, 2, 2, 1500);
            display.clearDisplay();
            display.display();
            return;
        }

        // Extract counter (little-endian)
        uint8_t counterBytes[4];
        counterBytes[0] = (uint8_t)val[0];
        counterBytes[1] = (uint8_t)val[1];
        counterBytes[2] = (uint8_t)val[2];
        counterBytes[3] = (uint8_t)val[3];

        uint32_t receivedCounter = ((uint32_t)counterBytes[0]) |
                                   ((uint32_t)counterBytes[1] << 8) |
                                   ((uint32_t)counterBytes[2] << 16) |
                                   ((uint32_t)counterBytes[3] << 24);

        // Extract received HMAC
        uint8_t receivedHMAC[HMAC_SIZE];
        for (int i = 0; i < HMAC_SIZE; ++i) receivedHMAC[i] = (uint8_t)val[4 + i];

        // Compute expected HMAC on the counter bytes
        uint8_t computedHMAC[HMAC_SIZE];
        if (!computeHMAC(counterBytes, sizeof(counterBytes), computedHMAC)) {
            Serial.println(">>> HMAC COMPUTATION FAILED <<<");
            pCharacteristic->setValue("HMAC ERROR");
            pCharacteristic->notify(true);
            oledShowMessageCentered("HMAC ERROR", nullptr, 2, 2, 1500);
            display.clearDisplay();
            display.display();
            return;
        }

        // Verify HMAC
        if (!verifyHMAC(receivedHMAC, computedHMAC)) {
            Serial.println(">>> AUTHENTICATION FAILED: Invalid HMAC <<<");
            Serial.print("Expected HMAC: ");
            for (int i = 0; i < HMAC_SIZE; ++i) Serial.printf("%02X", computedHMAC[i]);
            Serial.println();
            Serial.print("Received HMAC: ");
            for (int i = 0; i < HMAC_SIZE; ++i) Serial.printf("%02X", receivedHMAC[i]);
            Serial.println();

            pCharacteristic->setValue("INVALID HMAC");
            pCharacteristic->notify(true);

            oledShowMessageCentered("INVALID HMAC", nullptr, 2, 2, 1500);
            display.clearDisplay();
            display.display();
            return;
        }

        Serial.println(">>> HMAC VERIFIED: Authentic message <<<");

        // Validate rolling code counter
        if (!validateAndUpdateCounter(receivedCounter)) {
            Serial.println(">>> REQUEST REJECTED: Invalid counter <<<");
            pCharacteristic->setValue("INVALID COUNTER");
            pCharacteristic->notify(true);
            // validateAndUpdateCounter already showed message
            return;
        }

        // All checks passed - open the door!
        Serial.println(">>> OPENING DOOR <<<");
        digitalWrite(LOCK_PIN, HIGH);
        pCharacteristic->setValue("DOOR_OPENED");
        pCharacteristic->notify(true);

        // Show UNLOCKED message
        oledShowMessageCentered("UNLOCKED", nullptr, 2, 2, 1000);

        delay(3000);  // Keep door open for 3 seconds

        digitalWrite(LOCK_PIN, LOW);
        Serial.println(">>> DOOR CLOSED <<<");
        pCharacteristic->setValue("DOOR_CLOSED");
        pCharacteristic->notify(true);

        // Show LOCKED message briefly, then clear
        oledShowMessageCentered("LOCKED", nullptr, 2, 2, 1000);
        display.clearDisplay();
        display.display();
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

/*** Descriptor callbacks (optional logging) ***/
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

/*** ---------------------------
 *  Setup and loop
 *  --------------------------- */
void setup() {
    Serial.begin(115200);
    delay(500);
    Serial.println("\nStarting DOORLOCK NimBLE Server (HMAC Rolling Code + OLED)");

    pinMode(LOCK_PIN, OUTPUT);
    digitalWrite(LOCK_PIN, LOW);

    // Initialize OLED
    Wire.begin(); // uses default 21/22 unless changed
    if(!display.begin(SSD1306_SWITCHCAPVCC, SCREEN_ADDRESS)) {
        Serial.println(F("SSD1306 allocation failed"));
        // If the display fails, continue without crashing - but UI will not work.
    } else {
        display.clearDisplay();
        display.display();
        // initial ready message
        oledShowMessageCentered("DOORLOCK", "READY", 2, 1, 1000);
        display.clearDisplay();
        display.display();
    }

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
        NIMBLE_PROPERTY::WRITE_ENC    // require encryption for write
    );

    pDoorChr->setValue("OFF");
    pDoorChr->setCallbacks(&chrCallbacks);

    // Add 2904 descriptor and custom descriptor
    NimBLE2904* p2904 = pDoorChr->create2904();
    p2904->setFormat(NimBLE2904::FORMAT_UTF8);
    p2904->setCallbacks(&dscCallbacks);

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
    oledShowMessageCentered("ADVERTISING", nullptr, 1, 1, 1000);
    display.clearDisplay();
    display.display();
}

void loop() {
    // Minimal loop — keep BLE stack running
    delay(2000);

    // Optional: send periodic notification (keeps notifications alive if subscribed)
    if (pServer && pServer->getConnectedCount() && pDoorChr) {
        // send a simple "heartbeat" notification with current counter (optional)
        // Be cautious: notifying too often can affect performance / power.
        // Here we simply call notify to maintain subscription state; caller must manage payload.
        // pDoorChr->notify(true);
    }
}
