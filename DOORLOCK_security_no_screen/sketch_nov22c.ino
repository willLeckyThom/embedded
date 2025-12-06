/**
 * DOORLOCK – Secure NimBLE Server with:
 * - Static passkey (MITM protected)
 * - Encryption required
 * - 3 failed attempts → MAC banned for 5 minutes
 */

#include <Arduino.h>
#include <NimBLEDevice.h>
#include <vector>
#include <map>

#define SERVICE_UUID        "4fafc201-1fb5-459e-8fcc-c5c9c331914b"
#define CHARACTERISTIC_UUID "beb5483e-36e1-4688-b7f5-ea07361b26a8"
#define DEVICE_NAME         "DOORLOCK"
#define LOCK_PIN             27
#define STATIC_PASSKEY      123456
#define MAX_FAILS           3
#define BAN_DURATION        300000UL  // 5 minutes

/* Ban list structure */
struct BanEntry {
    NimBLEAddress mac;
    uint32_t until;
};

static std::vector<BanEntry> banned;
static std::map<std::string, int> failCount;

/* Cleanup expired bans */
void cleanupExpiredBans() {
    uint32_t now = millis();
    banned.erase(
        std::remove_if(banned.begin(), banned.end(),
            [&](BanEntry &b){ return now > b.until; }),
        banned.end()
    );
}

/* Check if MAC is banned */
bool isBanned(const NimBLEAddress &mac) {
    cleanupExpiredBans();
    uint32_t now = millis();
    for (auto &b : banned) {
        if (b.mac == mac && now < b.until) {
            return true;
        }
    }
    return false;
}

/* Add or extend ban */
void banMAC(const NimBLEAddress &mac) {
    uint32_t until = millis() + BAN_DURATION;
    for (auto &b : banned) {
        if (b.mac == mac) {
            b.until = until;
            return;
        }
    }
    banned.push_back({mac, until});
}

/* ----------------------------------------------
 *  Server Callbacks
 * ---------------------------------------------- */
class ServerCallbacks : public NimBLEServerCallbacks {

    void onConnect(NimBLEServer* s, NimBLEConnInfo& info) override {
        NimBLEAddress mac = info.getAddress();

        if (isBanned(mac)) {
            Serial.printf("BANNED device %s attempted to connect!\n",
                          mac.toString().c_str());
            s->disconnect(info.getConnHandle());
            return;
        }

        Serial.printf("Client connected: %s\n", mac.toString().c_str());
    }

    void onDisconnect(NimBLEServer*, NimBLEConnInfo& info, int reason) override {
        Serial.printf("Disconnected %s (reason %d). Restarting advertising.\n",
                      info.getAddress().toString().c_str(), reason);
        NimBLEDevice::startAdvertising();
    }

    uint32_t onPassKeyDisplay() override {
        Serial.printf("Static passkey displayed: %u\n", STATIC_PASSKEY);
        return STATIC_PASSKEY;
    }

    void onAuthenticationComplete(NimBLEConnInfo& info) override {
        std::string mac = info.getAddress().toString();

        if (!info.isEncrypted()) {
            Serial.printf("Authentication FAILED for %s\n", mac.c_str());
            failCount[mac]++;

            Serial.printf("→ Fail count: %d\n", failCount[mac]);

            if (failCount[mac] >= MAX_FAILS) {
                Serial.printf("!! BANNING %s\n", mac.c_str());
                banMAC(info.getAddress());
            }
            return;
        }

        Serial.printf("Secure authenticated connection with %s\n", mac.c_str());
        failCount[mac] = 0; // reset after success
    }
} serverCB;


/* ----------------------------------------------
 * Characteristic callbacks
 * ---------------------------------------------- */
class DoorCallbacks : public NimBLECharacteristicCallbacks {
    void onWrite(NimBLECharacteristic* chr, NimBLEConnInfo& info) override {

        if (!info.isEncrypted()) {
            Serial.println("Write blocked: NOT encrypted");
            return;
        }

        const std::string &val = chr->getValue();
        if (val.empty()) return;

        uint8_t cmd = val[0];
        Serial.printf("Write cmd %02X from %s\n",
                      cmd, info.getAddress().toString().c_str());

        if (cmd == 0x01) {
            digitalWrite(LOCK_PIN, HIGH);
            chr->setValue("ON");
            chr->notify();
            delay(1000);          // FIXED: replaced sleep(1) a
            digitalWrite(LOCK_PIN, LOW);
        }
    }
} doorCB;


/* ----------------------------------------------
 * Setup
 * ---------------------------------------------- */
void setup() {
    Serial.begin(115200);
    delay(200);

    pinMode(LOCK_PIN, OUTPUT);
    digitalWrite(LOCK_PIN, LOW);

    NimBLEDevice::init(DEVICE_NAME);

    /* Security settings */
    NimBLEDevice::setSecurityAuth(true, true, true);
    NimBLEDevice::setSecurityIOCap(BLE_HS_IO_DISPLAY_ONLY);
    NimBLEDevice::setSecurityPasskey(STATIC_PASSKEY);

    NimBLEDevice::setSecurityInitKey(BLE_SM_PAIR_KEY_DIST_ENC | BLE_SM_PAIR_KEY_DIST_ID);
    NimBLEDevice::setSecurityRespKey(BLE_SM_PAIR_KEY_DIST_ENC | BLE_SM_PAIR_KEY_DIST_ID);

    NimBLEServer* server = NimBLEDevice::createServer();
    server->setCallbacks(&serverCB);

    NimBLEService* svc = server->createService(SERVICE_UUID);

    NimBLECharacteristic* chr = svc->createCharacteristic(
        CHARACTERISTIC_UUID,
        NIMBLE_PROPERTY::READ |
        NIMBLE_PROPERTY::WRITE |
        NIMBLE_PROPERTY::WRITE_NR |
        NIMBLE_PROPERTY::NOTIFY |
        NIMBLE_PROPERTY::READ_ENC |
        NIMBLE_PROPERTY::WRITE_ENC
    );

    chr->setCallbacks(&doorCB);
    chr->setValue("OFF");

    svc->start();

    NimBLEAdvertising *adv = NimBLEDevice::getAdvertising();
    adv->addServiceUUID(SERVICE_UUID);
    adv->setName(DEVICE_NAME);
    adv->start();

    Serial.println("Advertising started.");
}

void loop() {
    cleanupExpiredBans();
    delay(1000);
}
