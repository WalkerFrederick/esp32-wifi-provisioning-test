#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <Arduino.h>
#include <mbedtls/aes.h>
#include <mbedtls/base64.h>
#include <WiFi.h>
#include <ESPAsyncWebServer.h>
#include <Preferences.h>
#include <ArduinoJson.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

// ===========================================================
// OLED Display & I2C Configuration
// ===========================================================
#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 32
#define OLED_RESET -1
#define SCREEN_ADDRESS 0x3C

// ESP32 I2C Pins
#define SDA_PIN 42
#define SCL_PIN 41

// Instantiate OLED display and web server objects
Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, OLED_RESET);
AsyncWebServer server(80);

// ===========================================================
// WiFi & Security Configuration
// ===========================================================

// AES Key for WiFi credentials decryption (16 bytes)
const uint8_t AES_KEY[16] = {'t', 'h', 'i', 's', 'i', 's', 'm', 'y', 'p', 'a', 's', 's', 'w', 'o', 'r', 'd'};

// Access Point (AP) mode credentials for initial provisioning
const char *ap_ssid = "ESP32-Setup";
const char *ap_password = "12345678";

// ===========================================================
// Boot Button (GPIO0) for long-press actions
// ===========================================================
const int bootButtonPin = 0;
unsigned long pressStartTime = 0;

// ===========================================================
// Utility Functions
// ===========================================================

bool decrypt_wifi_credentials(const char *encrypted_b64, char *output, size_t output_size)
{
    uint8_t encrypted_data[64];
    size_t encrypted_len = 0;
    if (mbedtls_base64_decode(encrypted_data, sizeof(encrypted_data), &encrypted_len,
                              (const uint8_t *)encrypted_b64, strlen(encrypted_b64)) != 0)
    {
        Serial.println("Base64 decode failed");
        return false;
    }
    if (encrypted_len < 16)
    {
        Serial.println("Encrypted data too short");
        return false;
    }
    uint8_t iv[16];
    memcpy(iv, encrypted_data, 16);
    uint8_t *ciphertext = encrypted_data + 16;
    size_t ciphertext_len = encrypted_len - 16;
    if (ciphertext_len >= output_size)
    {
        Serial.println("Decrypted output buffer too small");
        return false;
    }
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_dec(&aes, AES_KEY, 128);
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, ciphertext_len, iv, ciphertext, (uint8_t *)output);
    output[ciphertext_len] = '\0';
    mbedtls_aes_free(&aes);
    Serial.printf("Decrypted output: [%s]\n", output);
    return true;
}

void clean_string(char *str)
{
    int len = strlen(str);
    int i = 0, j = 0;
    while (i < len)
    {
        if (str[i] > 0x1F && str[i] < 0x7F)
        {
            str[j++] = str[i];
        }
        i++;
    }
    str[j] = '\0';
}

// ===========================================================
// Factory Reset Function
// ===========================================================
void factory_reset()
{
    Serial.println("Performing factory reset...");
    // Clear stored WiFi credentials
    Preferences preferences;
    preferences.begin("wifi", false);
    preferences.clear();
    preferences.end();

    // Display factory reset message
    display.clearDisplay();
    display.setCursor(0, 0);
    display.println("Factory Reset");
    display.display();
    delay(2000);

    // Restart the device
    ESP.restart();
}

// ===========================================================
// WiFi Connection Task
// ===========================================================
void connectToWiFi(void *parameter)
{
    char *credentials = (char *)parameter;
    if (!credentials)
    {
        Serial.println("Memory allocation failed for credentials!");
        vTaskDelete(NULL);
        return;
    }
    Serial.printf("Raw Credentials String: [%s]\n", credentials);
    char wifi_ssid[64], wifi_password[64];
    if (sscanf(credentials, "%63[^|]|%63s", wifi_ssid, wifi_password) != 2)
    {
        Serial.println("Invalid WiFi data format!");
        free(parameter);
        vTaskDelete(NULL);
        return;
    }
    wifi_ssid[63] = '\0';
    wifi_password[63] = '\0';
    clean_string(wifi_ssid);
    clean_string(wifi_password);
    WiFi.disconnect();
    delay(1000);
    WiFi.mode(WIFI_STA);
    WiFi.begin(wifi_ssid, wifi_password);
    Serial.print("Connecting to WiFi");
    int attempts = 0;
    while (WiFi.status() != WL_CONNECTED && attempts < 20)
    {
        vTaskDelay(pdMS_TO_TICKS(500));
        Serial.print(".");
        attempts++;
    }
    Serial.println();
    if (WiFi.status() == WL_CONNECTED)
    {
        Serial.printf("Connected to WiFi: %s\n", WiFi.SSID().c_str());
        IPAddress localIP = WiFi.localIP();
        Serial.printf("Local IP Address: %s\n", localIP.toString().c_str());
        display.clearDisplay();
        display.setCursor(0, 0);
        display.println("Connected:");
        display.println(wifi_ssid);
        display.print("IP: ");
        display.println(localIP.toString());
        display.display();
        Preferences preferences;
        preferences.begin("wifi", false);
        preferences.putString("ssid", wifi_ssid);
        preferences.putString("password", wifi_password);
        preferences.end();
    }
    else
    {
        Serial.println("WiFi connection failed.");
    }
    free(parameter);
    vTaskDelete(NULL);
}

// ===========================================================
// HTTP Request Handlers
// ===========================================================
void handle_wifi_setup(AsyncWebServerRequest *request, uint8_t *data, size_t len, size_t index, size_t total)
{
    Serial.println("Received WiFi setup request...");
    StaticJsonDocument<200> jsonDoc;
    DeserializationError error = deserializeJson(jsonDoc, (const char *)data);
    if (error)
    {
        Serial.println("JSON Parsing Failed!");
        request->send(400, "text/plain", "Invalid JSON");
        return;
    }
    if (!jsonDoc.containsKey("data"))
    {
        Serial.println("Missing 'data' parameter");
        request->send(400, "text/plain", "Missing 'data' parameter");
        return;
    }
    String encrypted_data = jsonDoc["data"].as<String>();
    char decrypted[128];
    if (!decrypt_wifi_credentials(encrypted_data.c_str(), decrypted, sizeof(decrypted)))
    {
        Serial.println("Decryption failed");
        request->send(400, "text/plain", "Decryption Failed");
        return;
    }
    Serial.printf("Decrypted String: [%s]\n", decrypted);
    request->send(200, "text/plain", "WiFi Credentials Processing...");
    delay(1000);
    xTaskCreate(connectToWiFi, "ConnectToWiFi", 4096, strdup(decrypted), 1, NULL);
}

// ===========================================================
// New HTTP GET Endpoint to Display a Message
// ===========================================================
void handle_display_message(AsyncWebServerRequest *request)
{
    String msg = "";
    if (request->hasParam("msg"))
    {
        msg = request->getParam("msg")->value();
    }
    display.clearDisplay();

    // Calculate the text dimensions
    int16_t x1, y1;
    uint16_t w, h;
    display.getTextBounds(msg, 0, 0, &x1, &y1, &w, &h);

    // Compute centered positions
    int x = (SCREEN_WIDTH - w) / 2;
    int y = (SCREEN_HEIGHT - h) / 2;

    display.setCursor(x, y);
    display.println(msg);
    display.display();

    request->send(200, "text/plain", "Displayed: " + msg);
}

// ===========================================================
// Access Point Mode Setup
// ===========================================================
void start_ap_mode()
{
    Serial.println("Starting AP Mode...");
    WiFi.softAP(ap_ssid, ap_password);
    IPAddress apIP = WiFi.softAPIP();
    Serial.print("AP IP Address: ");
    Serial.println(apIP);
    display.clearDisplay();
    display.setCursor(0, 0);
    display.println("AP Mode Active");
    display.println(apIP.toString());
    display.display();
}

// ===========================================================
// Setup and Loop
// ===========================================================
void setup()
{
    Serial.begin(115200);
    Wire.begin(SDA_PIN, SCL_PIN);
    if (!display.begin(SSD1306_SWITCHCAPVCC, SCREEN_ADDRESS))
    {
        Serial.println(F("SSD1306 allocation failed"));
        while (true)
            ;
    }
    display.clearDisplay();
    display.setTextSize(1);
    display.setTextColor(SSD1306_WHITE);
    display.setCursor(0, 0);
    display.println("Booting...");
    display.display();
    pinMode(bootButtonPin, INPUT_PULLUP);

    // Check for stored WiFi credentials
    Preferences preferences;
    preferences.begin("wifi", true);
    String storedSSID = preferences.getString("ssid", "");
    String storedPassword = preferences.getString("password", "");
    preferences.end();

    if (storedSSID != "" && storedPassword != "")
    {
        Serial.println("Stored credentials found. Connecting to WiFi...");
        WiFi.mode(WIFI_STA);
        WiFi.begin(storedSSID.c_str(), storedPassword.c_str());
        Serial.print("Connecting");
        int attempts = 0;
        while (WiFi.status() != WL_CONNECTED && attempts < 20)
        {
            delay(500);
            Serial.print(".");
            attempts++;
        }
        Serial.println();
        if (WiFi.status() == WL_CONNECTED)
        {
            Serial.printf("Connected to WiFi: %s\n", WiFi.SSID().c_str());
            IPAddress localIP = WiFi.localIP();
            Serial.printf("Local IP Address: %s\n", localIP.toString().c_str());
            display.clearDisplay();
            display.setCursor(0, 0);
            display.println("Connected:");
            display.println(storedSSID);
            display.print("IP: ");
            display.println(localIP.toString());
            display.display();
        }
        else
        {
            Serial.println("Failed to connect using stored credentials. Starting AP mode...");
            start_ap_mode();
        }
    }
    else
    {
        Serial.println("No stored credentials. Starting AP mode...");
        start_ap_mode();
    }

    // Set up HTTP endpoints
    server.on("/set_wifi", HTTP_POST, [](AsyncWebServerRequest *request) {}, NULL, handle_wifi_setup);
    server.on("/", HTTP_GET, [](AsyncWebServerRequest *request)
              { request->send(200, "text/plain", "Hello, world!"); });
    // New endpoint: /display?msg=your_message_here
    server.on("/display", HTTP_GET, handle_display_message);
    server.begin();
}

void loop()
{
    // Monitor boot button (GPIO0) for a long press (5 seconds) to trigger factory reset
    if (digitalRead(bootButtonPin) == LOW)
    {
        if (pressStartTime == 0)
        {
            pressStartTime = millis();
        }
        else if (millis() - pressStartTime >= 5000)
        {
            factory_reset();
        }
    }
    else
    {
        pressStartTime = 0;
    }
    delay(100);
}
