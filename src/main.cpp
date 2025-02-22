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
// Utility Functions
// ===========================================================

/**
 * @brief Decrypts the WiFi credentials provided as a base64-encoded string.
 *
 * The encrypted string is expected to have the first 16 bytes as the IV.
 *
 * @param encrypted_b64 Base64-encoded encrypted credentials.
 * @param output Buffer to store decrypted output.
 * @param output_size Size of the output buffer.
 * @return true if decryption is successful, false otherwise.
 */
bool decrypt_wifi_credentials(const char *encrypted_b64, char *output, size_t output_size)
{
    uint8_t encrypted_data[64];
    size_t encrypted_len = 0;

    // Decode Base64
    if (mbedtls_base64_decode(encrypted_data, sizeof(encrypted_data), &encrypted_len,
                              (const uint8_t *)encrypted_b64, strlen(encrypted_b64)) != 0)
    {
        Serial.println("Base64 decode failed");
        return false;
    }

    // Ensure we have at least enough bytes for the IV
    if (encrypted_len < 16)
    {
        Serial.println("Encrypted data too short");
        return false;
    }

    // Extract Initialization Vector (IV) from the first 16 bytes
    uint8_t iv[16];
    memcpy(iv, encrypted_data, 16);
    uint8_t *ciphertext = encrypted_data + 16;
    size_t ciphertext_len = encrypted_len - 16;

    // Check if the output buffer is large enough for the decrypted data
    if (ciphertext_len >= output_size)
    {
        Serial.println("Decrypted output buffer too small");
        return false;
    }

    // Initialize AES context and decrypt the data using CBC mode
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_dec(&aes, AES_KEY, 128);
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, ciphertext_len, iv, ciphertext, (uint8_t *)output);
    output[ciphertext_len] = '\0'; // Null-terminate the decrypted string
    mbedtls_aes_free(&aes);

    Serial.printf("Decrypted output: [%s]\n", output);
    return true;
}

/**
 * @brief Removes unwanted characters (carriage return, newline, backspace) from a string.
 *
 * @param str String to be cleaned.
 */
void clean_string(char *str)
{
    int len = strlen(str);
    int i = 0, j = 0;
    while (i < len)
    {
        // Remove carriage return, newline, backspace, and any ASCII control character (0x00 - 0x1F)
        if (str[i] > 0x1F && str[i] < 0x7F)
        {
            str[j++] = str[i];
        }
        i++;
    }
    str[j] = '\0'; // Null-terminate the cleaned string
}

// ===========================================================
// WiFi Connection Task
// ===========================================================

/**
 * @brief Background task that connects to a WiFi network using provided credentials.
 *
 * The credentials string should be in the format "SSID|Password".
 *
 * @param parameter Pointer to a dynamically allocated string containing the credentials.
 */
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

    // Parse credentials; expected format: "SSID|Password"
    if (sscanf(credentials, "%63[^|]|%63s", wifi_ssid, wifi_password) != 2)
    {
        Serial.println("Invalid WiFi data format!");
        free(parameter);
        vTaskDelete(NULL);
        return;
    }

    // Ensure proper null-termination and clean the strings
    wifi_ssid[63] = '\0';
    wifi_password[63] = '\0';

    clean_string(wifi_ssid);
    clean_string(wifi_password);

    // Prepare for WiFi connection
    WiFi.disconnect();
    delay(1000);
    WiFi.mode(WIFI_STA);
    // Begin connection process
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

    // If connected, display details and IP address on OLED
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

/**
 * @brief HTTP POST handler for WiFi setup requests.
 *
 * Expects a JSON payload with a "data" field containing the encrypted WiFi credentials.
 *
 * @param request The HTTP request pointer.
 * @param data Pointer to the received data.
 * @param len Length of the data.
 * @param index Index of the current chunk (for multipart requests).
 * @param total Total size of the data.
 */
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

    // Retrieve encrypted data from the JSON payload
    String encrypted_data = jsonDoc["data"].as<String>();
    char decrypted[128]; // Buffer for decrypted credentials

    // Decrypt the credentials
    if (!decrypt_wifi_credentials(encrypted_data.c_str(), decrypted, sizeof(decrypted)))
    {
        Serial.println("Decryption failed");
        request->send(400, "text/plain", "Decryption Failed");
        return;
    }

    Serial.printf("Decrypted String: [%s]\n", decrypted);

    // Respond to client before initiating the connection task
    request->send(200, "text/plain", "WiFi Credentials Processing...");
    delay(1000);

    // Launch the WiFi connection process in a background task
    xTaskCreate(connectToWiFi, "ConnectToWiFi", 4096, strdup(decrypted), 1, NULL);
}

// ===========================================================
// Access Point Mode Setup
// ===========================================================

/**
 * @brief Starts the device in Access Point (AP) mode for initial provisioning.
 *
 * Displays the AP IP address on the OLED.
 */
void start_ap_mode()
{
    Serial.println("Starting AP Mode...");
    WiFi.softAP(ap_ssid, ap_password);
    IPAddress apIP = WiFi.softAPIP();
    Serial.print("AP IP Address: ");
    Serial.println(apIP);

    // Display AP mode and IP address on OLED
    display.clearDisplay();
    display.setCursor(0, 0);
    display.println("AP Mode Active");
    display.println(apIP.toString());
    display.display();
}

// ===========================================================
// Setup and Loop
// ===========================================================

/**
 * @brief Arduino setup function.
 *
 * Initializes serial communication, the OLED display, WiFi AP mode, and the web server.
 */
void setup()
{
    // Initialize serial communication for debugging
    Serial.begin(115200);

    // Initialize I2C for OLED display
    Wire.begin(SDA_PIN, SCL_PIN);

    // Initialize the OLED display
    if (!display.begin(SSD1306_SWITCHCAPVCC, SCREEN_ADDRESS))
    {
        Serial.println(F("SSD1306 allocation failed"));
        while (true)
            ; // Halt execution if OLED initialization fails
    }

    // Display boot message
    display.clearDisplay();
    display.setTextSize(1);
    display.setTextColor(SSD1306_WHITE);
    display.setCursor(0, 0);
    display.println("Booting...");
    display.display();

    // Start AP mode for initial WiFi provisioning
    start_ap_mode();

    // Set up HTTP endpoints
    // Endpoint for setting WiFi credentials (POST request)
    server.on(
        "/set_wifi", HTTP_POST, [](AsyncWebServerRequest *request) {},
        NULL, handle_wifi_setup);
    // Simple GET endpoint to verify server functionality
    server.on("/", HTTP_GET, [](AsyncWebServerRequest *request)
              { request->send(200, "text/plain", "Hello, world!"); });
    server.begin();
}

/**
 * @brief Arduino loop function.
 *
 * The application is event-driven; the loop does not perform any actions.
 */
void loop()
{
    delay(100);
}
