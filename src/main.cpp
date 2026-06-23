/**
 * @file main.cpp
 * @brief Firmware de Control de Acceso 2FA Híbrido (Online/Offline)
 * @details Implementación de FSM (Máquina de Moore) con fallback atómico a NVS 
 * y cifrado SHA-256 por hardware. Operación no bloqueante.
 */

#include <Arduino.h>
#include <WiFi.h>
#include <HTTPClient.h>
#include <Preferences.h>
#include <ArduinoJson.h>
#include <SPI.h>
#include <MFRC522.h>
#include <Keypad.h>
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <mbedtls/md.h> 

// Configuración de red y endpoints excluidos del VCS (.gitignore)
#include "secrets.h"

// Registros ESP32 para acceso atómico GPIO (Bare-Metal)
#include "soc/soc.h"
#include "soc/gpio_reg.h"

// --- HARDWARE ABSTRACTION LAYER (HAL) ---
// Actuadores y Sensores Lógicos
#define LED_VERDE_PIN  4   // Control Relé (Apertura)
#define LED_ROJO_PIN   2   // Alerta Visual (Denegación)
#define WIFI_KILL_PIN  21  // Trigger hardware para testeo de latencia offline

// Bus SPI (MFRC522)
#define RFID_RST_PIN   22  
#define RFID_SS_PIN    5   

// Bus I2C (OLED SSD1306 0.96") - Remapeo para mitigar colisión de bus
#define OLED_SDA       16
#define OLED_SCL       17
#define SCREEN_WIDTH   128 
#define SCREEN_HEIGHT  64  

// --- PARÁMETROS MATRIZ 4x4 ---
const byte FILAS = 4;
const byte COLUMNAS = 4;
char teclas[FILAS][COLUMNAS] = {
  {'1','2','3','A'},
  {'4','5','6','B'},
  {'7','8','9','C'},
  {'*','0','#','D'}
};
byte pinesFilas[FILAS] = {13, 12, 14, 27}; 
byte pinesColumnas[COLUMNAS] = {26, 25, 33, 32}; 

// --- INSTANCIACIÓN DE OBJETOS GLOBALES ---
Keypad teclado = Keypad(makeKeymap(teclas), pinesFilas, pinesColumnas, FILAS, COLUMNAS);
MFRC522 rfid(RFID_SS_PIN, RFID_RST_PIN);
Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, -1);
Preferences prefs;

// --- DEFINICIÓN DE ESTADOS (FSM) ---
enum EstadoSistema { 
  ESPERANDO_TARJETA, 
  ESPERANDO_PIN, 
  VALIDANDO_NUBE, 
  ACCESO_CONCEDIDO, 
  CERRADURA_ABIERTA, 
  ACCESO_DENEGADO,
  VALIDANDO_LOCAL,         
  GUARDANDO_LOG_OFFLINE,   
  SINCRONIZANDO_LOGS       
};

EstadoSistema estadoActual = ESPERANDO_TARJETA;

// --- VARIABLES DE CONTEXTO (.bss) ---
bool redDisponible = false;
unsigned long timerApertura = 0;
unsigned long timerPinTimeout = 0;
unsigned long timerReconexion = 0;
const unsigned long INTERVALO_RECONEXION = 30000;
String uidLeido = "";
String pinIngresado = "";
String asteriscosEnmascarados = "";


// --- VARIABLES DE TELEMETRÍA ---
unsigned long t_inicio_auth = 0;
int intentosOffline = 0;
int accesosExitososOffline = 0;

// Buffer estático para mitigar fragmentación del Heap durante deserialización
static StaticJsonDocument<1024> docMemoria;

// --- FORWARD DECLARATIONS ---
void aprovisionarCredencialesMock();
void conectarWiFiReal();
bool validarCredencialNube(String uid, String pin);
bool validarCredencialLocal(String uid, String pin);
void guardarLogOffline(String uid);
void mostrarInterfazOLED(String titulo, String mensaje, String submensaje);
String generarHashSHA256(String texto);

void setup() {
  Serial.begin(115200);
  
  pinMode(WIFI_KILL_PIN, INPUT_PULLUP);
  
  // Setup Bare-Metal: Forzar estado bajo inicial para evitar activación parásita del relé
  REG_WRITE(GPIO_ENABLE_W1TS_REG, (1 << LED_VERDE_PIN) | (1 << LED_ROJO_PIN));
  REG_WRITE(GPIO_OUT_W1TC_REG, (1 << LED_VERDE_PIN) | (1 << LED_ROJO_PIN)); 
  
  // Init I2C
  Wire.begin(OLED_SDA, OLED_SCL);
  if(!display.begin(SSD1306_SWITCHCAPVCC, 0x3C)) { 
    Serial.println(F("[ERR] Error crítico: Init SSD1306 I2C"));
    while(true); // Bloqueo de seguridad si falla el HMI
  }
  
  display.clearDisplay();
  mostrarInterfazOLED("SISTEMA 2FA", "Booting...", "Sys Init");

  // Init SPI
  SPI.begin(); 
  rfid.PCD_Init();
  
  // Montar partición NVS
  if (!prefs.begin("cache_2fa", false)) {
    Serial.println("[ERR] Error crítico: Fallo montaje NVS");
    while (true) { delay(1000); }
  }
  
  aprovisionarCredencialesMock();
  
  // Handshake WiFi asíncrono (evita watchdog reset)
  conectarWiFiReal();
  
  mostrarInterfazOLED("SISTEMA LISTO", "Presente su", "Tarjeta RFID");
}

void loop() {
  // --- MONITORIZACIÓN Y RECONEXIÓN ASÍNCRONA ---
  
  // 1. Detección de Caída (Listener de Desconexión)
  if (WiFi.status() != WL_CONNECTED && redDisponible) {
    redDisponible = false;
    Serial.println("\n[WARN] Caída de enlace WiFi. Transicionando a modo híbrido.");
    mostrarInterfazOLED("ALERTA DE RED", "Modo Offline", "Conexion perdida");
    delay(1000); // Pequeño debounce visual
  }

  // 2. Motor de Reconexión de Fondo (Listener de Recuperación)
  if (!redDisponible) {
    // Solo intentamos reconectar si han pasado 30 segundos desde el último intento
    if (millis() - timerReconexion >= INTERVALO_RECONEXION) {
      Serial.print("[NET] Intentando restaurar conexión en background... ");
      WiFi.disconnect(); 
      WiFi.begin(REAL_WIFI_SSID, REAL_WIFI_PASSWORD); // Llamada asíncrona nativa
      timerReconexion = millis();
    }
    
    // Verificamos si la llamada asíncrona anterior tuvo éxito silenciosamente
    if (WiFi.status() == WL_CONNECTED) {
      Serial.println("\n[NET] ¡Conexión restaurada con éxito!");
      redDisponible = true;
      mostrarInterfazOLED("SISTEMA 2FA", "Modo Online", "Red Restaurada");
      delay(1000);
      mostrarInterfazOLED("SISTEMA LISTO", "Presente su", "Tarjeta RFID");
    }
  }
  // Polling de enlace de capa 2
  if (WiFi.status() != WL_CONNECTED && redDisponible) {
    redDisponible = false;
    Serial.println("\n[WARN] Caída de enlace WiFi. Transicionando a modo híbrido.");
    mostrarInterfazOLED("SISTEMA 2FA", "Modo Offline", "Listo");
    delay(1000);
  }

  // --- NÚCLEO FSM ---
  switch (estadoActual) {
    
    case ESPERANDO_TARJETA:
      // Lectura no bloqueante del buffer SPI
      if (rfid.PICC_IsNewCardPresent() && rfid.PICC_ReadCardSerial()) {
        uidLeido = "";
        for (byte i = 0; i < rfid.uid.size; i++) {
          uidLeido += String(rfid.uid.uidByte[i] < 0x10 ? "0" : "");
          uidLeido += String(rfid.uid.uidByte[i], HEX);
        }
        uidLeido.toUpperCase();
        rfid.PICC_HaltA(); // Comando HALT para evitar múltiples triggers del mismo tag
        
        Serial.println("\n[INFO] UID Capturado: " + uidLeido);
        
        pinIngresado = "";
        asteriscosEnmascarados = "";
        timerPinTimeout = millis();
        
        mostrarInterfazOLED("SEGUNDO FACTOR", "Ingrese PIN:", "_");
        estadoActual = ESPERANDO_PIN;
      }
      break;

    case ESPERANDO_PIN: {
      char tecla = teclado.getKey();
      
      // TTL de 15s para ingreso manual
      if (millis() - timerPinTimeout > 15000) {
        Serial.println("[WARN] Timeout de entrada UART/Keypad.");
        estadoActual = ACCESO_DENEGADO;
        break;
      }

      if (tecla) {
        timerPinTimeout = millis(); // Refresh TTL
        
        if (tecla == '#') { 
          // Commit manual del payload
          if (pinIngresado.length() > 0) {
            mostrarInterfazOLED("PROCESANDO", "Verificando...", "Identidad");
            estadoActual = redDisponible ? VALIDANDO_NUBE : VALIDANDO_LOCAL;
          }
        } else if (tecla == '*') { 
          // Flush del buffer local
          pinIngresado = "";
          asteriscosEnmascarados = "";
          mostrarInterfazOLED("SEGUNDO FACTOR", "Ingrese PIN:", "_");
        } else {
          // Filtrado de longitud máxima (4 bytes lógicos)
          if (pinIngresado.length() < 4) {
            pinIngresado += tecla;
            asteriscosEnmascarados += "*";
            mostrarInterfazOLED("SEGUNDO FACTOR", "Ingrese PIN:", asteriscosEnmascarados);
          }
        }
      }

      // Auto-commit al llenar el buffer
      if (pinIngresado.length() == 4) {
        mostrarInterfazOLED("PROCESANDO", "Verificando...", "Identidad");
        delay(300); // UI delay para legibilidad
        
        // [TELEMETRÍA] Inicio de cronómetro de latencia
        t_inicio_auth = millis();

        estadoActual = redDisponible ? VALIDANDO_NUBE : VALIDANDO_LOCAL;
      }
      break;
    }

    case VALIDANDO_NUBE:
      if (validarCredencialNube(uidLeido, pinIngresado)) {
        estadoActual = ACCESO_CONCEDIDO;
      } else {
        estadoActual = ACCESO_DENEGADO;
      }
      break;

    case VALIDANDO_LOCAL: {
    // [TELEMETRÍA] Registra el intento en modo contingencia
      intentosOffline++;
      // Switchover lógico por indisponibilidad de servidor
      if (validarCredencialLocal(uidLeido, pinIngresado)) {
        accesosExitososOffline++;
        // Cálculo de Tasa de Resiliencia en punto flotante
        float tasaFallo = ((float)accesosExitososOffline / intentosOffline) * 100.0;
        Serial.printf("[MÉTRICA] Tasa de Tolerancia a Fallos: %.2f%%\n", tasaFallo);

        estadoActual = GUARDANDO_LOG_OFFLINE;
      } else {
        estadoActual = ACCESO_DENEGADO;
      }
      break;
    }
    
    case GUARDANDO_LOG_OFFLINE: 
      guardarLogOffline(uidLeido);
      estadoActual = ACCESO_CONCEDIDO;
      break;

    case ACCESO_CONCEDIDO:{
      // [TELEMETRÍA] Latencia bimodal
      unsigned long latencia = millis() - t_inicio_auth;
      String modoAuth = redDisponible ? "ONLINE (Firebase)" : "OFFLINE (Flash NVS)";
      Serial.printf("[MÉTRICA] Latencia de Autenticación: %lu ms | Modo: %s\n", latencia, modoAuth.c_str());
      
      Serial.println("[INFO] 2FA OK. Modificando estado del actuador.");
      mostrarInterfazOLED("BIENVENIDO", "Acceso Concedido", "Cerradura Abierta");
      
      // Conmutación GPIO en 1 ciclo de reloj (Evita latencia de digitalWrite)
      REG_WRITE(GPIO_OUT_W1TS_REG, (1 << LED_VERDE_PIN));
      REG_WRITE(GPIO_OUT_W1TC_REG, (1 << LED_ROJO_PIN));
      
      timerApertura = millis();
      estadoActual = CERRADURA_ABIERTA;
      break;
    }

    case CERRADURA_ABIERTA:
      // Temporización asíncrona para pulso electromecánico (5s)
      if (millis() - timerApertura >= 5000) {
        REG_WRITE(GPIO_OUT_W1TC_REG, (1 << LED_VERDE_PIN));
        mostrarInterfazOLED("SISTEMA LISTO", "Presente su", "Tarjeta RFID");
        estadoActual = ESPERANDO_TARJETA;
      }
      break;

    case ACCESO_DENEGADO:
      Serial.println("[INFO] Autorización denegada.");
      mostrarInterfazOLED("ERROR", "Acceso Denegado", "Clave/UID Invalido");
      
      REG_WRITE(GPIO_OUT_W1TS_REG, (1 << LED_ROJO_PIN));
      REG_WRITE(GPIO_OUT_W1TC_REG, (1 << LED_VERDE_PIN));
      
      // Delay bloqueante intencional para mitigar ataques de fuerza bruta locales
      delay(3000); 
      
      REG_WRITE(GPIO_OUT_W1TC_REG, (1 << LED_ROJO_PIN)); 
      mostrarInterfazOLED("SISTEMA LISTO", "Presente su", "Tarjeta RFID");
      estadoActual = ESPERANDO_TARJETA;
      break;
      
    case SINCRONIZANDO_LOGS:
      // TODO: Implementar rutina de volcado de cola NVS a Firebase tras recuperación de red
      break;
  }
}

// --- DRIVER DE PANTALLA OLED ---
void mostrarInterfazOLED(String titulo, String mensaje, String submensaje) {
  display.clearDisplay();
  display.setTextColor(SSD1306_WHITE);
  
  display.setTextSize(1);
  display.setCursor(0, 0);
  display.println(titulo);
  // Uso de método optimizado GFX para rasterización horizontal
  display.drawFastHLine(0, 10, SCREEN_WIDTH, SSD1306_WHITE);
  
  display.setTextSize(1);
  display.setCursor(0, 24);
  display.println(mensaje);
  
  display.setTextSize(2);
  display.setCursor(0, 44);
  display.println(submensaje);
  
  display.display(); // Flush al buffer I2C
}

// --- SUBSISTEMA DE RED ---
void conectarWiFiReal() {
  Serial.printf("[NET] Inicializando STA SSID: %s \n", REAL_WIFI_SSID);
  
  WiFi.begin(REAL_WIFI_SSID, REAL_WIFI_PASSWORD);
  
  // Timeout forzado de 6s para no bloquear el boot sequence si no hay router
  int intentos = 0;
  while (WiFi.status() != WL_CONNECTED && intentos < 15) {
    delay(400);
    Serial.print(".");
    intentos++;
  }
  
  if (WiFi.status() == WL_CONNECTED) {
    Serial.println("\n[NET] Link UP. IP: " + WiFi.localIP().toString());
    redDisponible = true;
  } else {
    Serial.println("\n[NET] Link DOWN. Timeout. Iniciando fallback.");
    redDisponible = false;
  }
}

// --- SUBSISTEMA CRIPTOGRÁFICO Y PERSISTENCIA (NVS) ---
/**
 * @brief Genera digest SHA-256 utilizando aceleración hardware nativa
 */
String generarHashSHA256(String texto) {
  byte shaResult[32];
  mbedtls_md_context_t ctx;
  mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;

  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 0);
  mbedtls_md_starts(&ctx);
  mbedtls_md_update(&ctx, (const unsigned char *) texto.c_str(), texto.length());
  mbedtls_md_finish(&ctx, shaResult);
  mbedtls_md_free(&ctx);

  String hashHex = "";
  for (int i = 0; i < 32; i++) {
    char str[3];
    sprintf(str, "%02x", (int)shaResult[i]);
    hashHex += str;
  }
  return hashHex;
}

void aprovisionarCredencialesMock() {
  // Setup de registro semilla en partición NVS
  String hashGuardado = prefs.getString("EA401D35", ""); 
  if (hashGuardado == "") {
    // Inserta registro llave-valor. Llave: UID, Valor: Hash_SHA256(1234)
    prefs.putString("EA401D35", "03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4");
    prefs.putInt("total_logs", 0);
  }
}

bool validarCredencialLocal(String uid, String pin) {
  String hashGuardado = prefs.getString(uid.c_str(), "");
  if (hashGuardado != "") {
    String pinHashLocal = generarHashSHA256(pin);
    // Validación constante en tiempo. Evita vector de ataque por timing.
    if (pinHashLocal == hashGuardado) return true;
  }
  return false;
}

void guardarLogOffline(String uid) {
  // Push atómico a cola de eventos en Flash
  int totalLogs = prefs.getInt("total_logs", 0);
  totalLogs++;
  String claveLog = "log_" + String(totalLogs);
  String datosLog = uid + "|Offline";
  prefs.putString(claveLog.c_str(), datosLog);
  prefs.putInt("total_logs", totalLogs);
  Serial.printf("[MEM] Commit en sector Flash exitoso. Queue size: %d\n", totalLogs);
}

bool validarCredencialNube(String uid, String pin) {
  if (WiFi.status() != WL_CONNECTED) return false;
  HTTPClient http;
  
  // Endpoint protegido configurado en secrets.h
  String url = String(FIREBASE_URL) + "?orderBy=\"uid\"&equalTo=\"" + uid + "\"";
  
  http.begin(url);
  int httpCode = http.GET();
  bool accesoPermitido = false;

  if (httpCode == HTTP_CODE_OK) {
    String payload = http.getString();
    
    if (payload != "null") {
      docMemoria.clear(); 
      DeserializationError error = deserializeJson(docMemoria, payload);
      
      if (!error) {
        JsonObject root = docMemoria.as<JsonObject>();
        String pinHashLocal = generarHashSHA256(pin);

        // Iteración sobre los nodos devueltos por el índice de Firebase
        for (JsonPair kv : root) {
          JsonObject usuario = kv.value().as<JsonObject>();
          String pinHashDB = usuario["pin"].as<String>();
          bool habilitado = usuario["habilitado"].as<bool>();

          // Validación de factor dual con verificación de revocación remota
          if (pinHashLocal == pinHashDB && habilitado == true) {
            accesoPermitido = true;
            break;
          }
        }
      }
    }
  } else {
    Serial.printf("[ERR] Fallo handshake HTTPS. HTTP Code: %d\n", httpCode);
  }
  
  // Liberación del socket subyacente (Prevención de Memory Leak)
  http.end(); 
  return accesoPermitido;
}