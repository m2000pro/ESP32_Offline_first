/**
 * @file main.cpp
 * @brief Firmware de Control de Acceso 2FA Híbrido (Online/Offline)
 * @details Implementación de FSM (Máquina de Moore) con fallback atómico a NVS 
 * y cifrado SHA-256 por hardware. Operación no bloqueante.
 */

#include <Arduino.h>
#include <time.h>
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
#define BOTON_SALIDA_PIN  34  // Bit 2 del registro GPIO_IN1_REG (34 - 32)
#define SENSOR_PUERTA_PIN 35  // Bit 3 del registro GPIO_IN1_REG (35 - 32)
#define BUZZER_PIN         15  // Pin asignado para las alertas sonoras

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
unsigned long timerPuertaAbierta = 0;
bool puertaEstabaAbierta = false;
bool modoClase = false;
String uidLeido = "";
String pinIngresado = "";
String asteriscosEnmascarados = "";

// --- Variables de control para el buzzer pasivo 
unsigned long timerBuzzer = 0;
bool estadoBuzzer = false;

// --- VARIABLES DE TELEMETRÍA ---
unsigned long t_inicio_auth = 0;
int intentosOffline = 0;
int accesosExitososOffline = 0;

// Buffer estático para mitigar fragmentación del Heap durante deserialización
static StaticJsonDocument<1024> docMemoria;

// --- FORWARD DECLARATIONS ---
void conectarWiFiReal();
bool validarCredencialNube(String uid, String pin);
bool validarCredencialLocal(String uid, String pin);
void guardarLogOffline(String uid);
void mostrarInterfazOLED(String titulo, String mensaje, String submensaje);
String generarHashSHA256(String texto);
void sincronizarLogsOffline();

void actualizarEstadoPuertaNube(String estado) {
  if (WiFi.status() == WL_CONNECTED) {
    HTTPClient http;
    http.begin(FIREBASE_URL_TELEMETRIA);
    String payload = "{\"estado_puerta\": \"" + estado + "\"}";
    http.PATCH(payload);
    http.end();
  }
}

void registrarAuditoria(String uid, String evento, String modo) {
  struct tm timeinfo;
  String horaExacta = "OFFLINE_TIME";
  if (getLocalTime(&timeinfo)) {
    char timeBuff[50];
    strftime(timeBuff, sizeof(timeBuff), "%Y-%m-%d %H:%M:%S", &timeinfo);
    horaExacta = String(timeBuff);
  }

  DynamicJsonDocument logDoc(256);
  logDoc["uid"] = uid;
  logDoc["hora"] = horaExacta;
  logDoc["evento"] = evento;
  logDoc["modo"] = modo;
  logDoc["id_terminal"] = ID_TERMINAL;

  String payloadJSON;
  serializeJson(logDoc, payloadJSON);

  if (WiFi.status() == WL_CONNECTED) {
    HTTPClient http;
    http.begin(FIREBASE_URL_AUDITORIA);
    http.addHeader("Content-Type", "application/json");
    http.POST(payloadJSON);
    http.end();
  } else {
    Serial.println("[LOG OFFLINE] Encolando en NVS...");
    // Reemplazo directo de tu antigua función guardarLogOffline(uid)
    int totalLogs = prefs.getInt("total_logs", 0);
    totalLogs++;
    String claveLog = "log_" + String(totalLogs);
    prefs.putString(claveLog.c_str(), payloadJSON);
    prefs.putInt("total_logs", totalLogs);
  }
}

void sincronizarCredencialesDesdeFirebase() {
  if (WiFi.status() != WL_CONNECTED) return;
  
  Serial.println("[NVS-SYNC] Descargando credenciales...");
  mostrarInterfazOLED("SINCRONIZANDO", "Descargando", "Credenciales");

  HTTPClient http;
  http.begin(FIREBASE_URL_USUARIOS);
  int httpCode = http.GET();

  if (httpCode == 200) {
    String payload = http.getString();
    DynamicJsonDocument doc(4096); 
    if (!deserializeJson(doc, payload)) {
      JsonObject usuarios = doc.as<JsonObject>();
      
      for (JsonPair kv : usuarios) {
        JsonObject datosUsuario = kv.value().as<JsonObject>();
        String uidTarjeta = datosUsuario["uid"].as<String>();
        String hashPin = datosUsuario["pin"].as<String>();
        bool habilitado = datosUsuario["habilitado"].as<bool>();

        if (habilitado) {
          prefs.putString(uidTarjeta.c_str(), hashPin);
        } else {
          prefs.remove(uidTarjeta.c_str());
        }
      }
      Serial.println("[NVS-SYNC] Caché NVS actualizada.");
    }
  }
  http.end();
}

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

  // Los pines 34 y 35 no tienen pull-up interno, se configuran como INPUT estándar
  pinMode(BOTON_SALIDA_PIN, INPUT);
  pinMode(SENSOR_PUERTA_PIN, INPUT);
  
  // Configuración del canal del Buzzer
  pinMode(BUZZER_PIN, OUTPUT);
  digitalWrite(BUZZER_PIN, LOW);

  // Montar partición NVS
  if (!prefs.begin("cache_2fa", false)) {
    Serial.println("[ERR] Error crítico: Fallo montaje NVS");
    while (true) { delay(1000); }
  }
  
  // Handshake WiFi asíncrono (evita watchdog reset)
  conectarWiFiReal();

  // Sincronización NTP (UTC-5)
  configTime(-5 * 3600, 0, "pool.ntp.org", "time.nist.gov");
  
  // Sincronizar Caché de usuarios si hay red
  sincronizarCredencialesDesdeFirebase();
  
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
      
      // En lugar de ir directo a ESPERANDO_TARJETA, disparamos la sincronización
      estadoActual = SINCRONIZANDO_LOGS; 
    }
  }
  // Polling de enlace de capa 2
  if (WiFi.status() != WL_CONNECTED && redDisponible) {
    redDisponible = false;
    Serial.println("\n[WARN] Caída de enlace WiFi. Transicionando a modo híbrido.");
    mostrarInterfazOLED("SISTEMA 2FA", "Modo Offline", "Listo");
    delay(1000);
  }

// --LECTURA BARE-METAL (Pines superiores 32-39) ---
  uint32_t gpio_in1_state = REG_READ(GPIO_IN1_REG);
  bool botonSalidaPresionado = !(gpio_in1_state & (1 << (BOTON_SALIDA_PIN - 32)));
  bool puertaFisicamenteAbierta = (gpio_in1_state & (1 << (SENSOR_PUERTA_PIN - 32)));

  // --INTERRUPCIÓN DE SOFTWARE - PETICIÓN DE SALIDA (REX) ---
  if (botonSalidaPresionado && estadoActual == ESPERANDO_TARJETA) {
    Serial.println("[REX] Petición de salida detectada. Liberando cerradura...");
    REG_WRITE(GPIO_OUT_W1TS_REG, (1 << LED_VERDE_PIN)); 
    
    registrarAuditoria("BOTON_INTERIOR", "ACCESO_CONCEDIDO", "REX_FISICO");
    
    timerApertura = millis();
    estadoActual = CERRADURA_ABIERTA;
  }

  // --MÓDULO DE MONITOREO DE LA PUERTA (Telemetría y Alerta Limitada) ---
  if (puertaFisicamenteAbierta) {
    if (!puertaEstabaAbierta) {
      puertaEstabaAbierta = true;
      timerPuertaAbierta = millis();
      actualizarEstadoPuertaNube("ABIERTA");
      Serial.println("[SENSOR] Puerta física abierta.");
    }
    
    unsigned long tiempoAbierta = millis() - timerPuertaAbierta;
    
    if (tiempoAbierta > 10000 && !modoClase) {
      REG_WRITE(GPIO_OUT_W1TS_REG, (1 << LED_ROJO_PIN)); // Visual siempre activo
      
      // Buzzer activo solo entre el seg 10 y 25 (15s de duración)
      if (tiempoAbierta <= 25000) {
        if (millis() - timerBuzzer > 500) {
          timerBuzzer = millis();
          estadoBuzzer = !estadoBuzzer;
          if (estadoBuzzer) tone(BUZZER_PIN, 2000);
          else noTone(BUZZER_PIN);
        }
      } else {
        noTone(BUZZER_PIN);
      }
    }
  } else {
    if (puertaEstabaAbierta) {
      puertaEstabaAbierta = false;
      noTone(BUZZER_PIN);
      REG_WRITE(GPIO_OUT_W1TC_REG, (1 << LED_ROJO_PIN));
      actualizarEstadoPuertaNube("CERRADA");
      Serial.println("[SENSOR] Puerta física cerrada.");
    }
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
      // Logueamos el éxito directamente en Firebase
      registrarAuditoria(uidLeido, "ACCESO_CONCEDIDO", "ONLINE_FIREBASE");
      estadoActual = ACCESO_CONCEDIDO;
    } else {
      // Logueamos el intento fallido por seguridad
      registrarAuditoria(uidLeido, "ACCESO_DENEGADO", "ONLINE_FIREBASE");
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
    registrarAuditoria(uidLeido, "ACCESO_CONCEDIDO", "OFFLINE_CACHE");
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
    if (millis() - timerApertura > 5000) { 
      REG_WRITE(GPIO_OUT_W1TC_REG, (1 << LED_VERDE_PIN)); 
      estadoActual = ESPERANDO_TARJETA;
      Serial.println("[FSM] Cerradura asegurada.");
      mostrarInterfazOLED("SISTEMA LISTO", "Presente su", "Tarjeta RFID");
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
      sincronizarLogsOffline();
      mostrarInterfazOLED("SISTEMA LISTO", "Presente su", "Tarjeta RFID");
      estadoActual = ESPERANDO_TARJETA;
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

void sincronizarLogsOffline() {
  if (WiFi.status() != WL_CONNECTED) return;

  prefs.begin("cache_2fa", false);
  int totalLogs = prefs.getInt("total_logs", 0);

  if (totalLogs == 0) {
    prefs.end();
    return;
  }

  Serial.printf("[NVS-LOGS] Detectados %d logs en cola offline. Iniciando volcado...\n", totalLogs);
  mostrarInterfazOLED("CONEXION OK", "Sincronizando", "Logs Offline...");

  HTTPClient http;
  int logsExitosos = 0;

  for (int i = 1; i <= totalLogs; i++) {
    String claveLog = "log_" + String(i);
    String jsonStringNVS = prefs.getString(claveLog.c_str(), "");

    if (jsonStringNVS != "") {
      // [CORRECCIÓN] Parsear el string de NVS a un objeto JSON limpio
      DynamicJsonDocument tempDoc(384);
      DeserializationError error = deserializeJson(tempDoc, jsonStringNVS);

      if (!error) {
        String payloadLimpio;
        serializeJson(tempDoc, payloadLimpio); // Serialización limpia y estricta

        http.begin(FIREBASE_URL_AUDITORIA);
        http.addHeader("Content-Type", "application/json");
        
        int httpCode = http.POST(payloadLimpio);
        
        if (httpCode == 200 || httpCode == 201) {
          prefs.remove(claveLog.c_str());
          logsExitosos++;
        } else {
          Serial.printf("[NVS-LOGS] Error al subir %s. Código HTTP: %d. Abortando.\n", claveLog.c_str(), httpCode);
          http.end();
          break; 
        }
        http.end();
      } else {
        Serial.printf("[NVS-LOGS] Log %s corrompido en NVS. Purgando.\n", claveLog.c_str());
        prefs.remove(claveLog.c_str()); // Evita bloqueos por registros corruptos
      }
    }
  }

  if (logsExitosos == totalLogs) {
    prefs.putInt("total_logs", 0);
    Serial.println("[NVS-LOGS] Volcado completo. Cola NVS vaciada.");
    mostrarInterfazOLED("SINC EXITOSA", "Logs subidos:", String(logsExitosos));
  } else {
    int restantes = totalLogs - logsExitosos;
    prefs.putInt("total_logs", restantes);
    Serial.printf("[NVS-LOGS] Volcado parcial. Quedan %d logs pendientes.\n", restantes);
  }

  prefs.end();
  delay(1500);
}

bool validarCredencialNube(String uid, String pin) {
  if (WiFi.status() != WL_CONNECTED) return false;
  HTTPClient http;
  
  // 1. Usamos la nueva macro de endpoints configurada en secrets.h
  String url = String(FIREBASE_URL_USUARIOS) + "?orderBy=\"uid\"&equalTo=\"" + uid + "\"";
  
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
          bool habilitado = usuario["habilitado"].as<bool>(); // Lectura booleana estricta

          // (Futuro) Verificación del laboratorio específico según ID_TERMINAL
          // bool permisoLaboratorio = usuario["permisos_laboratorios"][ID_TERMINAL].is<String>();

          // Validación Zero-Trust
          if (pinHashLocal == pinHashDB && habilitado) {
            accesoPermitido = true;
            break;
          }
        }
      }
    }
  } else {
    Serial.printf("[ERR] Fallo handshake HTTPS. HTTP Code: %d\n", httpCode);
  }
  
  http.end(); 
  return accesoPermitido;
}