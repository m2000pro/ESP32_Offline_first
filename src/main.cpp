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
#include <WebServer.h>

// Configuración de red y endpoints excluidos del VCS (.gitignore)
#include "secrets.h"

// Registros ESP32 para acceso atómico GPIO (Bare-Metal)
#include "soc/soc.h"
#include "soc/gpio_reg.h"

// --- HARDWARE ABSTRACTION LAYER (HAL) ---
#define LED_VERDE_PIN  4   
#define LED_ROJO_PIN   2   
#define WIFI_KILL_PIN  21  
#define BOTON_SALIDA_PIN  34  
#define SENSOR_PUERTA_PIN 35  
#define BUZZER_PIN         15  

#define RFID_RST_PIN   22  
#define RFID_SS_PIN    5   

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
WebServer server(80);

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
  SINCRONIZANDO_LOGS,
  ESPERANDO_CLAVE_MAESTRA,
  CONFIGURACION_WIFI       
};

EstadoSistema estadoActual = ESPERANDO_TARJETA;

// --- VARIABLES DE CONTEXTO (.bss) ---
bool redDisponible = false;
unsigned long timerApertura = 0;
unsigned long timerPinTimeout = 0;
unsigned long timerReconexion = 0;
const unsigned long INTERVALO_RECONEXION = 30000;
unsigned long timerPuertaAbierta = 0;
unsigned long timerAdmin = 0;
bool puertaEstabaAbierta = false;
bool modoClase = false;
String uidLeido = "";
String pinIngresado = "";
String asteriscosEnmascarados = "";
Preferences prefsWiFi;
String bufferAdmin = "";

unsigned long timerBuzzer = 0;
bool estadoBuzzer = false;

// --- VARIABLES DE TELEMETRÍA ---
unsigned long t_inicio_auth = 0;
int intentosOffline = 0;
int accesosExitososOffline = 0;

static StaticJsonDocument<1024> docMemoria;

// --- FORWARD DECLARATIONS ---
void conectarWiFiReal();
int validarCredencialNube(String uid, String pin);
bool validarCredencialLocal(String uid, String pin);
void mostrarInterfazOLED(String titulo, String mensaje, String submensaje);
String generarHashSHA256(String texto);
void sincronizarLogsOffline();
void iniciarModoAP();
void handleRoot();
void handleSave();

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
    http.setTimeout(2500);
    http.addHeader("Content-Type", "application/json");
    http.POST(payloadJSON);
    http.end();
  } else {
    int totalLogs = prefs.getInt("total_logs", 0);
    totalLogs++;
    String claveLog = "log_" + String(totalLogs);
    prefs.putString(claveLog.c_str(), payloadJSON);
    prefs.putInt("total_logs", totalLogs);
    Serial.printf("[LOG OFFLINE] Encolado en NVS (Posición %d)\n", totalLogs);
  }
}

void sincronizarCredencialesDesdeFirebase() {
  if (WiFi.status() != WL_CONNECTED) return;
  Serial.println("[NVS-SYNC] Descargando credenciales...");

  HTTPClient http;
  http.setTimeout(4000); // Límite de 4 segundos por intento

  int intentos = 0;
  int httpCode = -1;
  
  // Bucle de reintento para superar la latencia de DNS del router
  while (intentos < 3 && httpCode <= 0) {
    http.begin(FIREBASE_URL_USUARIOS);
    httpCode = http.GET();
    
    if (httpCode <= 0) {
      Serial.printf("[NVS-SYNC] DNS/Timeout (HTTP %d). Reintentando en 2s...\n", httpCode);
      delay(2000);
    }
    intentos++;
  }

  if (httpCode == 200) {
    String payload = http.getString();
    DynamicJsonDocument doc(4096); 
    DeserializationError error = deserializeJson(doc, payload);
    
    if (!error) {
      JsonObject usuarios = doc.as<JsonObject>();
      int agregados = 0;
      
      for (JsonPair kv : usuarios) {
        JsonObject datosUsuario = kv.value().as<JsonObject>();
        String uidTarjeta = datosUsuario["uid"].as<String>();
        String hashPin = datosUsuario["pin"].as<String>();
        bool habilitado = datosUsuario["habilitado"].as<bool>();

        if (habilitado) {
          prefs.putString(uidTarjeta.c_str(), hashPin);
          agregados++;
        } else {
          prefs.remove(uidTarjeta.c_str());
        }
      }
      Serial.printf("[NVS-SYNC] Caché NVS actualizada. %d usuarios habilitados.\n", agregados);
    }
  } else {
    Serial.printf("[ERR] Sincronización abortada. HTTP Final: %d\n", httpCode);
  }
  http.end();
}

String obtenerClaveMaestra() {
  prefsWiFi.begin("wifi_net", true); // Solo lectura
  // Si no hay una clave guardada por el cliente, usa la de fábrica
  String clave = prefsWiFi.getString("pin_admin", CLAVE_MAESTRA_ADMIN);
  prefsWiFi.end();
  return clave;
}

void setup() {
  Serial.begin(115200);
  
  pinMode(WIFI_KILL_PIN, INPUT_PULLUP);
  
  REG_WRITE(GPIO_ENABLE_W1TS_REG, (1 << LED_VERDE_PIN) | (1 << LED_ROJO_PIN));
  REG_WRITE(GPIO_OUT_W1TC_REG, (1 << LED_VERDE_PIN) | (1 << LED_ROJO_PIN)); 
  
  Wire.begin(OLED_SDA, OLED_SCL);
  if(!display.begin(SSD1306_SWITCHCAPVCC, 0x3C)) { 
    Serial.println(F("[ERR] Error crítico: Init SSD1306 I2C"));
    while(true); 
  }
  
  display.clearDisplay();
  mostrarInterfazOLED("SISTEMA 2FA", "Booting...", "Sys Init");

  SPI.begin(); 
  rfid.PCD_Init();

  pinMode(BOTON_SALIDA_PIN, INPUT);
  pinMode(SENSOR_PUERTA_PIN, INPUT);
  
  pinMode(BUZZER_PIN, OUTPUT);
  digitalWrite(BUZZER_PIN, LOW);

  if (!prefs.begin("cache_2fa", false)) {
    Serial.println("[ERR] Error crítico: Fallo montaje NVS");
    while (true) { delay(1000); }
  }

  // prefs.clear(); // Descomentar solo para limpieza inicial si la memoria NVS está corrupta

  conectarWiFiReal();
  configTime(-5 * 3600, 0, "pool.ntp.org", "time.nist.gov");
  sincronizarCredencialesDesdeFirebase();
  
  mostrarInterfazOLED("SISTEMA LISTO", "Presente su", "Tarjeta RFID");
}

void loop() {
  // --- MONITORIZACIÓN Y RECONEXIÓN ASÍNCRONA ---
  if (estadoActual != CONFIGURACION_WIFI && 
      estadoActual != ESPERANDO_CLAVE_MAESTRA && 
      estadoActual != ACCESO_CONCEDIDO && 
      estadoActual != CERRADURA_ABIERTA) {
    
    if (WiFi.status() != WL_CONNECTED && redDisponible) {
      redDisponible = false;
      Serial.println("\n[WARN] Caída de enlace WiFi. Transicionando a modo híbrido.");
      mostrarInterfazOLED("ALERTA DE RED", "Modo Offline", "Conexion perdida");
      delay(1000); 
    }

    if (!redDisponible) {
      if (millis() - timerReconexion >= INTERVALO_RECONEXION) {
        Serial.print("[NET] Intentando restaurar conexión en background... ");
        WiFi.disconnect(); 
        WiFi.begin(REAL_WIFI_SSID, REAL_WIFI_PASSWORD); 
        timerReconexion = millis();
      }
      
      if (WiFi.status() == WL_CONNECTED) {
        Serial.println("\n[NET] ¡Conexión restaurada con éxito!");
        redDisponible = true;
        estadoActual = SINCRONIZANDO_LOGS; 
      }
    }
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

  // --MÓDULO DE MONITOREO DE LA PUERTA ---
  if (puertaFisicamenteAbierta) {
    if (!puertaEstabaAbierta) {
      puertaEstabaAbierta = true;
      timerPuertaAbierta = millis();
      actualizarEstadoPuertaNube("ABIERTA");
      Serial.println("[SENSOR] Puerta física abierta.");
    }
    
    unsigned long tiempoAbierta = millis() - timerPuertaAbierta;
    
    if (tiempoAbierta > 10000 && !modoClase) {
      REG_WRITE(GPIO_OUT_W1TS_REG, (1 << LED_ROJO_PIN)); 
      
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
    case ESPERANDO_TARJETA: {
      char teclaIdle = teclado.getKey();
      if (teclaIdle == '*') {
        Serial.println("[FSM] Iniciando autenticación administrativa...");
        bufferAdmin = "";
        timerAdmin = millis();
        mostrarInterfazOLED("MODO ADMIN", "Clave Maestra:", "_");
        estadoActual = ESPERANDO_CLAVE_MAESTRA;
        break; 
      }

      if (rfid.PICC_IsNewCardPresent() && rfid.PICC_ReadCardSerial()) {
        uidLeido = "";
        for (byte i = 0; i < rfid.uid.size; i++) {
          uidLeido += String(rfid.uid.uidByte[i] < 0x10 ? "0" : "");
          uidLeido += String(rfid.uid.uidByte[i], HEX);
        }
        uidLeido.toUpperCase();
        rfid.PICC_HaltA(); 
        
        Serial.println("\n[INFO] UID Capturado: " + uidLeido);
        
        pinIngresado = "";
        asteriscosEnmascarados = "";
        timerPinTimeout = millis();
        
        mostrarInterfazOLED("SEGUNDO FACTOR", "Ingrese PIN:", "_");
        estadoActual = ESPERANDO_PIN;
      }
      break;
    }
    
    case ESPERANDO_CLAVE_MAESTRA: {
      char teclaAdmin = teclado.getKey();
      
      if (millis() - timerAdmin > 10000) {
        Serial.println("[ADMIN] Timeout de ingreso. Abortando.");
        mostrarInterfazOLED("SISTEMA LISTO", "Presente su", "Tarjeta RFID");
        estadoActual = ESPERANDO_TARJETA;
        break;
      }

      if (teclaAdmin) {
        timerAdmin = millis(); 
        
        if (teclaAdmin == '#') { 
          if (bufferAdmin == obtenerClaveMaestra()) {
            Serial.println("[ADMIN] Autenticación exitosa. Levantando Portal Wi-Fi.");
            iniciarModoAP(); 
            estadoActual = CONFIGURACION_WIFI;
            timerApertura = millis(); 
          } else {
            Serial.println("[ADMIN] Clave incorrecta. Bloqueando acceso.");
            mostrarInterfazOLED("ERROR", "Clave Invalida", "Acceso Denegado");
            
            REG_WRITE(GPIO_OUT_W1TS_REG, (1 << LED_ROJO_PIN));
            delay(2000); 
            REG_WRITE(GPIO_OUT_W1TC_REG, (1 << LED_ROJO_PIN));
            
            mostrarInterfazOLED("SISTEMA LISTO", "Presente su", "Tarjeta RFID");
            estadoActual = ESPERANDO_TARJETA;
          }
        } else if (teclaAdmin == '*') {
          mostrarInterfazOLED("SISTEMA LISTO", "Presente su", "Tarjeta RFID");
          estadoActual = ESPERANDO_TARJETA;
        } else {
          if (bufferAdmin.length() < 8) {
            bufferAdmin += teclaAdmin;
            String mascara = "";
            for(int i=0; i<bufferAdmin.length(); i++) mascara += "*";
            mostrarInterfazOLED("MODO ADMIN", "Clave Maestra:", mascara);
          }
        }
      }
      break;
    }

    case CONFIGURACION_WIFI:
      server.handleClient();
      if (millis() - timerApertura > 180000) { 
        Serial.println("[AP] Timeout de configuración. Reiniciando...");
        ESP.restart();
      }
      break;

    case ESPERANDO_PIN: {
      char tecla = teclado.getKey();
      
      if (millis() - timerPinTimeout > 15000) {
        Serial.println("[WARN] Timeout de entrada UART/Keypad.");
        estadoActual = ACCESO_DENEGADO;
        break;
      }

      if (tecla) {
        timerPinTimeout = millis(); 
        
        if (tecla == '#') { 
          if (pinIngresado.length() > 0) {
            mostrarInterfazOLED("PROCESANDO", "Verificando...", "Identidad");
            // [AJUSTE] Verificación directa del estado físico del driver Wi-Fi antes de conmutar
            redDisponible = (WiFi.status() == WL_CONNECTED);
            estadoActual = redDisponible ? VALIDANDO_NUBE : VALIDANDO_LOCAL;
          }
        } else if (tecla == '*') { 
          pinIngresado = "";
          asteriscosEnmascarados = "";
          mostrarInterfazOLED("SEGUNDO FACTOR", "Ingrese PIN:", "_");
        } else {
          if (pinIngresado.length() < 4) {
            pinIngresado += tecla;
            asteriscosEnmascarados += "*";
            mostrarInterfazOLED("SEGUNDO FACTOR", "Ingrese PIN:", asteriscosEnmascarados);
          }
        }
      }

      if (pinIngresado.length() == 4) {
        mostrarInterfazOLED("PROCESANDO", "Verificando...", "Identidad");
        delay(150); 
        t_inicio_auth = millis();
        //Verificación directa del estado físico del driver Wi-Fi antes de conmutar
        redDisponible = (WiFi.status() == WL_CONNECTED);
        estadoActual = redDisponible ? VALIDANDO_NUBE : VALIDANDO_LOCAL;
      }
      break;
    }

    case VALIDANDO_NUBE: {
      int estadoAuth = validarCredencialNube(uidLeido, pinIngresado);
      
      if (estadoAuth == 1) {
        registrarAuditoria(uidLeido, "ACCESO_CONCEDIDO", "ONLINE_FIREBASE");
        estadoActual = ACCESO_CONCEDIDO;
      } else if (estadoAuth == 0) {
        registrarAuditoria(uidLeido, "ACCESO_DENEGADO", "ONLINE_FIREBASE");
        estadoActual = ACCESO_DENEGADO;
      } else {
        // estadoAuth == -1 (Falso positivo de red: Hay Wi-Fi pero no internet)
        Serial.println("[WARN] Servidor inalcanzable. Conmutando a caché NVS...");
        redDisponible = false; // Forzamos bandera para evitar futuros cuelgues
        estadoActual = VALIDANDO_LOCAL; // Redirige el flujo al modo Offline
      }
      break;
    };

    case VALIDANDO_LOCAL: {
      intentosOffline++;
      if (validarCredencialLocal(uidLeido, pinIngresado)) {
        accesosExitososOffline++;
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
      unsigned long latencia = millis() - t_inicio_auth;
      String modoAuth = redDisponible ? "ONLINE (Firebase)" : "OFFLINE (Flash NVS)";
      Serial.printf("[MÉTRICA] Latencia de Autenticación: %lu ms | Modo: %s\n", latencia, modoAuth.c_str());
      
      Serial.println("[INFO] 2FA OK. Modificando estado del actuador.");
      mostrarInterfazOLED("BIENVENIDO", "Acceso Concedido", "Cerradura Abierta");
      
      REG_WRITE(GPIO_OUT_W1TS_REG, (1 << LED_VERDE_PIN));
      REG_WRITE(GPIO_OUT_W1TC_REG, (1 << LED_ROJO_PIN));
      
      timerApertura = millis();
      estadoActual = CERRADURA_ABIERTA;
      break;
    }

    case CERRADURA_ABIERTA:
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
  display.drawFastHLine(0, 10, SCREEN_WIDTH, SSD1306_WHITE);
  
  display.setTextSize(1);
  display.setCursor(0, 24);
  display.println(mensaje);
  
  display.setTextSize(2);
  display.setCursor(0, 44);
  display.println(submensaje);
  
  display.display(); 
}

// --- SUBSISTEMA DE RED ---
void conectarWiFiReal() {
  prefsWiFi.begin("wifi_net", true); 
  String savedSSID = prefsWiFi.getString("ssid", "");
  String savedPass = prefsWiFi.getString("pass", "");
  prefsWiFi.end();

  String targetSSID = (savedSSID != "") ? savedSSID : String(REAL_WIFI_SSID);
  String targetPass = (savedPass != "") ? savedPass : String(REAL_WIFI_PASSWORD);

  WiFi.mode(WIFI_STA);       
  WiFi.disconnect(true);     
  delay(100);                

  Serial.printf("[NET] Inicializando STA SSID: %s \n", targetSSID.c_str());
  WiFi.begin(targetSSID.c_str(), targetPass.c_str());
  
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

void handleRoot() {
  String html = "<html><body style='font-family:sans-serif; text-align:center; margin-top:30px; background-color:#0B1320; color:white;'>";
  html += "<h2>Panel de Administracion LabAccess</h2>";
  html += "<form action='/save' method='POST' style='background-color:#121B2A; padding:20px; border-radius:10px; display:inline-block;'>";
  html += "<h3 style='color:#0BB885;'>1. Conexion Wi-Fi</h3>";
  html += "<input type='text' name='ssid' placeholder='Nombre de la Red (SSID)' required style='padding:8px; width:200px;'><br><br>";
  html += "<input type='password' name='pass' placeholder='Contrasena Wi-Fi' style='padding:8px; width:200px;'><br><br>";
  
  html += "<h3 style='color:#0BB885;'>2. Seguridad del Teclado</h3>";
  html += "<input type='text' name='new_admin_pin' placeholder='Nueva Clave Maestra (Opcional)' style='padding:8px; width:200px;'><br><br>";
  
  html += "<input type='submit' value='Guardar y Reiniciar' style='background:#0BB885; color:#0B1320; padding:10px 20px; border:none; border-radius:5px; font-weight:bold; cursor:pointer;'>";
  html += "</form></body></html>";
  server.send(200, "text/html", html);
}

void handleSave() {
  if (server.hasArg("ssid")) {
    String newSSID = server.arg("ssid");
    String newPass = server.arg("pass"); 
    String newAdminPin = server.arg("new_admin_pin");

    prefsWiFi.begin("wifi_net", false); // Modo escritura
    prefsWiFi.putString("ssid", newSSID);
    prefsWiFi.putString("pass", newPass);
    
    // Si el cliente rellenó el campo de nueva clave, se sobreescribe
    if (newAdminPin != "") {
      prefsWiFi.putString("pin_admin", newAdminPin);
      Serial.println("[AP] Nueva Clave Maestra registrada en NVS.");
    }
    
    prefsWiFi.end();

    String htmlExito = "<html><body style='background-color:#0B1320; color:#0BB885; text-align:center; margin-top:50px;'>";
    htmlExito += "<h2>Configuracion guardada exitosamente.</h2><p>El terminal se esta reiniciando...</p></body></html>";
    server.send(200, "text/html", htmlExito);
    
    delay(1500);
    ESP.restart(); 
  }
}

void iniciarModoAP() {
  WiFi.disconnect();
  WiFi.mode(WIFI_AP);
  WiFi.softAP("LabAccess_Config", "admin123"); 
  
  server.on("/", handleRoot);
  server.on("/save", HTTP_POST, handleSave);
  server.begin(); 
  
  Serial.println("[AP] Portal iniciado. Conéctate a 'LabAccess_Config'. IP: 192.168.4.1");
  mostrarInterfazOLED("MODO CONFIG", "Red: LabAccess_Config", "IP: 192.168.4.1");
}

// --- SUBSISTEMA CRIPTOGRÁFICO Y PERSISTENCIA (NVS) ---
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
    if (pinHashLocal == hashGuardado) return true;
  }
  return false;
}

void sincronizarLogsOffline() {
  if (WiFi.status() != WL_CONNECTED) return;

  int totalLogs = prefs.getInt("total_logs", 0);
  if (totalLogs == 0) return;

  Serial.printf("[NVS-LOGS] Iniciando volcado de %d logs offline...\n", totalLogs);
  mostrarInterfazOLED("CONEXION OK", "Sincronizando", "Logs Offline...");

  HTTPClient http;
  int logsProcesados = 0; 

  for (int i = 1; i <= totalLogs; i++) {
    String claveLog = "log_" + String(i);
    String jsonStringNVS = prefs.getString(claveLog.c_str(), "");

    if (jsonStringNVS != "") {
      DynamicJsonDocument tempDoc(384);
      DeserializationError error = deserializeJson(tempDoc, jsonStringNVS);

      if (!error) {
        String payloadLimpio;
        serializeJson(tempDoc, payloadLimpio);

        http.begin(FIREBASE_URL_AUDITORIA);
        http.addHeader("Content-Type", "application/json");
        int httpCode = http.POST(payloadLimpio);
        http.end();
        
        if (httpCode == 200 || httpCode == 201) {
          prefs.remove(claveLog.c_str());
          logsProcesados++;
        } else {
          Serial.printf("[NVS-LOGS] Error HTTP %d al subir %s. Pausando volcado.\n", httpCode, claveLog.c_str());
          break; 
        }
      } else {
        Serial.printf("[NVS-LOGS] Log %s corrompido. Purgando.\n", claveLog.c_str());
        prefs.remove(claveLog.c_str());
        logsProcesados++; 
      }
    } else {
      logsProcesados++; 
    }
  }

  if (logsProcesados == totalLogs) {
    prefs.putInt("total_logs", 0);
    Serial.println("[NVS-LOGS] Volcado 100% completado. Cola NVS vaciada.");
    mostrarInterfazOLED("SINC EXITOSA", "Logs subidos:", String(logsProcesados));
  } else if (logsProcesados > 0) {
    int pendientes = totalLogs - logsProcesados;
    Serial.printf("[NVS-LOGS] Desplazando cola. Moviendo %d logs pendientes al inicio...\n", pendientes);
    
    for (int i = 1; i <= pendientes; i++) {
      String claveVieja = "log_" + String(i + logsProcesados);
      String claveNueva = "log_" + String(i);
      String dato = prefs.getString(claveVieja.c_str(), "");
      
      if (dato != "") {
        prefs.putString(claveNueva.c_str(), dato);
        prefs.remove(claveVieja.c_str());
      }
    }
    prefs.putInt("total_logs", pendientes);
    Serial.printf("[NVS-LOGS] Cola reajustada. Quedan %d logs.\n", pendientes);
  }

  delay(1500); 
}

int validarCredencialNube(String uid, String pin) {
  if (WiFi.status() != WL_CONNECTED) return -1;
  HTTPClient http;
  
  String url = String(FIREBASE_URL_USUARIOS) + "?orderBy=\"uid\"&equalTo=\"" + uid + "\"";
  
  http.begin(url);
  http.setTimeout(2500); // Evita bloqueos
  int httpCode = http.GET();
  int resultado = 0; // 0 = Denegado, 1 = Concedido, -1 = Fallo de red

  if (httpCode == HTTP_CODE_OK) {
    String payload = http.getString();
    
    if (payload != "null") {
      docMemoria.clear(); 
      DeserializationError error = deserializeJson(docMemoria, payload);
      
      if (!error) {
        JsonObject root = docMemoria.as<JsonObject>();
        String pinHashLocal = generarHashSHA256(pin);

        for (JsonPair kv : root) {
          JsonObject usuario = kv.value().as<JsonObject>();
          String pinHashDB = usuario["pin"].as<String>();
          bool habilitado = usuario["habilitado"].as<bool>(); 

          if (pinHashLocal == pinHashDB && habilitado) {
            resultado = 1;
            break;
          }
        }
      }
    }
  } else if (httpCode <= 0) {
    Serial.printf("[ERR] Fallo handshake HTTPS. HTTP Code: %d\n", httpCode);
    resultado = -1; // Desvía hacia la memoria NVS
  }
  
  http.end(); 
  return resultado;
}