
# Herramienta de Auditoría SSL / HTTPS de Certificados Web

> Audita, inspecciona y reporta la postura TLS/SSL de cualquier lista de sitios
> web — desde un script de línea de comandos hasta un dashboard interactivo
> con scoring de cumplimiento en tiempo real.

---

## Descripción General

Este conjunto de herramientas permite a equipos de seguridad y auditoría de TI
validar la configuración HTTPS/SSL de sitios web a escala, con dependencias
mínimas y sin necesidad de infraestructura adicional. Cubre tres modos de uso
complementarios que se adaptan a cualquier flujo de trabajo: desde una revisión
rápida ad-hoc en una Raspberry Pi hasta una sesión de escaneo en vivo con
progreso en tiempo real y scoring de cumplimiento en el navegador.

La herramienta ejecuta, por cada objetivo:
  1. Verificación de conectividad TCP en el puerto indicado
  2. Handshake TLS e inspección completa del certificado (emisor, CN, fechas
     de validez, algoritmo y tamaño de clave, suite de cifrado, versión TLS)
  3. Solicitud HTTPS GET con captura del código de estado HTTP y clasificación
     de errores

Todos los resultados se guardan en un archivo CSV con marca de tiempo dentro
del directorio ./reports/.

---

## Componentes

### 1. certs.py — Script Standalone

Script Python autocontenido. No requiere servidor web ni navegador.

  - Se ejecuta desde cualquier terminal: python certs.py
  - Solicita la ruta de un archivo .txt con la lista de objetivos
  - Realiza las verificaciones TCP → TLS → HTTPS de forma secuencial
  - Genera un CSV con marca de tiempo en ./reports/
  - Salida en terminal con colores (marca verde / roja por paso)
  - Detección automática de dependencias faltantes con instrucciones
    de instalación claras

Dependencias:
  pip install requests cryptography urllib3

Plataformas soportadas: Windows, Linux (Kali), Raspberry Pi OS, macOS
Compatibilidad Python: 3.9 a 3.14


### 2. backend.py — Servidor API Flask Local

Servidor REST local que expone la lógica de escaneo por HTTP, permitiendo
al dashboard disparar y monitorear escaneos en tiempo real.

  - Detecta automáticamente un puerto libre de la lista de candidatos:
    5151, 5152, 5153, 8181, 8282, 8383, 9191, 9292
    (elegidos para evitar bloqueos de firewalls corporativos)
  - Escucha exclusivamente en 127.0.0.1 (no expuesto a la red)
  - Escaneo asíncrono con Server-Sent Events (SSE) para progreso en vivo
  - Guarda reportes CSV en ./reports/ al completar cada escaneo

Endpoints REST:
  GET  /ping                 Health check — confirma que el backend está activo
  POST /scan                 Inicia un escaneo asíncrono; retorna { scan_id, total }
  GET  /stream/<scan_id>     Flujo SSE: líneas de log, porcentaje y evento done
  GET  /reports              Lista todos los reportes CSV guardados
  GET  /reports/<filename>   Descarga un reporte CSV específico
  POST /run                  Endpoint síncrono legado (compatibilidad hacia atrás)

Comando de inicio:
  python backend.py

Dependencias:
  pip install flask flask-cors requests cryptography


### 3. dashboard_https_ssl.html — Dashboard Interactivo

Archivo HTML único y autocontenido. Sin instalación, sin pasos de compilación.

Modos de uso:
  a) Modo online: abrir el archivo en el navegador mientras backend.py
     está en ejecución. El dashboard se conecta al backend, acepta una lista
     de dominios, dispara el escaneo y transmite el progreso línea a línea
     mediante SSE.

  b) Modo offline / standalone: abrir el archivo directamente en el navegador
     y cargar un reporte CSV previamente generado por certs.py o backend.py.
     Visualización completa sin necesidad de backend.

Funcionalidades:
  - 9 tarjetas KPI: dominios OK/Fail, estado TLS, caducidad, algoritmos,
    versiones de protocolo
  - Scoring de cumplimiento: calificación A–D configurable con pesos ajustables
      * HTTPS activo
      * Versión TLS (1.2 vs 1.3)
      * Vigencia del certificado / días restantes
      * Algoritmo de clave
      * Tamaño de clave (bits)
    Los umbrales de cada calificación también son ajustables por el auditor.
  - Log de escaneo en tiempo real transmitido vía Server-Sent Events
  - Gráficas interactivas (Chart.js 4.4): distribución de estado, tipos de
    error, versiones TLS, algoritmos de clave, línea de tiempo de caducidad
  - Tabla de dominios filtrable y ordenable con badge de cumplimiento por fila
  - Interfaz bilingüe: Español / English (toggle en la misma interfaz)
  - URL base del backend configurable directamente en la interfaz
  - Compatible con Chrome, Edge y Firefox

---

## Formato del Archivo de Entrada

Una entrada por línea. Las líneas que comienzan con # se tratan como
comentarios y son ignoradas. Las líneas en blanco se omiten.

Formatos soportados:
  dominio.com
  192.168.1.1
  dominio.com/ruta
  192.168.1.1/api/health
  dominio.com:8443
  192.168.1.1:8443
  dominio.com:8443/ruta
  192.168.1.1:8443/api/health
  https://dominio.com
  https://dominio.com:8443/ruta

El puerto por defecto es 443 si no se especifica.

Ejemplo de archivo objetivos.txt:
  # Endpoints de producción
  www.ejemplo.com
  api.ejemplo.com:8443
  192.168.100.10/health
  # Servidor legado
  legado.interno.corp:4443

---

## Estructura del Reporte CSV

Convención de nombre: report_http_ssl_YYYYMMDDhhmmss.csv
Ubicación: ./reports/ (se crea automáticamente si no existe)

Campos:
  hostname          Entrada original del archivo de entrada
  https_active      TRUE si HTTPS respondió exitosamente; FALSE en caso contrario
  error_type        Etiqueta de error cuando https_active es FALSE:
                      DNS_ERROR | TIMEOUT | SSL_ERROR | CONNECTION_REFUSED
  https_status_code Código de respuesta HTTP (200, 301, 403, 500, ...)
  https_status_text Texto del estado HTTP (OK, Moved Permanently, ...)
  ssl_issuer        Common Name del emisor del certificado (CA)
  ssl_common_name   Common Name del sujeto del certificado
  ssl_valid_from    Fecha not-before del certificado (YYYY-MM-DD)
  ssl_valid_until   Fecha de expiración del certificado (YYYY-MM-DD)
  ssl_key_algorithm Algoritmo de clave pública: RSA | EC | DSA | Ed25519 | Ed448
  ssl_key_size_bits Tamaño de clave en bits (ej. 256, 2048, 4096)
  ssl_cipher_suite  Suite de cifrado negociada en el handshake TLS
  tls_version       Versión del protocolo TLS: TLSv1.2 | TLSv1.3

Nota: cuando https_active es FALSE, todos los campos SSL y de certificado
quedan en blanco. Los campos SSL se populan únicamente cuando tanto el
handshake TLS como la solicitud HTTPS tienen éxito. Esto es por diseño para
mantener los datos sin ambigüedad.

---

## Inicio Rápido

### Modo A — Standalone (sin navegador)

  1. Instalar dependencias:
       pip install requests cryptography urllib3

  2. Crear un archivo objetivos.txt con un dominio o IP por línea.

  3. Ejecutar el script:
       python certs.py

  4. Ingresar la ruta al archivo cuando el script lo solicite.

  5. Revisar la salida con colores en la terminal.

  6. El reporte se encuentra en:
       ./reports/report_http_ssl_<marca_de_tiempo>.csv

  7. Opcional: abrir dashboard_https_ssl.html en el navegador y cargar
     el CSV generado para visualización.


### Modo B — Backend + Dashboard (escaneo en vivo con interfaz)

  1. Instalar dependencias:
       pip install flask flask-cors requests cryptography

  2. Iniciar el backend:
       python backend.py

     La terminal mostrará el puerto seleccionado, por ejemplo:
       * Running on http://127.0.0.1:5151

  3. Abrir dashboard_https_ssl.html en Chrome, Edge o Firefox.

  4. Configurar la URL del backend en los ajustes del dashboard si es
     necesario (el valor por defecto es http://localhost:5151).

  5. Pegar la lista de dominios en el área de texto y hacer clic en
     "Iniciar Escaneo".

  6. Monitorear el progreso en tiempo real; el reporte CSV se guarda
     automáticamente al finalizar y puede descargarse desde el dashboard.


### Modo C — Dashboard offline (cargar reporte existente)

  1. Abrir dashboard_https_ssl.html directamente en el navegador
     (no se requiere backend).

  2. Hacer clic en "Cargar Reporte CSV" y seleccionar un archivo CSV
     previamente generado por certs.py o backend.py.

  3. Los KPIs, gráficas y tabla de dominios se populan de inmediato.

---

## Comportamiento de la Verificación SSL

La verificación del certificado SSL está intencionalmente desactivada en
ambos scripts. Esta es una decisión de diseño deliberada:

  - La herramienta es un auditor, no un guardián. Su propósito es reportar
    el estado real de los certificados, incluyendo los expirados, autofirmados
    o mal configurados.
  - Activar la verificación estricta de SSL haría que se omitieran en silencio
    exactamente los objetivos que más atención necesitan.
  - La advertencia InsecureRequestWarning de urllib3 se suprime en tiempo
    de ejecución para mantener la salida limpia.

El scoring de cumplimiento del dashboard penaliza los certificados inválidos
o próximos a expirar de forma independiente al éxito de la solicitud HTTPS.

---

## Scoring de Cumplimiento (Dashboard)

El dashboard calcula una puntuación de cumplimiento ponderada (0–100) por
dominio y asigna una calificación de letra:

  Calificación A — Postura Excelente
  Calificación B — Postura Buena
  Calificación C — Postura de Riesgo
  Calificación D — Postura Crítica

Pesos por defecto del scoring (ajustables mediante sliders):
  HTTPS activo        : línea base obligatoria
  Versión TLS         : TLSv1.3 preferido sobre TLSv1.2; versiones anteriores
                        son penalizadas
  Vigencia del cert.  : días restantes hasta la expiración
  Algoritmo de clave  : EC/Ed preferido; RSA aceptado; DSA penalizado
  Tamaño de clave     : umbrales mínimos por algoritmo

Todos los pesos y umbrales de calificación son configurables por sesión
directamente en la interfaz del dashboard.

---

## Notas de Plataforma y Entorno

  - Los scripts han sido probados en Windows 10/11, Kali Linux,
    Raspberry Pi OS (Bookworm), Ubuntu 22.04/24.04 y macOS Sonoma.
  - En entornos Python gestionados externamente (Kali, Raspberry Pi OS,
    Debian 12+):
      pip install <paquetes> --break-system-packages
    o usar un entorno virtual:
      python3 -m venv .venv && source .venv/bin/activate && pip install <paquetes>
  - La librería cryptography cambió su API en la versión 42 (campos datetime
    con timezone UTC). Ambas APIs se detectan y manejan automáticamente al
    importar.
  - Python 3.14 requiere importación explícita de importlib.util; esto está
    contemplado en backend.py.

---

## Estructura del Proyecto

  certs.py                    Script de escaneo standalone
  backend.py               Servidor API Flask + motor de escaneo
  dashboard_https_ssl.html Dashboard interactivo (archivo HTML único)
  reports/                    Directorio de salida (se crea automáticamente)
    report_http_ssl_<ts>.csv  Reportes de escaneo con marca de tiempo

---

## Licencia

Uso interno. Adaptar y redistribuir conforme a la política de software
de la organización.
