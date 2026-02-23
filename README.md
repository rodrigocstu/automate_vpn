# 🛡️ Custom VPN Automation Global Protect of PAN-OS

Solución profesional para **Automatizar VPN** y **Ordenar Info VPN CLI**. Diseñada para estandarizar la creación de cuentas y generación de comandos CLI de Palo Alto Networks (PAN-OS).

---

## 🚀 Guía Rápida: Uso en Producción (PRD)

El entorno de **Producción** es el estado final para la generación de accesos oficiales.

### 1. Iniciar la aplicación
Ejecuta el archivo `start_prd.bat` en la raíz del proyecto.
> [!NOTE]
> El sistema instalará automáticamente las librerías necesarias en el primer inicio.

### 2. Acceso al Portal
Abre tu navegador en: `http://localhost:5001`

### 3. Generación de Credenciales (Paso a Paso)
1. **Identificación**: Ingresa el RITM del ticket y el RUT del usuario.
2. **Parámetros de Red**: Define las IPs y zonas correspondientes al requerimiento.
3. **Generación**: Haz clic en **"Generar Acceso"**. El sistema aplicará la **Política de Seguridad Global (20 caracteres)**.
4. **Resultado**: El sistema entregará el bloque CLI formateado y listo para ser pegado en la consola del Firewall PAN-OS.

---

## 🧪 Guía de Desarrollo y Pruebas (QA)

El entorno **QA** permite validar configuraciones y realizar pruebas de carga.

### 1. Iniciar QA
Ejecuta `start_qa.bat`. Disponible en: `http://localhost:5000`

### 2. Carga Masiva desde Excel
Para procesar múltiples solicitudes a la vez:
1. Descarga la **Plantilla Excel** desde la interfaz.
2. Completa los datos.
3. Sube el archivo para generar los comandos CLI de forma masiva.

---

## 🛠️ Requisitos Técnicos
* **Lenguaje**: Python 3.10+
* **Framework**: Flask / PAN-OS CLI Standard
* **Seguridad**: Política de contraseñas de alta complejidad (20 caracteres, sin repeticiones).

---
> [!IMPORTANT]
> **Seguridad**: Este repositorio no contiene secretos ni datos privados. Las configuraciones persistentes se gestionan localmente en el entorno del usuario.
