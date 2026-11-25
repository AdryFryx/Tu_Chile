Turismo TUCHILE — Sistema de Gestión de Arriendos (PMS)

Prototipo funcional de PMS desarrollado en Python 3.11+, Django 5.1 y MariaDB, aplicando 4 Patrones de Diseño GoF y 5 Controles Técnicos de la norma ISO/IEC 27001:2022.

Instalación y Ejecución:
Crear y activar entorno virtual:
    python -m venv venv
    .\venv\Scripts\Activate.ps1

Instalar dependencias:
    pip install -r requirements.txt

Configurar variables de entorno:
    Copiar .env.example a .env y completar DJANGO_SECRET_KEY, credenciales de MariaDB y AES_ENCRYPTION_KEY (32 bytes en Base64).

Aplicar migraciones, ejecutar pruebas y levantar el servidor:
    python manage.py migrate
    python manage.py test portal -v 2
    python manage.py runserver

Patrones de Diseño GoF Implementados:
    Creacional — Factory Method (portal/domain/factory.py): Instancia Cabaña (con inventario crítico de menaje y gas) vs. Habitación de Hotel (con servicios estandarizados).

    Comportamiento — State (portal/domain/state.py): Controla el ciclo de vida estricto de las unidades (DISPONIBLE -> OCUPADA -> SUCIO -> LIMPIEZA -> DISPONIBLE), bloqueando transiciones inválidas.

    Estructural — Facade (portal/services/checkout_facade.py): Orquesta el Check-out en una transacción atómica (reporte de daños, cobro extra, movimiento en caja y cambio automático a estado SUCIO).

    Estructural — Adapter (portal/services/report_adapter.py): Desacopla la exportación de reportes de caja permitiendo al Administrador elegir entre Excel (.xlsx) o PDF (.pdf) bajo la misma interfaz.

Controles ISO/IEC 27001:2022 Implementados:
Constantes normativas declaradas en MAYÚSCULAS (PEP 8) en portal/security/constants.py e implementadas en portal/security/controls.py:

    A.8.5 (Gestión de Autenticación): Máximo 5 intentos fallidos, bloqueo de 900s (15 min) y expiración de sesión por inactividad en 1800s (30 min).

    A.8.2 (Control de Accesos RBAC): Roles ADMINISTRADOR, RECEPCIONISTA y ASEO con mínimo privilegio por macrozona y caché de permisos con timeout de 300s.

    A.8.11 (Enmascaramiento de Datos): Ofuscación de PII en salidas (RUT/Pasaporte muestra solo últimos 4 caracteres, Email muestra 1° y último carácter antes de @, Tarjetas muestran últimos 4 dígitos).

    A.8.24 (Uso de Criptografía): Hashing de contraseñas con bcrypt (rounds=12, largo mínimo 12 caracteres) y cifrado AES-256-GCM para PII en reposo.

    A.8.15 (Registro de Eventos): Bitácora de auditoría en audit.log con sanitización anti Log Injection (\n y \r), redacción de secretos y límite estricto de 4096 bytes por entrada.