"""
Constantes normativas ISO/IEC 27001:2022 para Turismo TUCHILE.
Cumple con PEP 8 (MAYÚSCULAS) para trazabilidad en auditoría.
"""

# --- A.8.5: Gestión de Autenticación ---
AUTH_MAX_FAILED_ATTEMPTS = 5          # Máx. 5 intentos fallidos
AUTH_LOCKOUT_SECONDS = 900            # Bloqueo por 900s (15 min)
AUTH_SESSION_TIMEOUT_SECONDS = 1800   # Inactividad de sesión: 1800s (30 min)
AUTH_JWT_MAX_LIFETIME_SECONDS = 28800 # Máx. 28800s (8h) si se usa JWT

# --- A.8.2: Control de Accesos (RBAC) ---
RBAC_CACHE_TIMEOUT_SECONDS = 300      # Timeout de caché de permisos: 300s (5 min)
ROLE_ADMIN = "ADMINISTRADOR"
ROLE_RECEPTIONIST = "RECEPCIONISTA"
ROLE_CLEANING = "ASEO"

# --- A.8.11: Enmascaramiento de Datos (PII) ---
MASK_VISIBLE_LAST_CHARS = 4           # RUT/Pasaporte y Tarjetas: últimos 4 caracteres
MASK_CHAR = "*"

# --- A.8.24: Uso de Criptografía ---
CRYPTO_BCRYPT_ROUNDS = 12             # Factor de costo bcrypt (tiempo >= 250ms)
CRYPTO_MIN_PASSWORD_LENGTH = 12       # Largo mínimo de contraseña: 12 caracteres
CRYPTO_AES_KEY_BYTES = 32             # 32 bytes = 256 bits (AES-256)

# --- A.8.15: Registro de Eventos (Logging) ---
LOG_MAX_ENTRY_BYTES = 4096            # Límite estricto de 4KB por entrada
LOG_FORBIDDEN_FIELDS = ("password", "clave", "cvv", "secret", "token", "rut_raw")