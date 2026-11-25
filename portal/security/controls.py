import base64
import logging
import os
import re
from functools import wraps

import bcrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from django.conf import settings
from django.core.cache import cache
from django.http import HttpResponseForbidden

from .constants import (
    AUTH_LOCKOUT_SECONDS,
    AUTH_MAX_FAILED_ATTEMPTS,
    CRYPTO_AES_KEY_BYTES,
    CRYPTO_BCRYPT_ROUNDS,
    CRYPTO_MIN_PASSWORD_LENGTH,
    LOG_FORBIDDEN_FIELDS,
    LOG_MAX_ENTRY_BYTES,
    MASK_CHAR,
    MASK_VISIBLE_LAST_CHARS,
    RBAC_CACHE_TIMEOUT_SECONDS,
)

# Logger dedicado para auditoría (A.8.15)
audit_logger = logging.getLogger("tuchile.audit")
if not audit_logger.handlers:
    handler = logging.FileHandler(settings.BASE_DIR / "audit.log", encoding="utf-8")
    formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
    handler.setFormatter(formatter)
    audit_logger.addHandler(handler)
    audit_logger.setLevel(logging.INFO)


# ==============================================================================
# 1. ISO A.8.5 — GESTIÓN DE AUTENTICACIÓN (Fuerza Bruta y Bloqueo)
# ==============================================================================
class AuthControl:
    """Controla intentos fallidos y bloqueo temporal usando la caché de Django."""

    @staticmethod
    def _attempts_key(username: str) -> str:
        return f"auth_attempts_{username.lower()}"

    @staticmethod
    def _lock_key(username: str) -> str:
        return f"auth_locked_{username.lower()}"

    @classmethod
    def is_locked(cls, username: str) -> bool:
        return bool(cache.get(cls._lock_key(username)))

    @classmethod
    def register_failed_attempt(cls, username: str) -> int:
        key = cls._attempts_key(username)
        attempts = cache.get(key, 0) + 1
        cache.set(key, attempts, timeout=AUTH_LOCKOUT_SECONDS)

        if attempts >= AUTH_MAX_FAILED_ATTEMPTS:
            cache.set(cls._lock_key(username), True, timeout=AUTH_LOCKOUT_SECONDS)
            AuditLogger.log_event(
                "WARNING",
                f"Cuenta bloqueada por {AUTH_LOCKOUT_SECONDS}s tras {attempts} intentos fallidos (user={username})"
            )
        return attempts

    @classmethod
    def reset_attempts(cls, username: str) -> None:
        cache.delete(cls._attempts_key(username))
        cache.delete(cls._lock_key(username))


# ==============================================================================
# 2. ISO A.8.11 — ENMASCARAMIENTO DE DATOS (Ofuscación de PII)
# ==============================================================================
class DataMasking:
    """Ofusca PII en salidas para evitar exposición directa."""

    @staticmethod
    def mask_rut_or_passport(value: str) -> str:
        """Muestra solo los últimos 4 caracteres. Ej: 12.345.678-9 -> ********78-9"""
        if not value:
            return ""
        clean = value.strip()
        if len(clean) <= MASK_VISIBLE_LAST_CHARS:
            return MASK_CHAR * len(clean)
        hidden = MASK_CHAR * (len(clean) - MASK_VISIBLE_LAST_CHARS)
        return f"{hidden}{clean[-MASK_VISIBLE_LAST_CHARS:]}"

    @staticmethod
    def mask_email(email: str) -> str:
        """Muestra 1° y último carácter antes de @. Ej: gabriel@inacap.cl -> g*****l@inacap.cl"""
        if not email or "@" not in email:
            return MASK_CHAR * 4
        local, domain = email.split("@", 1)
        if len(local) <= 2:
            masked_local = local[0] + MASK_CHAR
        else:
            masked_local = local[0] + (MASK_CHAR * (len(local) - 2)) + local[-1]
        return f"{masked_local}@{domain}"

    @staticmethod
    def mask_card(card_number: str) -> str:
        """Muestra solo los últimos 4 dígitos. Ej: ****-****-****-1234"""
        digits = re.sub(r"\D", "", card_number or "")
        if len(digits) < MASK_VISIBLE_LAST_CHARS:
            return MASK_CHAR * 4
        return f"****-****-****-{digits[-MASK_VISIBLE_LAST_CHARS:]}"


# ==============================================================================
# 3. ISO A.8.24 — USO DE CRIPTOGRAFÍA (bcrypt rounds=12 y AES-256-GCM)
# ==============================================================================
class CryptoControl:
    """Hashing seguro de contraseñas y cifrado AES-256 para PII en reposo."""

    @staticmethod
    def validate_password_strength(password: str) -> bool:
        return bool(password and len(password) >= CRYPTO_MIN_PASSWORD_LENGTH)

    @staticmethod
    def hash_password(plain_password: str) -> str:
        if not CryptoControl.validate_password_strength(plain_password):
            raise ValueError(
                f"La contraseña debe tener al menos {CRYPTO_MIN_PASSWORD_LENGTH} caracteres."
            )
        salt = bcrypt.gensalt(rounds=CRYPTO_BCRYPT_ROUNDS)
        hashed = bcrypt.hashpw(plain_password.encode("utf-8"), salt)
        return hashed.decode("utf-8")

    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        return bcrypt.checkpw(
            plain_password.encode("utf-8"), hashed_password.encode("utf-8")
        )

    @staticmethod
    def _get_aes_key() -> bytes:
        raw_key = base64.b64decode(settings.AES_ENCRYPTION_KEY)
        if len(raw_key) != CRYPTO_AES_KEY_BYTES:
            raise ValueError("La clave AES_ENCRYPTION_KEY debe tener exactamente 32 bytes (AES-256).")
        return raw_key

    @classmethod
    def encrypt_pii(cls, plaintext: str) -> str:
        """Cifra PII usando AES-256-GCM (incluye nonce aleatorio de 12 bytes)."""
        if not plaintext:
            return ""
        aesgcm = AESGCM(cls._get_aes_key())
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
        return base64.b64encode(nonce + ciphertext).decode("utf-8")

    @classmethod
    def decrypt_pii(cls, encrypted_b64: str) -> str:
        """Descifra PII previamente cifrado con AES-256-GCM."""
        if not encrypted_b64:
            return ""
        raw = base64.b64decode(encrypted_b64)
        nonce, ciphertext = raw[:12], raw[12:]
        aesgcm = AESGCM(cls._get_aes_key())
        return aesgcm.decrypt(nonce, ciphertext, None).decode("utf-8")


# ==============================================================================
# 4. ISO A.8.15 — REGISTRO DE EVENTOS (Anti Log Injection y Límite 4KB)
# ==============================================================================
class AuditLogger:
    """Bitácora de auditoría sanitizada, sin PII y acotada a 4096 bytes."""

    @staticmethod
    def sanitize_message(message: str) -> str:
        # 1. Anti Log Injection: elimina saltos de línea \n y retornos \r
        clean = message.replace("\n", " ").replace("\r", " ")

        # 2. Bloqueo básico de palabras prohibidas (PII / Passwords)
        lower_msg = clean.lower()
        for forbidden in LOG_FORBIDDEN_FIELDS:
            if forbidden in lower_msg:
                clean = re.sub(
                    rf"{forbidden}\s*[:=]\s*\S+",
                    f"{forbidden}=[REDACTED]",
                    clean,
                    flags=re.IGNORECASE,
                )

        # 3. Límite estricto de 4096 bytes (4KB)
        encoded = clean.encode("utf-8")
        if len(encoded) > LOG_MAX_ENTRY_BYTES:
            clean = encoded[:LOG_MAX_ENTRY_BYTES].decode("utf-8", errors="ignore")
        return clean

    @classmethod
    def log_event(cls, level: str, message: str) -> str:
        safe_msg = cls.sanitize_message(message)
        level_upper = level.upper()
        if level_upper == "WARNING":
            audit_logger.warning(safe_msg)
        elif level_upper == "ERROR":
            audit_logger.error(safe_msg)
        else:
            audit_logger.info(safe_msg)
        return safe_msg


# ==============================================================================
# 5. ISO A.8.2 — CONTROL DE ACCESOS (RBAC con caché de 300s)
# ==============================================================================
def get_user_role_cached(user) -> tuple[str, str]:
    """Obtiene (rol, macrozona) del usuario usando caché con timeout de 300s."""
    cache_key = f"rbac_user_{user.id}"
    cached = cache.get(cache_key)
    if cached is not None:
        return cached

    perfil = getattr(user, "perfil", None)
    data = (perfil.rol, perfil.macrozona) if perfil else ("", "")
    cache.set(cache_key, data, timeout=RBAC_CACHE_TIMEOUT_SECONDS)
    return data


def require_role(allowed_roles: list[str]):
    """Decorador RBAC: revalida permisos en cada operación."""
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return HttpResponseForbidden("Acceso denegado: autenticación requerida.")

            rol, _ = get_user_role_cached(request.user)
            if rol not in allowed_roles:
                AuditLogger.log_event(
                    "WARNING",
                    f"Intento de acceso no autorizado por user={request.user.username} con rol={rol}"
                )
                return HttpResponseForbidden("Acceso denegado: permisos insuficientes.")
            return view_func(request, *args, **kwargs)
        return _wrapped
    return decorator