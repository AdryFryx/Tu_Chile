from datetime import date
from decimal import Decimal
import time

from django.contrib.auth.models import User
from django.core.cache import cache
from django.test import Client, TestCase
from django.urls import reverse

from portal.domain.factory import UnidadFactory
from portal.domain.state import GestorEstadoUnidad
from portal.models import MovimientoCaja, Pasajero, PerfilUsuario, Reserva
from portal.security.constants import (
    AUTH_MAX_FAILED_ATTEMPTS,
    LOG_MAX_ENTRY_BYTES,
    ROLE_ADMIN,
    ROLE_CLEANING,
    ROLE_RECEPTIONIST,
)
from portal.security.controls import (
    AuditLogger,
    AuthControl,
    CryptoControl,
    DataMasking,
)
from portal.services.checkout_facade import CheckoutFacade
from portal.services.report_adapter import obtener_exportador


class PatronesGoFTests(TestCase):
    """Pruebas del Bloque 1: Factory Method, State, Facade y Adapter."""

    def setUp(self):
        cache.clear()
        self.admin_user = User.objects.create_user(
            username="admin_test", password="PasswordSeguro123!", email="admin@tuchile.cl"
        )
        PerfilUsuario.objects.create(user=self.admin_user, rol=ROLE_ADMIN, macrozona="TODAS")

    def test_factory_method_cabana_vs_habitacion(self):
        """Creacional: Cabaña nace con inventario crítico (gas/menaje) y Habitación con servicios."""
        cabana = UnidadFactory.crear(
            tipo="CABANA",
            nombre="Cabaña El Quisco 1",
            macrozona="COSTERA",
            ubicacion="El Quisco",
            precio_base=Decimal("65000.00"),
            capacidad=4,
        )
        habitacion = UnidadFactory.crear(
            tipo="HABITACION",
            nombre="Habitación Pucón 101",
            macrozona="SUR",
            ubicacion="Pucón",
            precio_base=Decimal("55000.00"),
            capacidad=2,
        )
        self.assertEqual(cabana.tipo, "CABANA")
        self.assertIn("balon_gas_15kg", cabana.inventario_base)
        self.assertEqual(habitacion.tipo, "HABITACION")
        self.assertTrue(habitacion.inventario_base.get("desayuno_incluido"))

    def test_state_ciclo_de_vida_y_transicion_invalida(self):
        """Comportamiento: DISPONIBLE -> OCUPADA -> SUCIO -> LIMPIEZA -> DISPONIBLE."""
        unidad = UnidadFactory.crear(
            tipo="CABANA",
            nombre="Cabaña Ancud",
            macrozona="SUR",
            ubicacion="Ancud",
            precio_base=Decimal("70000.00"),
            capacidad=4,
        )
        # Transición inválida: no se puede iniciar limpieza si está DISPONIBLE
        with self.assertRaises(ValueError):
            GestorEstadoUnidad.obtener_estado(unidad).iniciar_limpieza(unidad)

        # Ciclo válido completo
        GestorEstadoUnidad.obtener_estado(unidad).ocupar(unidad)
        self.assertEqual(unidad.estado, "OCUPADA")

        GestorEstadoUnidad.obtener_estado(unidad).marcar_sucio(unidad)
        self.assertEqual(unidad.estado, "SUCIO")

        GestorEstadoUnidad.obtener_estado(unidad).iniciar_limpieza(unidad)
        self.assertEqual(unidad.estado, "LIMPIEZA")

        GestorEstadoUnidad.obtener_estado(unidad).habilitar(unidad)
        self.assertEqual(unidad.estado, "DISPONIBLE")

    def test_facade_checkout_orquestado(self):
        """Estructural: Facade registra daño, suma caja, cierra reserva y pasa unidad a SUCIO."""
        unidad = UnidadFactory.crear(
            tipo="CABANA",
            nombre="Cabaña Villarrica",
            macrozona="SUR",
            ubicacion="Villarrica",
            precio_base=Decimal("80000.00"),
            capacidad=4,
        )
        GestorEstadoUnidad.obtener_estado(unidad).ocupar(unidad)

        pasajero = Pasajero(nombre_completo="Teresa Tapia", email="teresa@tuchile.cl")
        pasajero.set_rut_pasaporte("12.345.678-9")
        pasajero.save()

        reserva = Reserva.objects.create(
            unidad=unidad,
            pasajero=pasajero,
            creado_por=self.admin_user,
            fecha_checkin=date(2026, 12, 1),
            fecha_checkout=date(2026, 12, 4),
            temporada="ALTA",
            total_estadia=Decimal("240000.00"),
            abono_pagado=Decimal("240000.00"),
            estado="CHECKIN",
        )

        resultado = CheckoutFacade.ejecutar_checkout(
            reserva=reserva,
            usuario_operador=self.admin_user,
            turno="TARDE",
            descripcion_dano="Falta balón de gas 15kg",
            costo_extra=Decimal("25000.00"),
        )
        self.assertEqual(resultado["nuevo_estado_unidad"], "SUCIO")
        self.assertEqual(resultado["cobros_extra"], Decimal("25000.00"))
        self.assertEqual(MovimientoCaja.objects.filter(reserva=reserva, tipo="COBRO_EXTRA").count(), 1)

    def test_adapter_exportacion_excel_y_pdf(self):
        """Estructural: Adapter genera bytes válidos tanto para .xlsx como para .pdf."""
        movimientos = MovimientoCaja.objects.none()

        excel_bytes = obtener_exportador("xlsx").exportar(movimientos)
        pdf_bytes = obtener_exportador("pdf").exportar(movimientos)

        self.assertTrue(excel_bytes.startswith(b"PK"))    # Firma estándar de archivos .xlsx (ZIP)
        self.assertTrue(pdf_bytes.startswith(b"%PDF"))    # Firma estándar de archivos .pdf


class ControlesISO27001Tests(TestCase):
    """Pruebas del Bloque 2: Controles A.8.5, A.8.2, A.8.11, A.8.24 y A.8.15."""

    def setUp(self):
        cache.clear()
        self.client = Client()

        self.admin = User.objects.create_user(
            username="admin_iso", password="PasswordSeguro123!", email="admin@tuchile.cl"
        )
        PerfilUsuario.objects.create(user=self.admin, rol=ROLE_ADMIN, macrozona="TODAS")

        self.aseo = User.objects.create_user(
            username="aseo_iso", password="PasswordSeguro123!", email="aseo@tuchile.cl"
        )
        PerfilUsuario.objects.create(user=self.aseo, rol=ROLE_CLEANING, macrozona="COSTERA")

    def test_iso_a85_bloqueo_por_fuerza_bruta(self):
        """A.8.5: Bloqueo automático tras 5 intentos fallidos."""
        user = "atacante"
        for _ in range(AUTH_MAX_FAILED_ATTEMPTS):
            AuthControl.register_failed_attempt(user)

        self.assertTrue(AuthControl.is_locked(user))

    def test_iso_a811_enmascaramiento_pii(self):
        """A.8.11: RUT (últimos 4), Email (1° y último antes de @), Tarjeta (últimos 4)."""
        self.assertEqual(DataMasking.mask_rut_or_passport("12.345.678-9"), "********78-9")
        self.assertEqual(DataMasking.mask_email("gabriel@inacap.cl"), "g*****l@inacap.cl")
        self.assertEqual(DataMasking.mask_card("4532-1111-2222-9876"), "****-****-****-9876")

    def test_iso_a824_criptografia_bcrypt_y_aes256(self):
        """A.8.24: Largo mín. 12 chars, bcrypt rounds=12 y cifrado/descifrado AES-256."""
        self.assertFalse(CryptoControl.validate_password_strength("corta123"))
        self.assertTrue(CryptoControl.validate_password_strength("ClaveSegura2026!"))

        inicio = time.perf_counter()
        hashed = CryptoControl.hash_password("ClaveSegura2026!")
        self.assertTrue(CryptoControl.verify_password("ClaveSegura2026!", hashed))
        self.assertGreater(time.perf_counter() - inicio, 0.05)

        rut_plano = "19.876.543-2"
        cifrado = CryptoControl.encrypt_pii(rut_plano)
        self.assertNotEqual(cifrado, rut_plano)
        self.assertEqual(CryptoControl.decrypt_pii(cifrado), rut_plano)

    def test_iso_a815_logging_anti_injection_y_limite_4kb(self):
        """A.8.15: Elimina \\n y \\r, redacta secretos y trunca a <= 4096 bytes."""
        payload_malicioso = "Login fallido\nADMIN_OVERRIDE=True\rpassword=MiClave123 " + ("A" * 5000)
        sanitizado = AuditLogger.log_event("WARNING", payload_malicioso)

        self.assertNotIn("\n", sanitizado)
        self.assertNotIn("\r", sanitizado)
        self.assertNotIn("MiClave123", sanitizado)
        self.assertLessEqual(len(sanitizado.encode("utf-8")), LOG_MAX_ENTRY_BYTES)

    def test_iso_a82_rbac_permisos_por_rol(self):
        """A.8.2: Personal de Aseo recibe 403 al intentar exportar caja; Admin recibe 200."""
        self.client.login(username="aseo_iso", password="PasswordSeguro123!")
        resp_aseo = self.client.get(reverse("exportar_caja") + "?formato=pdf")
        self.assertEqual(resp_aseo.status_code, 403)

        self.client.login(username="admin_iso", password="PasswordSeguro123!")
        resp_admin = self.client.get(reverse("exportar_caja") + "?formato=pdf")
        self.assertEqual(resp_admin.status_code, 200)