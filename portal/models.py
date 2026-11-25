from decimal import Decimal
from django.db import models
from django.contrib.auth.models import User
from portal.security.constants import ROLE_ADMIN, ROLE_RECEPTIONIST, ROLE_CLEANING
from portal.security.controls import CryptoControl, DataMasking


class PerfilUsuario(models.Model):
    """Extiende User de Django para RBAC por rol y macrozona (ISO A.8.2)."""

    ROLES = [
        (ROLE_ADMIN, "Administrador"),
        (ROLE_RECEPTIONIST, "Recepcionista"),
        (ROLE_CLEANING, "Personal de Aseo"),
    ]
    MACROZONAS = [
        ("COSTERA", "Zona Costera Central (El Tabo, El Quisco, Las Cruces)"),
        ("SUR", "Zona Sur de Lagos y Archipiélago (Pucón, Villarrica, Llanquihue, Ancud)"),
        ("TODAS", "Todas las Macrozonas"),
    ]

    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="perfil")
    rol = models.CharField(max_length=20, choices=ROLES, default=ROLE_RECEPTIONIST)
    macrozona = models.CharField(max_length=20, choices=MACROZONAS, default="COSTERA")

    def __str__(self):
        return f"{self.user.username} ({self.rol} - {self.macrozona})"


class UnidadAlojamiento(models.Model):
    """Soporta Cabañas y Habitaciones de Hotel con máquina de estados (GoF Factory + State)."""

    TIPOS = [
        ("CABANA", "Cabaña"),
        ("HABITACION", "Habitación de Hotel"),
    ]
    MACROZONAS = [
        ("COSTERA", "Zona Costera Central"),
        ("SUR", "Zona Sur de Lagos y Archipiélago"),
    ]
    ESTADOS = [
        ("DISPONIBLE", "Disponible"),
        ("OCUPADA", "Ocupada"),
        ("SUCIO", "Sucio"),
        ("LIMPIEZA", "En Limpieza"),
    ]

    nombre = models.CharField(max_length=100)
    tipo = models.CharField(max_length=20, choices=TIPOS, default="CABANA")
    macrozona = models.CharField(max_length=20, choices=MACROZONAS, default="COSTERA")
    ubicacion = models.CharField(max_length=100, help_text="Ej: El Quisco, Pucón, Ancud")
    precio_base_noche = models.DecimalField(max_digits=10, decimal_places=2)
    capacidad = models.PositiveIntegerField(default=2)
    estado = models.CharField(max_length=20, choices=ESTADOS, default="DISPONIBLE")

    # Inventario crítico (ej. balón de gas, kit menaje) o servicios estandarizados (JSON)
    inventario_base = models.JSONField(default=dict, blank=True)

    def __str__(self):
        return f"{self.nombre} [{self.get_tipo_display()} - {self.macrozona}] ({self.estado})"


class Pasajero(models.Model):
    """Almacena PII cifrado con AES-256 en reposo (A.8.24) y expone salida enmascarada (A.8.11)."""

    nombre_completo = models.CharField(max_length=150)
    rut_pasaporte_cifrado = models.TextField()
    email = models.EmailField()
    telefono_cifrado = models.TextField(blank=True, default="")
    creado_en = models.DateTimeField(auto_now_add=True)

    def set_rut_pasaporte(self, valor_plano: str) -> None:
        self.rut_pasaporte_cifrado = CryptoControl.encrypt_pii(valor_plano)

    def get_rut_pasaporte_plano(self) -> str:
        return CryptoControl.decrypt_pii(self.rut_pasaporte_cifrado)

    @property
    def rut_enmascarado(self) -> str:
        """ISO A.8.11: solo últimos 4 caracteres visibles."""
        return DataMasking.mask_rut_or_passport(self.get_rut_pasaporte_plano())

    @property
    def email_enmascarado(self) -> str:
        """ISO A.8.11: 1° y último carácter antes de @."""
        return DataMasking.mask_email(self.email)

    def set_telefono(self, valor_plano: str) -> None:
        self.telefono_cifrado = CryptoControl.encrypt_pii(valor_plano)

    def __str__(self):
        return f"{self.nombre_completo} ({self.rut_enmascarado})"


class Reserva(models.Model):
    """Reserva con cálculo por temporada, abonos (50%) y control anti-overbooking."""

    TEMPORADAS = [
        ("BAJA", "Temporada Baja"),
        ("ALTA", "Temporada Alta (Verano)"),
        ("FIESTAS_PATRIAS", "Fiestas Patrias / Fin de Semana Largo"),
    ]
    ESTADOS_RESERVA = [
        ("PENDIENTE", "Pendiente de Abono"),
        ("CONFIRMADA", "Confirmada"),
        ("CHECKIN", "Check-in Realizado"),
        ("CHECKOUT", "Check-out Finalizado"),
        ("CANCELADA", "Cancelada"),
    ]

    unidad = models.ForeignKey(UnidadAlojamiento, on_delete=models.PROTECT, related_name="reservas")
    pasajero = models.ForeignKey(Pasajero, on_delete=models.PROTECT, related_name="reservas")
    creado_por = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)

    fecha_checkin = models.DateField()
    fecha_checkout = models.DateField()
    temporada = models.CharField(max_length=20, choices=TEMPORADAS, default="BAJA")

    total_estadia = models.DecimalField(max_digits=10, decimal_places=2)
    abono_pagado = models.DecimalField(max_digits=10, decimal_places=2, default=Decimal("0.00"))
    cobros_extra = models.DecimalField(max_digits=10, decimal_places=2, default=Decimal("0.00"))
    estado = models.CharField(max_length=20, choices=ESTADOS_RESERVA, default="PENDIENTE")
    comentario = models.TextField(blank=True, default="")
    creada_en = models.DateTimeField(auto_now_add=True)

    @property
    def saldo_pendiente(self) -> Decimal:
        return (self.total_estadia + self.cobros_extra) - self.abono_pagado

    def __str__(self):
        return f"Reserva #{self.id} - {self.unidad.nombre} ({self.fecha_checkin} a {self.fecha_checkout})"


class MovimientoCaja(models.Model):
    """Caja diaria por turno: abonos, saldos de check-in y cobros extra de check-out."""

    TIPOS_MOVIMIENTO = [
        ("ABONO", "Abono de Reserva"),
        ("SALDO_CHECKIN", "Pago de Saldo en Check-in"),
        ("COBRO_EXTRA", "Cobro Extra / Daños en Check-out"),
    ]
    TURNOS = [
        ("MANANA", "Turno Mañana"),
        ("TARDE", "Turno Tarde"),
        ("NOCHE", "Turno Noche"),
    ]

    reserva = models.ForeignKey(Reserva, on_delete=models.PROTECT, related_name="movimientos")
    registrado_por = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    tipo = models.CharField(max_length=20, choices=TIPOS_MOVIMIENTO)
    turno = models.CharField(max_length=15, choices=TURNOS, default="MANANA")
    monto = models.DecimalField(max_digits=10, decimal_places=2)
    tarjeta_enmascarada = models.CharField(max_length=25, blank=True, default="EFECTIVO/TRANSFERENCIA")
    fecha_transaccion = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"[{self.turno}] {self.tipo} ${self.monto} - Reserva #{self.reserva_id}"


class ReporteDano(models.Model):
    """Reporte de daños o faltantes de inventario (menaje/gas) en recambio o aseo."""

    unidad = models.ForeignKey(UnidadAlojamiento, on_delete=models.CASCADE, related_name="reportes_dano")
    reserva = models.ForeignKey(Reserva, on_delete=models.SET_NULL, null=True, blank=True)
    reportado_por = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    descripcion = models.TextField()
    costo_estimado = models.DecimalField(max_digits=10, decimal_places=2, default=Decimal("0.00"))
    resuelto = models.BooleanField(default=False)
    fecha_reporte = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Daño en {self.unidad.nombre} (${self.costo_estimado})"