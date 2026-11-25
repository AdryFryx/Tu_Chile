from datetime import datetime
from decimal import Decimal
import time

from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.db.models import Q
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_http_methods

from portal.domain.factory import UnidadFactory
from portal.domain.state import GestorEstadoUnidad
from portal.models import (
    MovimientoCaja,
    Pasajero,
    PerfilUsuario,
    ReporteDano,
    Reserva,
    UnidadAlojamiento,
)
from portal.security.constants import (
    AUTH_LOCKOUT_SECONDS,
    CRYPTO_MIN_PASSWORD_LENGTH,
    ROLE_ADMIN,
    ROLE_CLEANING,
    ROLE_RECEPTIONIST,
)
from portal.security.controls import (
    AuditLogger,
    AuthControl,
    CryptoControl,
    DataMasking,
    get_user_role_cached,
    require_role,
)
from portal.services.checkout_facade import CheckoutFacade
from portal.services.report_adapter import obtener_exportador


# Multiplicadores de tarifa dinámica por temporada
MULTIPLICADOR_TEMPORADA = {
    "BAJA": Decimal("1.00"),
    "ALTA": Decimal("1.35"),
    "FIESTAS_PATRIAS": Decimal("1.50"),
}


# ==============================================================================
# AUTENTICACIÓN Y REGISTRO (ISO A.8.5 y A.8.24)
# ==============================================================================
def registro_cliente(request):
    if request.method == "POST":
        username = request.POST.get("username", "").strip()
        password = request.POST.get("password", "")
        email = request.POST.get("email", "").strip()
        rol = request.POST.get("rol", ROLE_RECEPTIONIST)
        macrozona = request.POST.get("macrozona", "COSTERA")

        # ISO A.8.24: Largo mínimo de contraseña (12 caracteres)
        if not CryptoControl.validate_password_strength(password):
            return render(
                request,
                "portal/registro.html",
                {"error": f"La contraseña debe tener al menos {CRYPTO_MIN_PASSWORD_LENGTH} caracteres."},
            )

        if User.objects.filter(username=username).exists():
            return render(request, "portal/registro.html", {"error": "No fue posible completar el registro."})

        user = User.objects.create_user(username=username, password=password, email=email)
        PerfilUsuario.objects.create(user=user, rol=rol, macrozona=macrozona)
        AuditLogger.log_event("INFO", f"Usuario registrado: {username} con rol {rol}")
        login(request, user)
        return redirect("dashboard")

    return render(request, "portal/registro.html")


def login_cliente(request):
    if request.method == "POST":
        username = request.POST.get("username", "").strip()
        password = request.POST.get("password", "")

        # ISO A.8.5: Verificar bloqueo por fuerza bruta (900s)
        if AuthControl.is_locked(username):
            return render(
                request,
                "portal/login.html",
                {"error": f"Cuenta bloqueada temporalmente por seguridad ({AUTH_LOCKOUT_SECONDS // 60} min)."},
            )

        user = authenticate(request, username=username, password=password)
        if user is not None:
            AuthControl.reset_attempts(username)
            login(request, user)
            AuditLogger.log_event("INFO", f"Inicio de sesión exitoso: {username}")
            return redirect("dashboard")

        # Mensaje genérico (sin revelar si el usuario existe o no)
        AuthControl.register_failed_attempt(username)
        return render(request, "portal/login.html", {"error": "Credenciales inválidas."})

    return render(request, "portal/login.html")


@require_http_methods(["GET"])
def logout_cliente(request):
    if request.user.is_authenticated:
        AuditLogger.log_event("INFO", f"Cierre de sesión: {request.user.username}")
    logout(request)
    return redirect("login")


# ==============================================================================
# DASHBOARD PRINCIPAL
# ==============================================================================
@login_required(login_url="login")
@require_http_methods(["GET"])
def dashboard(request):
    rol, macrozona = get_user_role_cached(request.user)

    unidades = UnidadAlojamiento.objects.all()
    if macrozona in ("COSTERA", "SUR") and rol != ROLE_ADMIN:
        unidades = unidades.filter(macrozona=macrozona)

    reservas = Reserva.objects.select_related("unidad", "pasajero").order_by("-creada_en")[:20]

    return render(
        request,
        "portal/dashboard.html",
        {
            "unidades": unidades,
            "reservas": reservas,
            "rol": rol,
            "macrozona": macrozona,
        },
    )


# ==============================================================================
# CREAR UNIDAD DE ALOJAMIENTO (Patrón Creacional: Factory Method + RBAC Admin)
# ==============================================================================
@require_role([ROLE_ADMIN])
def crear_unidad(request):
    if request.method == "POST":
        tipo = request.POST.get("tipo", "CABANA")
        unidad = UnidadFactory.crear(
            tipo=tipo,
            nombre=request.POST.get("nombre", "").strip(),
            macrozona=request.POST.get("macrozona", "COSTERA"),
            ubicacion=request.POST.get("ubicacion", "").strip(),
            precio_base=Decimal(request.POST.get("precio_base", "50000")),
            capacidad=int(request.POST.get("capacidad", "2")),
        )
        AuditLogger.log_event("INFO", f"Unidad creada vía Factory: {unidad.nombre} ({unidad.tipo})")
        return redirect("dashboard")

    return render(request, "portal/dashboard.html")


# ==============================================================================
# MOTOR DE RESERVAS SIN OVERBOOKING + TARIFAS DINÁMICAS (A.8.24 + A.8.11)
# ==============================================================================
@require_role([ROLE_ADMIN, ROLE_RECEPTIONIST])
def crear_reserva(request):
    unidades = UnidadAlojamiento.objects.all()

    if request.method == "POST":
        inicio_consulta = time.perf_counter()

        unidad_id = request.POST.get("unidad_id")
        fecha_in = datetime.strptime(request.POST.get("checkin"), "%Y-%m-%d").date()
        fecha_out = datetime.strptime(request.POST.get("checkout"), "%Y-%m-%d").date()
        temporada = request.POST.get("temporada", "BAJA")

        if fecha_out <= fecha_in:
            return render(
                request,
                "portal/crear_reserva.html",
                {"unidades": unidades, "error": "La fecha de check-out debe ser posterior al check-in."},
            )

        unidad = get_object_or_404(UnidadAlojamiento, id=unidad_id)

        # Validación Anti-Overbooking (< 2 segundos)
        existe_solapamiento = Reserva.objects.filter(
            unidad=unidad,
            estado__in=["PENDIENTE", "CONFIRMADA", "CHECKIN"],
        ).filter(
            Q(fecha_checkin__lt=fecha_out) & Q(fecha_checkout__gt=fecha_in)
        ).exists()

        latencia = time.perf_counter() - inicio_consulta
        AuditLogger.log_event("INFO", f"Consulta disponibilidad Unidad #{unidad.id} en {latencia:.4f}s")

        if existe_solapamiento:
            return render(
                request,
                "portal/crear_reserva.html",
                {"unidades": unidades, "error": "Overbooking prevenido: la unidad ya está reservada en esas fechas."},
            )

        # Guardar pasajero con PII cifrado en reposo (ISO A.8.24)
        pasajero = Pasajero(
            nombre_completo=request.POST.get("nombre_pasajero", "Pasajero").strip(),
            email=request.POST.get("email_pasajero", "sin@correo.cl").strip(),
        )
        pasajero.set_rut_pasaporte(request.POST.get("rut_pasajero", "00000000-0").strip())
        pasajero.set_telefono(request.POST.get("telefono_pasajero", "").strip())
        pasajero.save()

        # Cálculo de tarifa dinámica por temporada
        noches = (fecha_out - fecha_in).days
        factor = MULTIPLICADOR_TEMPORADA.get(temporada, Decimal("1.00"))
        total = unidad.precio_base_noche * noches * factor

        reserva = Reserva.objects.create(
            unidad=unidad,
            pasajero=pasajero,
            creado_por=request.user,
            fecha_checkin=fecha_in,
            fecha_checkout=fecha_out,
            temporada=temporada,
            total_estadia=total,
            estado="PENDIENTE",
        )
        return redirect("pago_reserva", reserva_id=reserva.id)

    return render(request, "portal/crear_reserva.html", {"unidades": unidades})


@require_role([ROLE_ADMIN, ROLE_RECEPTIONIST])
def pago_reserva(request, reserva_id):
    reserva = get_object_or_404(Reserva, id=reserva_id)

    if request.method == "POST":
        tarjeta = request.POST.get("tarjeta", "")
        turno = request.POST.get("turno", "MANANA")
        # Abono del 50% por defecto
        monto_abono = (reserva.total_estadia * Decimal("0.50")).quantize(Decimal("0.01"))

        MovimientoCaja.objects.create(
            reserva=reserva,
            registrado_por=request.user,
            tipo="ABONO",
            turno=turno,
            monto=monto_abono,
            tarjeta_enmascarada=DataMasking.mask_card(tarjeta),  # ISO A.8.11
        )
        reserva.abono_pagado += monto_abono
        reserva.estado = "CONFIRMADA"
        reserva.save(update_fields=["abono_pagado", "estado"])

        AuditLogger.log_event("INFO", f"Abono de ${monto_abono} registrado para Reserva #{reserva.id}")
        return render(request, "portal/pago_exitoso.html", {"reserva": reserva, "monto": monto_abono})

    return render(request, "portal/pago.html", {"reserva": reserva})


# ==============================================================================
# CHECK-IN (Patrón State) Y CHECK-OUT (Patrón Facade + State)
# ==============================================================================
@require_role([ROLE_ADMIN, ROLE_RECEPTIONIST])
@require_http_methods(["POST"])
def checkin_reserva(request, reserva_id):
    reserva = get_object_or_404(Reserva, id=reserva_id)
    try:
        estado_actual = GestorEstadoUnidad.obtener_estado(reserva.unidad)
        estado_actual.ocupar(reserva.unidad)

        if reserva.saldo_pendiente > 0:
            MovimientoCaja.objects.create(
                reserva=reserva,
                registrado_por=request.user,
                tipo="SALDO_CHECKIN",
                turno=request.POST.get("turno", "MANANA"),
                monto=reserva.saldo_pendiente,
            )
            reserva.abono_pagado += reserva.saldo_pendiente

        reserva.estado = "CHECKIN"
        reserva.save(update_fields=["abono_pagado", "estado"])
    except ValueError as e:
        return HttpResponse(str(e), status=400)

    return redirect("dashboard")


@require_role([ROLE_ADMIN, ROLE_RECEPTIONIST])
@require_http_methods(["POST"])
def checkout_reserva(request, reserva_id):
    reserva = get_object_or_404(Reserva, id=reserva_id)
    costo_extra = Decimal(request.POST.get("costo_extra", "0") or "0")
    descripcion_dano = request.POST.get("descripcion_dano", "")
    turno = request.POST.get("turno", "MANANA")

    try:
        CheckoutFacade.ejecutar_checkout(
            reserva=reserva,
            usuario_operador=request.user,
            turno=turno,
            descripcion_dano=descripcion_dano,
            costo_extra=costo_extra,
        )
    except ValueError as e:
        return HttpResponse(str(e), status=400)

    return redirect("dashboard")


# ==============================================================================
# FLUJO DE ASEO (Patrón State + RBAC Aseo/Admin)
# ==============================================================================
@require_role([ROLE_ADMIN, ROLE_CLEANING])
@require_http_methods(["POST"])
def cambiar_estado_aseo(request, unidad_id):
    unidad = get_object_or_404(UnidadAlojamiento, id=unidad_id)
    accion = request.POST.get("accion")

    try:
        estado_actual = GestorEstadoUnidad.obtener_estado(unidad)
        if accion == "iniciar_limpieza":
            estado_actual.iniciar_limpieza(unidad)
        elif accion == "habilitar":
            estado_actual.habilitar(unidad)
        else:
            return HttpResponse("Acción de aseo inválida.", status=400)
    except ValueError as e:
        return HttpResponse(str(e), status=400)

    return redirect("dashboard")


# ==============================================================================
# EXPORTACIÓN DE REPORTES DE CAJA (Patrón Adapter: Excel o PDF + RBAC Admin)
# ==============================================================================
@require_role([ROLE_ADMIN])
@require_http_methods(["GET"])
def exportar_caja(request):
    formato = request.GET.get("formato", "xlsx")  # 'xlsx' o 'pdf'
    movimientos = MovimientoCaja.objects.select_related("reserva").order_by("-fecha_transaccion")

    exportador = obtener_exportador(formato)
    archivo_bytes = exportador.exportar(movimientos)

    AuditLogger.log_event("INFO", f"Reporte de caja exportado en formato {exportador.extension} por {request.user.username}")

    response = HttpResponse(archivo_bytes, content_type=exportador.content_type)
    response["Content-Disposition"] = f'attachment; filename="cierre_caja_tuchile.{exportador.extension}"'
    return response
