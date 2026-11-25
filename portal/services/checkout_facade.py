from decimal import Decimal
from django.db import transaction
from portal.models import MovimientoCaja, ReporteDano, Reserva
from portal.domain.state import GestorEstadoUnidad
from portal.security.controls import AuditLogger


class CheckoutFacade:
    """
    Patrón Facade: orquesta el flujo completo de Check-out en una sola operación atómica:
    1) Registra daños/faltantes de inventario si existen.
    2) Actualiza cobros extra y cierra la reserva.
    3) Registra el movimiento en caja diaria.
    4) Cambia automáticamente la unidad a estado 'SUCIO' usando el patrón State.
    """

    @staticmethod
    @transaction.atomic
    def ejecutar_checkout(
        reserva: Reserva,
        usuario_operador,
        turno: str = "MANANA",
        descripcion_dano: str = "",
        costo_extra: Decimal = Decimal("0.00"),
    ) -> dict:
        if reserva.estado != "CHECKIN":
            raise ValueError("Solo se puede hacer check-out a una reserva con check-in activo.")

        # 1. Registrar daño de inventario (menaje/gas) si aplica
        if costo_extra > Decimal("0.00") or descripcion_dano.strip():
            ReporteDano.objects.create(
                unidad=reserva.unidad,
                reserva=reserva,
                reportado_por=usuario_operador,
                descripcion=descripcion_dano.strip() or "Cobro extra por recambio/inventario",
                costo_estimado=costo_extra,
            )
            reserva.cobros_extra += costo_extra

            # 2. Registrar cobro extra en caja
            MovimientoCaja.objects.create(
                reserva=reserva,
                registrado_por=usuario_operador,
                tipo="COBRO_EXTRA",
                turno=turno,
                monto=costo_extra,
            )

        # 3. Finalizar reserva
        reserva.estado = "CHECKOUT"
        reserva.save(update_fields=["cobros_extra", "estado"])

        # 4. Cambiar estado de la unidad a 'SUCIO' (Patrón State)
        estado_actual = GestorEstadoUnidad.obtener_estado(reserva.unidad)
        estado_actual.marcar_sucio(reserva.unidad)

        AuditLogger.log_event(
            "INFO",
            f"Check-out completado para Reserva #{reserva.id} por {usuario_operador.username} (extra=${costo_extra})",
        )

        return {
            "reserva_id": reserva.id,
            "unidad": reserva.unidad.nombre,
            "nuevo_estado_unidad": reserva.unidad.estado,
            "cobros_extra": reserva.cobros_extra,
            "saldo_pendiente": reserva.saldo_pendiente,
        }