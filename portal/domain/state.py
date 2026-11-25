from abc import ABC
from portal.models import UnidadAlojamiento
from portal.security.controls import AuditLogger


class EstadoUnidad(ABC):
    """Estado base de una UnidadAlojamiento (Patrón State)."""

    nombre_estado: str = ""

    def ocupar(self, unidad: UnidadAlojamiento) -> None:
        raise ValueError(f"No se puede ocupar una unidad en estado {self.nombre_estado}.")

    def marcar_sucio(self, unidad: UnidadAlojamiento) -> None:
        raise ValueError(f"No se puede marcar sucia una unidad en estado {self.nombre_estado}.")

    def iniciar_limpieza(self, unidad: UnidadAlojamiento) -> None:
        raise ValueError(f"No se puede iniciar limpieza en estado {self.nombre_estado}.")

    def habilitar(self, unidad: UnidadAlojamiento) -> None:
        raise ValueError(f"No se puede habilitar una unidad en estado {self.nombre_estado}.")

    @staticmethod
    def _transicionar(unidad: UnidadAlojamiento, nuevo_estado: str) -> None:
        anterior = unidad.estado
        unidad.estado = nuevo_estado
        unidad.save(update_fields=["estado"])
        AuditLogger.log_event(
            "INFO", f"Unidad #{unidad.id} ({unidad.nombre}) cambió de {anterior} a {nuevo_estado}"
        )


class DisponibleState(EstadoUnidad):
    nombre_estado = "DISPONIBLE"

    def ocupar(self, unidad: UnidadAlojamiento) -> None:
        self._transicionar(unidad, "OCUPADA")


class OcupadaState(EstadoUnidad):
    nombre_estado = "OCUPADA"

    def marcar_sucio(self, unidad: UnidadAlojamiento) -> None:
        self._transicionar(unidad, "SUCIO")


class SucioState(EstadoUnidad):
    nombre_estado = "SUCIO"

    def iniciar_limpieza(self, unidad: UnidadAlojamiento) -> None:
        self._transicionar(unidad, "LIMPIEZA")


class LimpiezaState(EstadoUnidad):
    nombre_estado = "LIMPIEZA"

    def habilitar(self, unidad: UnidadAlojamiento) -> None:
        self._transicionar(unidad, "DISPONIBLE")


class GestorEstadoUnidad:
    """Contexto que resuelve la clase de estado actual de una unidad."""

    _ESTADOS = {
        "DISPONIBLE": DisponibleState(),
        "OCUPADA": OcupadaState(),
        "SUCIO": SucioState(),
        "LIMPIEZA": LimpiezaState(),
    }

    @classmethod
    def obtener_estado(cls, unidad: UnidadAlojamiento) -> EstadoUnidad:
        estado_obj = cls._ESTADOS.get(unidad.estado)
        if not estado_obj:
            raise ValueError(f"Estado desconocido: {unidad.estado}")
        return estado_obj