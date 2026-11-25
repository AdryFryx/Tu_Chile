from abc import ABC, abstractmethod
from decimal import Decimal
from portal.models import UnidadAlojamiento


class UnidadCreator(ABC):
    """Interfaz base del patrón Factory Method."""

    @abstractmethod
    def crear_unidad(
        self, nombre: str, macrozona: str, ubicacion: str, precio_base: Decimal, capacidad: int
    ) -> UnidadAlojamiento:
        pass


class CabanaCreator(UnidadCreator):
    """Crea una Cabaña con su inventario crítico de menaje y gas."""

    def crear_unidad(
        self, nombre: str, macrozona: str, ubicacion: str, precio_base: Decimal, capacidad: int
    ) -> UnidadAlojamiento:
        inventario_critico = {
            "balon_gas_15kg": 1,
            "kit_menaje_cocina": capacidad,
            "juegos_sabanas": capacidad,
            "llaves_acceso": 2,
        }
        return UnidadAlojamiento.objects.create(
            nombre=nombre,
            tipo="CABANA",
            macrozona=macrozona,
            ubicacion=ubicacion,
            precio_base_noche=precio_base,
            capacidad=capacidad,
            estado="DISPONIBLE",
            inventario_base=inventario_critico,
        )


class HabitacionCreator(UnidadCreator):
    """Crea una Habitación de Hotel con servicios estandarizados."""

    def crear_unidad(
        self, nombre: str, macrozona: str, ubicacion: str, precio_base: Decimal, capacidad: int
    ) -> UnidadAlojamiento:
        servicios_estandar = {
            "desayuno_incluido": True,
            "aseo_diario": True,
            "wifi_tv_cable": True,
            "tarjeta_acceso": 1,
        }
        return UnidadAlojamiento.objects.create(
            nombre=nombre,
            tipo="HABITACION",
            macrozona=macrozona,
            ubicacion=ubicacion,
            precio_base_noche=precio_base,
            capacidad=capacidad,
            estado="DISPONIBLE",
            inventario_base=servicios_estandar,
        )


class UnidadFactory:
    """Punto de entrada único para instanciar unidades según su tipo."""

    _CREATORS = {
        "CABANA": CabanaCreator(),
        "HABITACION": HabitacionCreator(),
    }

    @classmethod
    def crear(cls, tipo: str, **kwargs) -> UnidadAlojamiento:
        creator = cls._CREATORS.get(tipo.upper())
        if not creator:
            raise ValueError(f"Tipo de unidad no soportado: {tipo}")
        return creator.crear_unidad(**kwargs)