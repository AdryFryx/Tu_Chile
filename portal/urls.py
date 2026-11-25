from django.urls import path
from . import views

urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("registro/", views.registro_cliente, name="registro"),
    path("login/", views.login_cliente, name="login"),
    path("logout/", views.logout_cliente, name="logout"),

    # Unidades (Factory Method)
    path("unidades/crear/", views.crear_unidad, name="crear_unidad"),

    # Reservas y Pagos
    path("reservas/crear/", views.crear_reserva, name="crear_reserva"),
    path("reservas/<int:reserva_id>/pago/", views.pago_reserva, name="pago_reserva"),
    path("reservas/<int:reserva_id>/checkin/", views.checkin_reserva, name="checkin_reserva"),
    path("reservas/<int:reserva_id>/checkout/", views.checkout_reserva, name="checkout_reserva"),

    # Aseo (State)
    path("aseo/<int:unidad_id>/estado/", views.cambiar_estado_aseo, name="cambiar_estado_aseo"),

    # Reportes (Adapter: ?formato=xlsx o ?formato=pdf)
    path("reportes/caja/", views.exportar_caja, name="exportar_caja"),
]