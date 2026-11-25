from abc import ABC, abstractmethod
from io import BytesIO
from openpyxl import Workbook
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas


class ReporteExporter(ABC):
    """Interfaz común del patrón Adapter para exportación de reportes."""

    content_type: str = ""
    extension: str = ""

    @abstractmethod
    def exportar(self, movimientos) -> bytes:
        pass


class ExcelReporteAdapter(ReporteExporter):
    """Adapta la librería openpyxl a nuestra interfaz ReporteExporter."""

    content_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    extension = "xlsx"

    def exportar(self, movimientos) -> bytes:
        wb = Workbook()
        ws = wb.active
        ws.title = "Cierre Caja TUCHILE"
        ws.append(["ID", "Fecha", "Turno", "Tipo", "Reserva", "Monto (CLP)", "Medio/Tarjeta"])

        total = 0
        for m in movimientos:
            ws.append([
                m.id,
                m.fecha_transaccion.strftime("%Y-%m-%d %H:%M"),
                m.turno,
                m.tipo,
                f"#{m.reserva_id}",
                float(m.monto),
                m.tarjeta_enmascarada,
            ])
            total += float(m.monto)

        ws.append(["", "", "", "", "TOTAL CAJA:", total, ""])

        buffer = BytesIO()
        wb.save(buffer)
        return buffer.getvalue()


class PdfReporteAdapter(ReporteExporter):
    """Adapta la librería ReportLab a nuestra interfaz ReporteExporter."""

    content_type = "application/pdf"
    extension = "pdf"

    def exportar(self, movimientos) -> bytes:
        buffer = BytesIO()
        pdf = canvas.Canvas(buffer, pagesize=letter)
        pdf.setTitle("Resumen Operativo y Caja - Turismo TUCHILE")

        y = 750
        pdf.setFont("Helvetica-Bold", 14)
        pdf.drawString(50, y, "Turismo TUCHILE - Resumen de Caja Diaria")
        y -= 30

        pdf.setFont("Helvetica", 10)
        total = 0
        for m in movimientos:
            linea = (
                f"#{m.id} | {m.fecha_transaccion.strftime('%Y-%m-%d %H:%M')} | "
                f"{m.turno} | {m.tipo} | Res #{m.reserva_id} | ${m.monto}"
            )
            pdf.drawString(50, y, linea)
            total += float(m.monto)
            y -= 18
            if y < 60:
                pdf.showPage()
                y = 750

        y -= 15
        pdf.setFont("Helvetica-Bold", 11)
        pdf.drawString(50, y, f"TOTAL RECAUDADO: ${total:,.2f} CLP")

        pdf.save()
        return buffer.getvalue()


def obtener_exportador(formato: str) -> ReporteExporter:
    """Devuelve el adaptador según la elección del Administrador ('xlsx' o 'pdf')."""
    fmt = (formato or "xlsx").lower()
    if fmt == "pdf":
        return PdfReporteAdapter()
    return ExcelReporteAdapter()