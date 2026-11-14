# Informe de SW1

Fecha UTC: 2026-11-14T02:12:39+00:00
Modo: Solo informe; sin cambios

| Control | Antes | Despues |
|---|---|---|
| CIS 1.1.2.3 VTY solo SSH | CUMPLE | NO APLICADO |
| CIS 1.1.2.4 timeout consola | HALLAZGO | NO APLICADO |
| CIS 1.1.2.4 timeout VTY | CUMPLE | NO APLICADO |
| CIS 1.1.2.5 AUX sin EXEC | HALLAZGO | NO APLICADO |
| CIS 1.2.2.5 HTTP deshabilitado | HALLAZGO | NO APLICADO |
| HTTPS no requerido deshabilitado | HALLAZGO | NO APLICADO |
| CIS 1.2.2.7 TCP keepalives entrada | HALLAZGO | NO APLICADO |
| CIS 1.2.2.8 TCP keepalives salida | HALLAZGO | NO APLICADO |

## Comandos propuestos o ejecutados

- `no ip http server`
- `no ip http secure-server`
- `service tcp-keepalives-in`
- `service tcp-keepalives-out`
- `line con 0`
- `exec-timeout 5 0`
- `exit`
- `line aux 0`
- `no exec`
- `exit`

Revision parcial de controles seleccionados; no es certificacion CIS.
El informe no contiene contrasenas ni running-configs.

_Transcripcion del resultado mostrado por el estudiante en la conversacion; el archivo original permanece en Ubuntu._
