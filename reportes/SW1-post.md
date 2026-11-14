# Informe de SW1

Fecha UTC: 2026-11-14T02:15:53+00:00
Modo: Aplicacion y revision posterior

| Control | Antes | Despues |
|---|---|---|
| CIS 1.1.2.3 VTY solo SSH | CUMPLE | CUMPLE |
| CIS 1.1.2.4 timeout consola | HALLAZGO | CUMPLE |
| CIS 1.1.2.4 timeout VTY | CUMPLE | CUMPLE |
| CIS 1.1.2.5 AUX sin EXEC | HALLAZGO | CUMPLE |
| CIS 1.2.2.5 HTTP deshabilitado | HALLAZGO | CUMPLE |
| HTTPS no requerido deshabilitado | HALLAZGO | CUMPLE |
| CIS 1.2.2.7 TCP keepalives entrada | HALLAZGO | CUMPLE |
| CIS 1.2.2.8 TCP keepalives salida | HALLAZGO | CUMPLE |

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
