# Selección de controles y justificación

## Referencias

- [CIS Cisco IOS Benchmark v2.2](https://www.cisecurity.org/-/jssmedia/Project/cisecurity/cisecurity/data/media/files/uploads/2017/04/CIS_Cisco_IOS_Benchmark_v22.pdf): documento histórico aplicable a IOS 12.x o superior, usado porque ambos equipos del laboratorio ejecutan IOS 15.2.
- [CIS FortiGate 7.0.x Benchmark](https://www.cisecurity.org/benchmark/fortinet): familia y versión correspondiente al firewall FortiOS 7.0.9. El control de acceso administrativo de `port1` se registra como revisión adaptada, sin atribuirle un número de sección no verificado.
- [Fortinet: configuración de acceso administrativo por interfaz](https://docs.fortinet.com/document/fortigate/7.0.10/administration-guide/574723/interface-settings).

## Router y switch Cisco

| Control seleccionado | Por qué se aplicó | Estado verificado |
|---|---|---|
| CIS 1.1.2.3, VTY solo SSH | Evitar acceso remoto por Telnet en texto claro | `transport input ssh` en ambos equipos; nuevas sesiones SSH del auditor funcionaron |
| CIS 1.1.2.4, expiración de sesiones | Reducir exposición de consolas abandonadas | `exec-timeout 5 0` en consola y VTY |
| CIS 1.1.2.5, AUX sin EXEC | Cerrar un acceso administrativo no utilizado | `no exec` en AUX |
| CIS 1.2.2.5, servidor HTTP apagado | Evitar gestión web HTTP no necesaria | `no ip http server`; en SW1 el puerto 80 quedó cerrado |
| CIS 1.2.2.7 y 1.2.2.8, TCP keepalives | Retirar sesiones TCP muertas | `service tcp-keepalives-in` y `service tcp-keepalives-out` |

Se deshabilitó además HTTPS en SW1 porque el laboratorio administra el switch por SSH. Este control es complementario; no se presenta como el control CIS 1.2.2.5, que se refiere a HTTP. La prueba de puertos confirmó SSH/22 abierto y HTTP/80 y HTTPS/443 cerrados.

## FortiGate

`port1` conecta al segmento de tránsito con R1. Inicialmente aceptaba `ping https ssh http fgfm`. El script lo redujo a `ping`; así la administración remota queda disponible solo por `port2` desde la LAN. El informe posterior confirmó la directiva, y el ping posterior entre FortiGate y R1 permite comprobar que el enlace sigue operativo.

Las políticas de firewall para PING y SSH de Ubuntu a R1 usan objetos de host específicos y servicios separados. La prueba controlada de la política PING obtuvo 0/5 respuestas cuando se desactivó y 5/5 tras reactivarla.

## Alcance y limitaciones

El auditor evalúa exclusivamente los controles listados. Comprueba configuración textual y conectividad; no mide la eficacia de keepalives con una sesión TCP averiada ni prueba físicamente el puerto AUX. El IOS 15.2 del router ofrece KEX SHA-1 y cifrados CBC; Ubuntu requirió opciones de compatibilidad **solo para esa conexión**. SSHv2 no elimina esa limitación criptográfica. Una actualización de la imagen sería necesaria para eliminarla si se dispusiera de una versión compatible más moderna.
