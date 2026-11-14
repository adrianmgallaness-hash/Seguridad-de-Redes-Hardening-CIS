# Matriz de pruebas

| Objetivo | Procedimiento y resultado | Evidencia |
|---|---|---|
| Topología real | R1, FortiGate, SW1 y una Ubuntu Desktop conectados en GNS3 | [Captura con puertos](../evidencias/01-topologia-puertos.png) |
| Política del firewall | Política PING desactivada: 0/5. Reactivada: 5/5 | [Bloqueo](../evidencias/02-politica-desactivada-ping-bloqueado.png) · [Permiso](../evidencias/03-politica-activada-ping-permitido.png) · [Regla](../evidencias/04-politica-fortigate.png) |
| SSH Cisco antes de la automatización | Acceso desde Ubuntu a SW1 y R1, privilegio 15 confirmado en R1 | [Sesión en R1](../evidencias/06-ssh-router-exitoso.png); salida de SW1 mostrada por el estudiante |
| Auditor sin cambios | Generó informes previos para los tres equipos | [Ejecución](../evidencias/07-script-modo-informe.png) · [Informes](../reportes/) |
| Aplicación automática | Generó informes `pre` y `post` para los tres equipos; los post indican todos los controles seleccionados conformes | [Informes posteriores](../reportes/) y configuraciones posteriores |
| Conectividad y acceso posteriores | Ubuntu obtuvo 3/3 pings a cada equipo; el auditor abrió nuevas sesiones SSH | Salida facilitada por el estudiante; captura pendiente de publicación |
| Servicios de gestión del switch | Puerto 22 abierto; 80 y 443 cerrados | Salida facilitada por el estudiante; captura pendiente de publicación |

Los informes `pre`/`post` evalúan la configuración exportada por comandos de lectura del script. Las capturas de ping y puertos son las pruebas funcionales. Ninguna de las capturas prueba una evaluación completa de CIS ni la fortaleza real de las contraseñas.

