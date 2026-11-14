# Auditor automático del laboratorio

El script `hardening.py` se ejecuta desde Ubuntu (`10.21.39.100`) y se conecta
por SSH a SW1 (`.66`), R1 (`.1`) y FortiGate (`.65`). Solicita las contraseñas
sin guardarlas ni incluirlas en los informes. No requiere `pip` ni `netmiko`.

## Preparación

Python 3 y el cliente `ssh` de Ubuntu son suficientes.

Se requiere que las cuentas SSH de los tres equipos funcionen. En R1, la
política FortiGate 2 permite SSH únicamente desde Ubuntu. La imagen Cisco
7200 usa algoritmos SSH antiguos; esta es una limitación de la imagen.

## Modo sin cambios

```bash
python3 scripts/hardening.py report --output reportes
```

Genera un informe `*-pre.md` por dispositivo. Este modo solo ejecuta comandos
de consulta.

## Aplicación y revisión posterior

Antes de aplicar, conservar un respaldo local y confirmar el acceso por consola
a los tres equipos.

```bash
python3 scripts/hardening.py apply --output reportes
```

El script guarda un informe previo, aplica solo controles que no cumplen,
vuelve a consultar y guarda un informe `*-post.md`. En Cisco guarda la
configuración solo tras una verificación posterior sin errores. FortiOS aplica
los cambios al salir del modo de configuración.

Controles Cisco seleccionados: VTY solo SSH, timeout de consola y VTY, AUX sin
EXEC, HTTP deshabilitado, TCP keepalives de entrada y salida. Deshabilitar HTTPS
en el switch es un control complementario porque no se utiliza la interfaz web.
Control FortiGate: no exponer HTTP, HTTPS, SSH ni FGFM en `port1`, el enlace de
tránsito hacia R1; se conserva `ping` para las pruebas.

Esta revisión cubre controles elegidos de los benchmarks CIS; no representa
una evaluación completa ni una certificación de CIS.
