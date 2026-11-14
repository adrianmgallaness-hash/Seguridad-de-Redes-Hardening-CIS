"""Auditor de controles CIS seleccionados para el laboratorio 2025-2139.

Se ejecuta desde Ubuntu en la LAN. `report` solo consulta; `apply` consulta,
aplica comandos faltantes y vuelve a consultar. Usa Python y OpenSSH instalados.
"""

import argparse
from datetime import datetime, timezone
import getpass
import os
from pathlib import Path
import re
import select
import signal
import time


DEVICES = [
    {"name": "SW1", "device_type": "cisco_ios", "host": "10.21.39.66", "username": "auditor2139"},
    {"name": "R1", "device_type": "cisco_ios", "host": "10.21.39.1", "username": "auditor2139"},
    {"name": "FortiGate", "prompt": "FortiGate-VM64-KVM", "device_type": "fortinet",
     "host": "10.21.39.65", "username": "admin"},
]


def sections(config):
    result = {}
    key = None
    for line in config.splitlines():
        if line and not line.startswith((" ", "!")):
            key = line.strip()
            result[key] = []
        elif key and line.startswith(" "):
            result[key].append(line.strip())
    return result


def timeout_ok(lines):
    matches = [re.fullmatch(r"exec-timeout\s+(\d+)(?:\s+(\d+))?", x) for x in lines]
    matches = [x for x in matches if x]
    if not matches:
        return False
    seconds = int(matches[-1][1]) * 60 + int(matches[-1][2] or 0)
    return 0 < seconds <= 600


def audit_cisco(config):
    globals_ = {x.strip() for x in config.splitlines() if x and not x.startswith((" ", "!"))}
    block = sections(config)
    vtys = [v for k, v in block.items() if k.startswith("line vty ")]
    console = block.get("line con 0", [])
    aux = block.get("line aux 0", [])
    return {
        "CIS 1.1.2.3 VTY solo SSH": bool(vtys) and all("transport input ssh" in x for x in vtys),
        "CIS 1.1.2.4 timeout consola": timeout_ok(console),
        "CIS 1.1.2.4 timeout VTY": bool(vtys) and all(timeout_ok(x) for x in vtys),
        "CIS 1.1.2.5 AUX sin EXEC": "no exec" in aux,
        "CIS 1.2.2.5 HTTP deshabilitado": "no ip http server" in globals_ and "ip http server" not in globals_,
        "HTTPS no requerido deshabilitado": "no ip http secure-server" in globals_ and "ip http secure-server" not in globals_,
        "CIS 1.2.2.7 TCP keepalives entrada": "service tcp-keepalives-in" in globals_,
        "CIS 1.2.2.8 TCP keepalives salida": "service tcp-keepalives-out" in globals_,
    }


def cisco_commands(config):
    state = audit_cisco(config)
    out = []
    if not state["CIS 1.2.2.5 HTTP deshabilitado"]:
        out.append("no ip http server")
    if not state["HTTPS no requerido deshabilitado"]:
        out.append("no ip http secure-server")
    if not state["CIS 1.2.2.7 TCP keepalives entrada"]:
        out.append("service tcp-keepalives-in")
    if not state["CIS 1.2.2.8 TCP keepalives salida"]:
        out.append("service tcp-keepalives-out")
    if not state["CIS 1.1.2.4 timeout consola"]:
        out += ["line con 0", "exec-timeout 5 0", "exit"]
    if not state["CIS 1.1.2.5 AUX sin EXEC"]:
        out += ["line aux 0", "no exec", "exit"]
    vtys = [k for k in sections(config) if k.startswith("line vty ")]
    if vtys and (not state["CIS 1.1.2.3 VTY solo SSH"] or not state["CIS 1.1.2.4 timeout VTY"]):
        for line in vtys:
            out.append(line)
            if "transport input ssh" not in sections(config)[line]:
                out.append("transport input ssh")
            if not timeout_ok(sections(config)[line]):
                out.append("exec-timeout 5 0")
            out.append("exit")
    return out


def audit_fortigate(interface):
    match = re.search(r"(?m)^\s*set allowaccess\s+(.+)$", interface)
    allowed = set(match.group(1).split()) if match else set()
    return {"FortiGate: administracion restringida en port1":
            not bool(allowed & {"http", "https", "ssh", "telnet", "fgfm"})}


def report(name, before, after, commands, mode, error=None):
    lines = [f"# Informe de {name}", "", f"Fecha UTC: {datetime.now(timezone.utc).isoformat(timespec='seconds')}",
             f"Modo: {mode}", "", "| Control | Antes | Después |", "|---|---|---|"]
    for key, value in before.items():
        post = "NO APLICADO" if after is None else "CUMPLE" if after.get(key) else "HALLAZGO"
        lines.append(f"| {key} | {'CUMPLE' if value else 'HALLAZGO'} | {post} |")
    lines += ["", "## Comandos propuestos o ejecutados", ""]
    lines += [f"- `{x}`" for x in commands] if commands else ["- Ninguno"]
    if error:
        lines += ["", f"**Error:** {error}"]
    lines += ["", "Evaluación parcial de controles elegidos. No equivale a una certificación CIS.",
              "El informe no incluye contraseñas ni running-configs; estos se sanitizan por separado."]
    return "\n".join(lines) + "\n"


class SSHSession:
    """Shell interactivo SSH sobre un pseudo-terminal, sin librerías externas."""

    def __init__(self, device, password):
        import pty  # Disponible en Linux, donde corre Ubuntu.

        self.pid, self.master = pty.fork()
        name = device["name"]
        prefix = re.escape(device.get("prompt", name))
        self.prompt = re.compile(rf"(?m)^{prefix}(?: ?\([^)]*\))? ?#\s*\Z")
        command = ["ssh", "-tt", "-oConnectTimeout=12", "-oNumberOfPasswordPrompts=1",
                   "-oStrictHostKeyChecking=accept-new", "-oPubkeyAuthentication=no",
                   "-oPreferredAuthentications=password"]
        if device["device_type"] == "cisco_ios":
            command += ["-oKexAlgorithms=+diffie-hellman-group14-sha1",
                        "-oHostKeyAlgorithms=+ssh-rsa"]
            if name == "R1":
                command += ["-oCiphers=+aes256-cbc"]
        command.append(f"{device['username']}@{device['host']}")
        if self.pid == 0:
            try:
                os.execvp("ssh", command)
            except OSError:
                os._exit(127)
        first = self._read(password_prompt=True, timeout=45)
        if re.search(r"(?i)password:\s*$", first):
            os.write(self.master, password.encode() + b"\n")
            self._read(timeout=45)

    def _read(self, password_prompt=False, timeout=45):
        deadline = time.monotonic() + timeout
        output = ""
        while time.monotonic() < deadline:
            ready, _, _ = select.select([self.master], [], [], min(1, max(0, deadline-time.monotonic())))
            if not ready:
                continue
            try:
                chunk = os.read(self.master, 65536).decode("utf-8", errors="replace")
            except OSError as exc:
                raise RuntimeError("La sesión SSH terminó") from exc
            output += chunk.replace("\r", "")
            tail = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", output)
            if self.prompt.search(tail):
                return tail
            if password_prompt and re.search(r"(?i)password:\s*$", tail):
                return tail
            if re.search(r"(?i)(?:permission denied|connection refused|no matching)", tail):
                raise RuntimeError("SSH rechazó la conexión o las credenciales")
            if tail.rstrip().endswith("[confirm]"):
                os.write(self.master, b"\n")
        raise RuntimeError("Tiempo de espera agotado en SSH")

    def send(self, command, timeout=45):
        os.write(self.master, command.encode() + b"\n")
        return self._read(timeout=timeout)

    def close(self):
        try:
            os.kill(self.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            os.waitpid(self.pid, 0)
        except ChildProcessError:
            pass
        os.close(self.master)


def read_state(conn, kind):
    if kind == "cisco_ios":
        conn.send("terminal length 0")
        config = conn.send("show running-config", timeout=90)
        return config, audit_cisco(config)
    config = conn.send("show system interface port1", timeout=60)
    return config, audit_fortigate(config)


def apply_changes(conn, kind, commands):
    if not commands:
        return
    if kind == "cisco_ios":
        conn.send("configure terminal")
        try:
            for command in commands:
                result = conn.send(command)
                if re.search(r"%\s*(?:Invalid input|Incomplete command|Error)", result, re.I):
                    raise RuntimeError("IOS rechazó un comando; revise la consola")
        finally:
            conn.send("end")
    else:
        for command in commands:
            result = conn.send(command)
            if re.search(r"(?:Command fail|command parse error|Return code -)", result, re.I):
                raise RuntimeError("FortiOS rechazó un comando; revise la consola")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["report", "apply"])
    parser.add_argument("--output", type=Path, default=Path("reportes"))
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    for device in DEVICES:
        name, kind = device["name"], device["device_type"]
        password = getpass.getpass(f"Contraseña de {name} ({device['host']}): ")
        connection = SSHSession(device, password)
        try:
            config, before = read_state(connection, kind)
            commands = cisco_commands(config) if kind == "cisco_ios" else (
                ["config system interface", 'edit "port1"', "set allowaccess ping", "next", "end"]
                if not next(iter(before.values())) else [])
            if args.mode == "report":
                content = report(name, before, None, commands, "Solo informe; sin cambios")
                path = args.output / f"{name}-pre.md"
                path.write_text(content, encoding="utf-8")
            else:
                path = args.output / f"{name}-pre.md"
                path.write_text(report(name, before, None, commands, "Línea base antes de aplicar"), encoding="utf-8")
                error = None
                try:
                    apply_changes(connection, kind, commands)
                except Exception as exc:
                    error = str(exc)
                _, after = read_state(connection, kind)
                if not error and commands and not all(after.values()):
                    error = "La verificación posterior conserva hallazgos; no se guardó IOS"
                if kind == "cisco_ios" and commands and not error:
                    connection.send("write memory", timeout=90)
                content = report(name, before, after, commands, "Aplicación y revisión posterior", error)
                path = args.output / f"{name}-post.md"
                path.write_text(content, encoding="utf-8")
            print(path)
        finally:
            connection.close()


if __name__ == "__main__":
    main()
