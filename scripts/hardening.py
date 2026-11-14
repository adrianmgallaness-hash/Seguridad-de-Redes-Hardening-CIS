"""Auditor de controles CIS seleccionados del laboratorio 2025-2139."""

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
    {"name": "SW1", "type": "cisco", "host": "10.21.39.66", "user": "auditor2139"},
    {"name": "R1", "type": "cisco", "host": "10.21.39.1", "user": "auditor2139"},
    {"name": "FortiGate", "type": "fortinet", "host": "10.21.39.65",
     "user": "admin", "prompt": "FortiGate-VM64-KVM"},
]


def sections(config):
    result = {}
    current = None
    for line in config.splitlines():
        if line and not line.startswith((" ", "!")):
            current = line.strip()
            result[current] = []
        elif current and line.startswith(" "):
            result[current].append(line.strip())
    return result


def timeout_ok(lines):
    matches = [re.fullmatch(r"exec-timeout\s+(\d+)(?:\s+(\d+))?", x)
               for x in lines]
    matches = [x for x in matches if x]
    if not matches:
        return False
    seconds = int(matches[-1][1]) * 60 + int(matches[-1][2] or 0)
    return 0 < seconds <= 600


def audit_cisco(config):
    global_lines = {
        line.strip() for line in config.splitlines()
        if line and not line.startswith((" ", "!"))
    }
    blocks = sections(config)
    vtys = [value for key, value in blocks.items()
            if key.startswith("line vty ")]
    return {
        "CIS 1.1.2.3 VTY solo SSH":
            bool(vtys) and all("transport input ssh" in x for x in vtys),
        "CIS 1.1.2.4 timeout consola":
            timeout_ok(blocks.get("line con 0", [])),
        "CIS 1.1.2.4 timeout VTY":
            bool(vtys) and all(timeout_ok(x) for x in vtys),
        "CIS 1.1.2.5 AUX sin EXEC":
            "no exec" in blocks.get("line aux 0", []),
        "CIS 1.2.2.5 HTTP deshabilitado":
            "no ip http server" in global_lines
            and "ip http server" not in global_lines,
        "HTTPS no requerido deshabilitado":
            "no ip http secure-server" in global_lines
            and "ip http secure-server" not in global_lines,
        "CIS 1.2.2.7 TCP keepalives entrada":
            "service tcp-keepalives-in" in global_lines,
        "CIS 1.2.2.8 TCP keepalives salida":
            "service tcp-keepalives-out" in global_lines,
    }


def cisco_commands(config):
    state = audit_cisco(config)
    commands = []
    if not state["CIS 1.2.2.5 HTTP deshabilitado"]:
        commands.append("no ip http server")
    if not state["HTTPS no requerido deshabilitado"]:
        commands.append("no ip http secure-server")
    if not state["CIS 1.2.2.7 TCP keepalives entrada"]:
        commands.append("service tcp-keepalives-in")
    if not state["CIS 1.2.2.8 TCP keepalives salida"]:
        commands.append("service tcp-keepalives-out")
    if not state["CIS 1.1.2.4 timeout consola"]:
        commands += ["line con 0", "exec-timeout 5 0", "exit"]
    if not state["CIS 1.1.2.5 AUX sin EXEC"]:
        commands += ["line aux 0", "no exec", "exit"]

    blocks = sections(config)
    for line, values in blocks.items():
        if not line.startswith("line vty "):
            continue
        changes = []
        if "transport input ssh" not in values:
            changes.append("transport input ssh")
        if not timeout_ok(values):
            changes.append("exec-timeout 5 0")
        if changes:
            commands += [line, *changes, "exit"]
    return commands


def audit_fortigate(config):
    match = re.search(r"(?m)^\s*set allowaccess\s+(.+)$", config)
    access = set(match.group(1).split()) if match else set()
    unwanted = {"http", "https", "ssh", "telnet", "fgfm"}
    return {
        "FortiGate: administracion restringida en port1":
            not bool(access & unwanted)
    }


def make_report(name, before, after, commands, mode, error=None):
    lines = [
        f"# Informe de {name}",
        "",
        f"Fecha UTC: {datetime.now(timezone.utc).isoformat(timespec='seconds')}",
        f"Modo: {mode}",
        "",
        "| Control | Antes | Despues |",
        "|---|---|---|",
    ]
    for control, value in before.items():
        previous = "CUMPLE" if value else "HALLAZGO"
        later = ("NO APLICADO" if after is None else
                 "CUMPLE" if after.get(control) else "HALLAZGO")
        lines.append(f"| {control} | {previous} | {later} |")

    lines += ["", "## Comandos propuestos o ejecutados", ""]
    lines += [f"- `{cmd}`" for cmd in commands] if commands else ["- Ninguno"]
    if error:
        lines += ["", f"Error: {error}"]
    lines += [
        "",
        "Revision parcial de controles seleccionados; no es certificacion CIS.",
        "El informe no contiene contrasenas ni running-configs.",
    ]
    return "\n".join(lines) + "\n"


class SSHSession:
    """Conexion interactiva usando el SSH que ya tiene Ubuntu."""

    def __init__(self, device, password):
        import pty

        self.pid, self.master = pty.fork()
        name = device["name"]
        prefix = re.escape(device.get("prompt", name))
        self.prompt = re.compile(
            rf"(?m)^{prefix}(?: ?\([^)]*\))? ?#\s*\Z"
        )

        command = [
            "ssh", "-tt",
            "-oConnectTimeout=12",
            "-oNumberOfPasswordPrompts=1",
            "-oStrictHostKeyChecking=accept-new",
            "-oPubkeyAuthentication=no",
            "-oPreferredAuthentications=password",
        ]
        if device["type"] == "cisco":
            command += [
                "-oKexAlgorithms=+diffie-hellman-group14-sha1",
                "-oHostKeyAlgorithms=+ssh-rsa",
            ]
            if name == "R1":
                command.append("-oCiphers=+aes256-cbc")
        command.append(f"{device['user']}@{device['host']}")

        if self.pid == 0:
            try:
                os.execvp("ssh", command)
            except OSError:
                os._exit(127)

        first = self.read(password_prompt=True, timeout=45)
        if re.search(r"(?i)password:\s*$", first):
            os.write(self.master, password.encode() + b"\n")
            self.read(timeout=45)

    def read(self, password_prompt=False, timeout=45):
        deadline = time.monotonic() + timeout
        output = ""
        while time.monotonic() < deadline:
            remaining = max(0, deadline - time.monotonic())
            ready, _, _ = select.select(
                [self.master], [], [], min(1, remaining)
            )
            if not ready:
                continue
            try:
                data = os.read(self.master, 65536)
            except OSError as exc:
                raise RuntimeError("La sesion SSH termino") from exc

            output += data.decode("utf-8", errors="replace").replace("\r", "")
            clean = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", output)
            if self.prompt.search(clean):
                return clean
            if password_prompt and re.search(r"(?i)password:\s*$", clean):
                return clean
            if re.search(
                r"(?i)(permission denied|connection refused|no matching)",
                clean
            ):
                raise RuntimeError("SSH rechazo la conexion o credenciales")
            if clean.rstrip().endswith("[confirm]"):
                os.write(self.master, b"\n")

        raise RuntimeError("Tiempo de espera agotado en SSH")

    def send(self, command, timeout=45):
        os.write(self.master, command.encode() + b"\n")
        return self.read(timeout=timeout)

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


def read_state(session, kind):
    if kind == "cisco":
        session.send("terminal length 0")
        config = session.send("show running-config", timeout=90)
        return config, audit_cisco(config)
    config = session.send("show system interface port1", timeout=60)
    return config, audit_fortigate(config)


def apply_changes(session, kind, commands):
    if not commands:
        return
    if kind == "cisco":
        session.send("configure terminal")
        try:
            for command in commands:
                result = session.send(command)
                if re.search(
                    r"%\s*(Invalid input|Incomplete command|Error)",
                    result, re.I
                ):
                    raise RuntimeError("IOS rechazo un comando")
        finally:
            session.send("end")
    else:
        for command in commands:
            result = session.send(command)
            if re.search(
                r"(Command fail|command parse error|Return code -)",
                result, re.I
            ):
                raise RuntimeError("FortiOS rechazo un comando")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["report", "apply"])
    parser.add_argument("--output", type=Path, default=Path("reportes"))
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)

    for device in DEVICES:
        name = device["name"]
        kind = device["type"]
        password = getpass.getpass(
            f"Contrasena de {name} ({device['host']}): "
        )
        session = SSHSession(device, password)
        try:
            config, before = read_state(session, kind)
            if kind == "cisco":
                commands = cisco_commands(config)
            else:
                commands = (
                    ["config system interface", 'edit "port1"',
                     "set allowaccess ping", "next", "end"]
                    if not all(before.values()) else []
                )

            pre = args.output / f"{name}-pre.md"
            pre.write_text(
                make_report(name, before, None, commands,
                            "Solo informe; sin cambios"),
                encoding="utf-8"
            )
            print(pre)

            if args.mode == "apply":
                error = None
                try:
                    apply_changes(session, kind, commands)
                except Exception as exc:
                    error = str(exc)

                _, after = read_state(session, kind)
                if not error and commands and not all(after.values()):
                    error = "Quedan hallazgos tras aplicar"
                if kind == "cisco" and commands and not error:
                    session.send("write memory", timeout=90)

                post = args.output / f"{name}-post.md"
                post.write_text(
                    make_report(name, before, after, commands,
                                "Aplicacion y revision posterior", error),
                    encoding="utf-8"
                )
                print(post)
        finally:
            session.close()


if __name__ == "__main__":
    main()
