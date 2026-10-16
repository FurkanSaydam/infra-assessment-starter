"""Nmap execution and port-file validation."""
import re, shutil, subprocess, time
from datetime import datetime, timezone
from pathlib import Path
from config import NMAP_BINARY, DEFAULT_TOP_PORTS

def validate_ports(ports):
    if not ports:
        return None
    supplied = str(ports).strip()
    candidate = Path(supplied).expanduser()
    if candidate.is_file():
        tokens = []
        for line in candidate.read_text(encoding="utf-8").splitlines():
            line = line.split("#", 1)[0].strip()
            tokens.extend(x for x in re.split(r"[\s,]+", line) if x)
    else:
        tokens = [x for x in re.split(r"[\s,]+", supplied) if x]
    if not tokens:
        raise ValueError(f"Port dosyası boş: {candidate}")
    normalized, seen = [], set()
    for token in tokens:
        if not re.fullmatch(r"\d+(?:-\d+)?", token):
            raise ValueError(f"Geçersiz port: {token!r}. Sayı veya başlangıç-bitiş aralığı kullan.")
        if "-" in token:
            a, b = map(int, token.split("-", 1))
            if not (1 <= a <= b <= 65535):
                raise ValueError(f"Geçersiz port aralığı: {token}")
            # Expand for de-duplication while retaining compact ranges.
            value = f"{a}-{b}"
        else:
            a = int(token)
            if not 1 <= a <= 65535:
                raise ValueError(f"Port 1-65535 aralığında olmalı: {token}")
            value = str(a)
        if value not in seen:
            seen.add(value); normalized.append(value)
    return ",".join(normalized)

def run_scan(target, ports, profile, timeout, output_dir, no_ping, audit, on_progress=None):
    binary = shutil.which(NMAP_BINARY)
    if not binary:
        raise RuntimeError("nmap bulunamadı. Nmap'in kurulu ve PATH içinde olduğundan emin ol.")
    ports = validate_ports(ports)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe_target = target.replace(":", "_")
    output_dir = Path(output_dir); output_dir.mkdir(parents=True, exist_ok=True)
    xml_path = output_dir / f"{safe_target}_{stamp}.xml"
    command = [binary, "-n", "-sT", "-sV", "--version-light", "--reason", "--stats-every", "2s"]
    if no_ping: command.append("-Pn")
    if profile == "standard": command.append("-sC")
    if ports: command.extend(["-p", ports])
    else: command.extend(["--top-ports", str(DEFAULT_TOP_PORTS)])
    command.extend(["-oX", str(xml_path), target])
    audit.log("scan_started", target=target, profile=profile, ports=ports or f"top-{DEFAULT_TOP_PORTS}",
              command=command, timeout_seconds=timeout)
    started = time.monotonic()
    try:
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, bufsize=1)
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()
            elapsed = round(time.monotonic() - started, 2)
            log_path = output_dir / f"{safe_target}_{stamp}.log"
            log_path.write_text(f"COMMAND: {command!r}\\nTIMEOUT: {timeout}\\nSTDOUT:\\n{stdout}\\nSTDERR:\\n{stderr}",
                                encoding="utf-8")
            audit.log("scan_timeout", target=target, elapsed_seconds=elapsed, timeout_seconds=timeout)
            raise RuntimeError(f"Tarama {timeout} saniyede zaman aşımına uğradı. Log: {log_path}")
        elapsed = round(time.monotonic() - started, 2)
        log_path = output_dir / f"{safe_target}_{stamp}.log"
        log_path.write_text(f"COMMAND: {command!r}\\nEXIT_CODE: {proc.returncode}\\nELAPSED_SECONDS: {elapsed}\\n\\nSTDOUT:\\n{stdout}\\n\\nSTDERR:\\n{stderr}",
                            encoding="utf-8")
        meta = {"command": command, "exit_code": proc.returncode, "elapsed_seconds": elapsed,
                "log_file": str(log_path), "started_at_utc": stamp, "timed_out": False}
        audit.log("scan_finished", target=target, exit_code=proc.returncode, elapsed_seconds=elapsed,
                  xml_file=str(xml_path), log_file=str(log_path))
        if not xml_path.is_file():
            raise RuntimeError(f"Nmap XML çıktısı oluşmadı. Ayrıntı: {log_path}")
        if proc.returncode != 0:
            audit.log("nmap_nonzero_exit", target=target, exit_code=proc.returncode, stderr_tail=stderr[-2000:])
        return xml_path, meta
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"Tarama zaman aşımına uğradı: {exc}") from exc
