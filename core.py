"""Nmap execution with explicit argument lists and auditable outputs."""
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from config import NMAP_BINARY


def validate_ports(ports):
    if not ports:
        return None
    allowed = set("0123456789,-")
    if not ports or any(ch not in allowed for ch in ports):
        raise ValueError("Port ifadesi yalnızca rakam, virgül ve tire içerebilir.")
    if ports.startswith(",") or ports.endswith(",") or ",," in ports:
        raise ValueError("Port listesi biçimi geçersiz.")
    return ports


def run_scan(target, ports, profile, timeout, output_dir, no_ping, audit):
    binary = shutil.which(NMAP_BINARY)
    if not binary:
        raise RuntimeError("nmap bulunamadı. Nmap'in kurulu ve PATH içinde olduğundan emin ol.")

    ports = validate_ports(ports)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe_target = target.replace(":", "_")
    xml_path = Path(output_dir) / f"{safe_target}_{stamp}.xml"

    command = [binary, "-n", "-sV", "--version-light", "--reason"]
    if no_ping:
        command.append("-Pn")
    if profile == "standard":
        command.append("-sC")
    if ports:
        command.extend(["-p", ports])
    else:
        command.extend(["--top-ports", "1000"])
    command.extend(["-oX", str(xml_path), target])

    audit.log("scan_started", target=target, profile=profile, ports=ports or "top-1000",
              command=command, timeout_seconds=timeout)
    started = time.monotonic()
    try:
        completed = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout, check=False
        )
        elapsed = round(time.monotonic() - started, 2)
        # Store stderr/stdout in a separate text log for troubleshooting and traceability.
        log_path = Path(output_dir) / f"{safe_target}_{stamp}.log"
        log_path.write_text(
            f"COMMAND: {command!r}\nEXIT_CODE: {completed.returncode}\n"
            f"ELAPSED_SECONDS: {elapsed}\n\nSTDOUT:\n{completed.stdout}\n\nSTDERR:\n{completed.stderr}",
            encoding="utf-8",
        )
        meta = {
            "command": command,
            "exit_code": completed.returncode,
            "elapsed_seconds": elapsed,
            "log_file": str(log_path),
            "started_at_utc": stamp,
            "timed_out": False,
        }
        audit.log("scan_finished", target=target, exit_code=completed.returncode,
                  elapsed_seconds=elapsed, xml_file=str(xml_path), log_file=str(log_path))
        if not xml_path.is_file():
            raise RuntimeError(f"Nmap XML çıktısı oluşmadı. Ayrıntı: {log_path}")
        return xml_path, meta
    except subprocess.TimeoutExpired as exc:
        elapsed = round(time.monotonic() - started, 2)
        audit.log("scan_timeout", target=target, elapsed_seconds=elapsed, timeout_seconds=timeout)
        raise RuntimeError(f"Tarama {timeout} saniyede tamamlanmadı; sonuç eksik olabilir.") from exc
