#!/usr/bin/env python3
"""MFS Scanner CLI and live dashboard."""
import argparse, ipaddress, json, sys, time, traceback
from datetime import datetime
from pathlib import Path
import xml.etree.ElementTree as ET
from audit import AuditLogger
from core import run_scan, validate_ports
from parser import parse_nmap_xml
from ui import banner, Dashboard, print_error, print_result
from report import write_reports

def read_scope(path):
    networks = []
    for line_no, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line: continue
        try: networks.append(ipaddress.ip_network(line, strict=False))
        except ValueError as exc: raise ValueError(f"{path}:{line_no} geçersiz scope: {line}") from exc
    if not networks: raise ValueError(f"{path} boş. Yetkili IP/CIDR aralıklarını ekle.")
    return networks

def read_targets(target_arg, target_file, networks):
    values = []
    for source_arg in (target_arg, target_file):
        if not source_arg: continue
        path = Path(source_arg).expanduser()
        if path.is_file():
            for n, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                value = raw.split("#",1)[0].strip()
                if value: values.append((value, f"{path}:{n}"))
        elif source_arg == target_arg:
            values.append((source_arg, "-t"))
        else:
            raise ValueError(f"Hedef dosyası bulunamadı: {path}")
    if not values: raise ValueError("-t ile IP veya IP listesi dosyası belirtmelisin.")
    targets, seen = [], set()
    for raw, source in values:
        try: addr = ipaddress.ip_address(raw.strip())
        except ValueError as exc:
            raise ValueError(f"{source}: geçersiz IP {raw!r}. Satır başına bir IP yazılmalı.") from exc
        if not any(addr.version == net.version and addr in net for net in networks):
            raise ValueError(f"{addr} scope dışı. Tarama güvenlik için durduruldu.")
        if str(addr) not in seen: targets.append(str(addr)); seen.add(str(addr))
    return targets

def read_ports_arg(value):
    if not value: return None
    path = Path(value).expanduser()
    if path.is_file(): return validate_ports(str(path))
    # If it looks like a path but does not exist, fail instead of treating as a port.
    if any(c in value for c in ("/", "\\")) or value.endswith(".txt"):
        raise ValueError(f"Port dosyası bulunamadı: {path}")
    return validate_ports(value)

def main():
    ap = argparse.ArgumentParser(description="MFS Scanner — authorized, scoped infrastructure assessment")
    ap.add_argument("-t", "--target", help="IP veya satır başına bir IP içeren dosya (örn. ip.txt)")
    ap.add_argument("--target-file", help="Geriye dönük uyumluluk için hedef dosyası")
    ap.add_argument("-p", "--ports", help="Port listesi veya dosyası (örn. ports.txt)")
    ap.add_argument("--scope-file", default="scope.txt", help="Yetkili IP/CIDR kapsamı (varsayılan scope.txt)")
    ap.add_argument("--profile", choices=("safe","standard"), default="safe")
    ap.add_argument("--timeout", type=int, default=900, help="Hedef başına timeout saniyesi")
    ap.add_argument("--output", default="result", help="Sonuç kök dizini")
    ap.add_argument("--no-ping", action="store_true", help="Nmap'e -Pn ekle")
    args = ap.parse_args()
    try:
        scope_path = Path(args.scope_file)
        if not scope_path.is_file(): raise ValueError(f"Scope dosyası bulunamadı: {scope_path}")
        networks = read_scope(scope_path)
        targets = read_targets(args.target, args.target_file, networks)
        if args.timeout < 30: raise ValueError("--timeout en az 30 saniye olmalı.")
        ports = read_ports_arg(args.ports)
    except (OSError, ValueError) as exc:
        print_error(str(exc)); return 2

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    result_dir = Path(args.output) / stamp
    logs_dir = result_dir / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    for name in ("nmap.txt","web.txt","smb.txt","rpc.txt","error.txt"):
        (logs_dir / name).touch()
    audit = AuditLogger(logs_dir / "audit.jsonl")
    states = {ip: {"status":"WAITING","tool":"NMAP","chunk":"1/1","open_ports":0} for ip in targets}
    results = []
    start = time.monotonic()
    banner()
    ports_label = ports if ports else "TOP 1000"
    try:
        with Dashboard(targets, states, ports_label, start, result_dir) as dash:
            for ip in targets:
                states[ip]["status"] = "SCANNING"; dash.refresh()
                try:
                    xml_path, meta = run_scan(ip, ports, args.profile, args.timeout, logs_dir, args.no_ping, audit)
                    result = parse_nmap_xml(xml_path, ip, meta)
                    result["_xml_path"] = str(xml_path)
                    states[ip]["status"] = "DONE" if result["status"] == "completed" else "ERROR"
                    states[ip]["open_ports"] = sum(1 for h in result.get("hosts", []) for p in h.get("ports", []) if p.get("state") == "open")
                    states[ip]["chunk"] = "1/1"
                    results.append(result)
                    dash.refresh()
                    print_result(result, result_dir / f"{ip.replace(':','_')}.json")
                    (result_dir / f"{ip.replace(':','_')}.json").write_text(json.dumps({k:v for k,v in result.items() if k != "_xml_path"}, indent=2, ensure_ascii=False), encoding="utf-8")
                    # Append raw Nmap stdout/stderr log to combined human-readable log.
                    with (logs_dir / "nmap.txt").open("a",encoding="utf-8") as out:
                        out.write(f"\\n=== {ip} ===\\nXML: {xml_path}\\nLog: {meta.get('log_file')}\\n")
                except Exception as exc:
                    states[ip]["status"] = "ERROR"; dash.refresh()
                    audit.log("scan_error", target=ip, error=str(exc), traceback=traceback.format_exc())
                    with (logs_dir / "error.txt").open("a", encoding="utf-8") as f:
                        f.write(f"{ip}: {exc}\\n{traceback.format_exc()}\\n")
                    print_error(f"{ip}: {exc}")
        write_reports(result_dir, results, targets, ports)
        audit.log("run_finished", targets=len(targets), result_count=len(results), output_dir=str(result_dir))
        print(f"\\nSonuç klasörü: {result_dir.resolve()}")
        print(f"Raporlar: {result_dir / 'report.docx'} | {result_dir / 'report.pdf'} | {result_dir / 'summary.json'}")
        return 1 if any(s["status"] == "ERROR" for s in states.values()) else 0
    except KeyboardInterrupt:
        audit.log("run_interrupted", completed=len(results), total=len(targets))
        print_error("Kullanıcı tarafından durduruldu. Kısmi sonuçlar mevcut olabilir.")
        return 130

if __name__ == "__main__":
    sys.exit(main())
