#!/usr/bin/env python3
"""Scoped infrastructure assessment CLI."""
import argparse
import ipaddress
import sys
from pathlib import Path

from audit import AuditLogger
from core import run_scan
from parser import parse_nmap_xml
from ui import print_banner, print_result, print_error


def read_scope(path: Path):
    networks = []
    for line_no, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        try:
            networks.append(ipaddress.ip_network(line, strict=False))
        except ValueError as exc:
            raise ValueError(f"scope dosyası {line_no}. satır geçersiz: {line}") from exc
    if not networks:
        raise ValueError("scope.txt boş. Yalnızca taramaya yetkili IP/CIDR aralıklarını ekle.")
    return networks


def read_targets(args):
    values = []

    # -t/--target accepts either one IP address or a file containing one IP per line.
    # --target-file remains supported for compatibility.
    if args.target:
        target_path = Path(args.target).expanduser()
        if target_path.is_file():
            for line_no, raw in enumerate(target_path.read_text(encoding="utf-8").splitlines(), 1):
                line = raw.split("#", 1)[0].strip()
                if line:
                    values.append((line, f"{target_path}:{line_no}"))
        else:
            values.append((args.target, "-t/--target"))

    if args.target_file:
        target_path = Path(args.target_file).expanduser()
        for line_no, raw in enumerate(target_path.read_text(encoding="utf-8").splitlines(), 1):
            line = raw.split("#", 1)[0].strip()
            if line:
                values.append((line, f"{target_path}:{line_no}"))

    if not values:
        raise ValueError("-t/--target ile tek IP veya IP listesi dosyası belirtmelisin.")

    targets = []
    for raw, source in values:
        try:
            addr = ipaddress.ip_address(raw.strip())
        except ValueError as exc:
            raise ValueError(
                f"{source} içinde geçersiz hedef: {raw!r}. "
                "Hedef dosyasında satır başına bir IP adresi olmalı; CIDR hedef olarak desteklenmez."
            ) from exc
        if not any(addr.version == net.version and addr in net for net in args.scope_networks):
            raise ValueError(
                f"{addr} scope dosyasında tanımlı yetkili kapsamın dışında; tarama durduruldu."
            )
        if str(addr) not in targets:
            targets.append(str(addr))
    return targets


def main():
    ap = argparse.ArgumentParser(
        description="Yetkili kapsam içindeki sistemler için denetlenebilir Nmap tabanlı değerlendirme."
    )
    ap.add_argument("-t", "--target", help="Tek IP adresi veya satır başına bir IP içeren dosya yolu")
    ap.add_argument("--target-file", help="Satır başına bir IP adresi içeren dosya (geriye dönük uyumluluk)")
    ap.add_argument("--scope-file", default="scope.txt", help="Yetkili IP/CIDR kapsamı (varsayılan: scope.txt)")
    ap.add_argument("-p", "--ports", help="Port listesi veya port dosyası; ör. 22,80,443 ya da ports.txt")
    ap.add_argument("--profile", choices=("safe", "standard"), default="safe",
                    help="safe: -sV; standard: -sV -sC (Nmap default NSE scriptleri)")
    ap.add_argument("--timeout", type=int, default=900, help="Hedef başına zaman aşımı, saniye (varsayılan: 900)")
    ap.add_argument("--output", default="output", help="Çıktı klasörü (varsayılan: output)")
    ap.add_argument("--no-ping", action="store_true",
                    help="Host discovery yerine -Pn kullanır; erişilemeyen hedeflerde süreyi artırabilir.")
    args = ap.parse_args()

    try:
        scope_path = Path(args.scope_file)
        if not scope_path.is_file():
            raise ValueError(f"{scope_path} bulunamadı. Önce scope.txt oluştur.")
        args.scope_networks = read_scope(scope_path)
        targets = read_targets(args)
        if args.timeout < 30:
            raise ValueError("--timeout en az 30 saniye olmalı.")
    except (OSError, ValueError) as exc:
        print_error(str(exc))
        return 2

    print_banner()
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    audit = AuditLogger(output_dir / "audit.jsonl")
    overall = 0

    for target in targets:
        try:
            xml_path, meta = run_scan(
                target=target,
                ports=args.ports,
                profile=args.profile,
                timeout=args.timeout,
                output_dir=output_dir,
                no_ping=args.no_ping,
                audit=audit,
            )
            result = parse_nmap_xml(xml_path, target, meta)
            result_path = output_dir / f"{target.replace(':', '_')}.json"
            import json
            result_path.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
            print_result(result, result_path)
            if result.get("status") != "completed":
                overall = 1
        except Exception as exc:
            audit.log("scan_error", target=target, error=str(exc))
            print_error(f"{target}: {exc}")
            overall = 1
    return overall


if __name__ == "__main__":
    sys.exit(main())
