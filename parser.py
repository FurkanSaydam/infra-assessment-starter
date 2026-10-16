"""Defensive Nmap XML parser."""
import xml.etree.ElementTree as ET
from pathlib import Path
from web import summarize_web_services
from smb import summarize_smb_services

def parse_nmap_xml(xml_path, target, meta):
    try:
        root = ET.parse(Path(xml_path)).getroot()
    except (ET.ParseError, OSError) as exc:
        raise ValueError(f"Nmap XML okunamadı/geçersiz: {exc}") from exc
    runstats = root.find("runstats")
    finished = runstats.find("finished") if runstats is not None else None
    host_results = []
    for host in root.findall("host"):
        status_node = host.find("status")
        addresses = [{"addr": n.get("addr"), "type": n.get("addrtype")}
                     for n in host.findall("address") if n.get("addr")]
        ports = []
        for port in host.findall("./ports/port"):
            state_node, service_node = port.find("state"), port.find("service")
            try:
                port_number = int(port.get("portid") or 0)
            except (ValueError, TypeError):
                port_number = 0
            scripts = [{"id": s.get("id", ""), "output": s.get("output", ""),
                        "elements": [{"key": e.get("key"), "text": (e.text or "").strip()}
                                     for e in list(s)]}
                       for s in port.findall("script")]
            ports.append({
                "protocol": port.get("protocol") or "unknown", "port": port_number,
                "state": state_node.get("state", "unknown") if state_node is not None else "unknown",
                "reason": state_node.get("reason") if state_node is not None else None,
                "service": service_node.get("name") if service_node is not None else None,
                "product": service_node.get("product") if service_node is not None else None,
                "version": service_node.get("version") if service_node is not None else None,
                "extra_info": service_node.get("extrainfo") if service_node is not None else None,
                "tunnel": service_node.get("tunnel") if service_node is not None else None,
                "method": service_node.get("method") if service_node is not None else None,
                "confidence": service_node.get("conf") if service_node is not None else None,
                "scripts": scripts})
        host_results.append({
            "status": status_node.get("state", "unknown") if status_node is not None else "unknown",
            "addresses": addresses,
            "hostnames": [n.get("name") for n in host.findall("./hostnames/hostname") if n.get("name")],
            "ports": ports, "web_review": summarize_web_services(ports),
            "smb_review": summarize_smb_services(ports)})
    hosts_node = runstats.find("hosts") if runstats is not None else None
    finished_status = finished.get("exit") if finished is not None else None
    completed = meta.get("exit_code") == 0 and finished_status == "success"
    return {"schema_version": "1.0", "target": target,
            "status": "completed" if completed else "incomplete",
            "limitations": [
                "Rapor yalnızca çalıştırılan taramanın kapsamını gösterir; tüm zafiyetlerin bulunduğunu garanti etmez.",
                "Servis sürümü tek başına CVE etkilenimini kanıtlamaz; vendor backport ve yapılandırma kontrolü gerekir.",
                "Açık port veya servis tespiti tek başına zafiyet anlamına gelmez.",
                "Taranmayan port/protokol ve başarısız kontroller güvenli olarak yorumlanmamalıdır."],
            "scan": {**meta, "nmap_finished_status": finished_status,
                     "hosts_up": hosts_node.get("up") if hosts_node is not None else None,
                     "hosts_down": hosts_node.get("down") if hosts_node is not None else None},
            "hosts": host_results}
