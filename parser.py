"""Parse Nmap XML into normalized JSON; never infer 'not vulnerable' from missing data."""
import xml.etree.ElementTree as ET
from pathlib import Path

from web import summarize_web_services
from smb import summarize_smb_services


def parse_nmap_xml(xml_path, target, meta):
    root = ET.parse(Path(xml_path)).getroot()
    runstats = root.find("runstats")
    finished = runstats.find("finished") if runstats is not None else None
    hosts = root.findall("host")
    host_results = []

    for host in hosts:
        status_node = host.find("status")
        host_status = status_node.get("state", "unknown") if status_node is not None else "unknown"
        addresses = [
            {"addr": node.get("addr"), "type": node.get("addrtype")}
            for node in host.findall("address")
        ]
        hostnames = [n.get("name") for n in host.findall("./hostnames/hostname") if n.get("name")]
        ports = []
        for port in host.findall("./ports/port"):
            state_node = port.find("state")
            service_node = port.find("service")
            scripts = []
            for script in port.findall("script"):
                scripts.append({
                    "id": script.get("id", ""),
                    "output": script.get("output", ""),
                    "elements": [
                        {"key": e.get("key"), "text": (e.text or "").strip()}
                        for e in list(script)
                    ],
                })
            ports.append({
                "protocol": port.get("protocol"),
                "port": int(port.get("portid", "0")),
                "state": state_node.get("state", "unknown") if state_node is not None else "unknown",
                "reason": state_node.get("reason") if state_node is not None else None,
                "service": service_node.get("name") if service_node is not None else None,
                "product": service_node.get("product") if service_node is not None else None,
                "version": service_node.get("version") if service_node is not None else None,
                "extra_info": service_node.get("extrainfo") if service_node is not None else None,
                "tunnel": service_node.get("tunnel") if service_node is not None else None,
                "method": service_node.get("method") if service_node is not None else None,
                "confidence": service_node.get("conf") if service_node is not None else None,
                "scripts": scripts,
            })

        host_results.append({
            "status": host_status,
            "addresses": addresses,
            "hostnames": hostnames,
            "ports": ports,
            "web_review": summarize_web_services(ports),
            "smb_review": summarize_smb_services(ports),
        })

    finished_status = finished.get("exit") if finished is not None else None
    status = "completed" if meta.get("exit_code") == 0 and finished_status == "success" else "incomplete"
    return {
        "schema_version": "1.0",
        "target": target,
        "status": status,
        "limitations": [
            "Bu rapor yalnızca çalıştırılan taramanın kapsamını gösterir; tüm zafiyetlerin bulunduğunu garanti etmez.",
            "Sürüm bilgisi tek başına CVE etkilenimini kanıtlamaz; vendor backport ve yapılandırma kontrolü gerekir.",
            "Açık port veya servis tespiti tek başına zafiyet anlamına gelmez.",
            "Taranmayan port/protokol ve başarısız kontroller 'güvenli' olarak yorumlanmamalıdır."
        ],
        "scan": {
            **meta,
            "nmap_finished_status": finished_status,
            "hosts_up": runstats.find("hosts").get("up") if runstats is not None and runstats.find("hosts") is not None else None,
            "hosts_down": runstats.find("hosts").get("down") if runstats is not None and runstats.find("hosts") is not None else None,
        },
        "hosts": host_results,
    }
